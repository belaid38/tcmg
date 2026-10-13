#define MODULE_LOG_PREFIX "serial"
#include "serial.h"
#include "../config/runtime_access.h"
#include "../core/constants.h"
#include "../reader/card_utils.h"
#include "../reader/old_ecm.h"
#include "../core/utils.h"
#include "../platform/platform.h"
#include "../log/log.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef TCMG_OS_WINDOWS
#include <strings.h>
#endif

#ifndef TCMG_OS_WINDOWS
#include <fcntl.h>
#include <glob.h>
#include <sys/select.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/ioctl.h>
#endif
#else
#include <windows.h>
#include <winreg.h>
#endif

#define SERIAL_BAUD 9600
#define SERIAL_CARD_BAUD_BASE 9600u
#define SERIAL_OPEN_SETTLE_MS 50
#define SERIAL_FAST_RESET_SETTLE_MS 50
#define SERIAL_IO_TIMEOUT_MS 1500
#define SERIAL_ATR_TIMEOUT_MS 1000
#define SERIAL_T0_GAP_MS 10
#define SERIAL_PROBE_ATR_FIRST_MS 700
#define SERIAL_UNAVAILABLE_COOLDOWN_MS 2000
#define SERIAL_T0_NO_PROCEDURE_MS 1200

typedef struct {
#ifdef TCMG_OS_WINDOWS
    HANDLE h;
#else
    int fd;
#endif
    int open;
    int present;
    int ready;
    int protocol;
    int parity;
    uint8_t t0_fi;
    uint8_t t0_di;
    uint8_t t0_d;
    uint8_t t0_wi;
    uint8_t t0_n;
    uint8_t t0_ta1;
    int t0_ta1_present;
    uint8_t t0_ta2;
    int t0_ta2_present;
    uint32_t current_baud;
    uint32_t requested_baud;
    uint32_t t0_wwt_ms;
    int64_t last_reset_ms;
    int64_t last_attempt_ms;
    int64_t last_poll_ms;
    int64_t last_activity_ms;
    int64_t last_activity_seen_ms;
    int fast_reset_paused;
    int ecm_active;
    S_READER_OLD_ECM_STATE old_ecm;
    uint8_t atr[TCMG_SERIAL_MAX_ATR];
    size_t atr_len;
    char device[TCMG_SERIAL_PORT_LEN];
    pthread_mutex_t mtx;
} S_SERIAL_SLOT;

static S_SERIAL_SLOT s_slots[MAX_READERS];
static pthread_t s_tid;
static _Atomic int8_t s_running = 0;
static pthread_mutex_t s_init_mtx = PTHREAD_MUTEX_INITIALIZER;
static int s_initialized = 0;

static int64_t mono_ms(void)
{
    return tcmg_mono_ms();
}

static void slots_init(void)
{
    pthread_mutex_lock(&s_init_mtx);
    if (!s_initialized) {
        for (int i = 0; i < MAX_READERS; i++) {
#ifdef TCMG_OS_WINDOWS
            s_slots[i].h = INVALID_HANDLE_VALUE;
#else
            s_slots[i].fd = -1;
#endif
            pthread_mutex_init(&s_slots[i].mtx, NULL);
        }
        s_initialized = 1;
    }
    pthread_mutex_unlock(&s_init_mtx);
}

static void slot_close(S_SERIAL_SLOT *s)
{
    if (!s) return;
#ifdef TCMG_OS_WINDOWS
    if (s->h != INVALID_HANDLE_VALUE) {
        CloseHandle(s->h);
        s->h = INVALID_HANDLE_VALUE;
    }
#else
    if (s->fd >= 0) {
        close(s->fd);
        s->fd = -1;
    }
#endif
    s->open = 0;
}

static void slot_clear(S_SERIAL_SLOT *s)
{
    if (!s) return;
    slot_close(s);
    s->present = 0;
    s->ready = 0;
    s->protocol = 0;
    s->parity = -1;
    s->t0_fi = 1;
    s->t0_di = 1;
    s->t0_d = 1;
    s->t0_wi = 10;
    s->t0_n = 0;
    s->t0_ta1 = 0x11;
    s->t0_ta1_present = 0;
    s->t0_ta2 = 0;
    s->t0_ta2_present = 0;
    s->current_baud = SERIAL_BAUD;
    s->requested_baud = SERIAL_BAUD;
    s->t0_wwt_ms = 1000;
    s->last_reset_ms = 0;
    s->last_attempt_ms = 0;
    s->last_poll_ms = 0;
    s->last_activity_ms = mono_ms();
    s->last_activity_seen_ms = s->last_activity_ms;
    s->fast_reset_paused = 0;
    s->ecm_active = 0;
    memset(&s->old_ecm, 0, sizeof(s->old_ecm));
    s->atr_len = 0;
    memset(s->atr, 0, sizeof(s->atr));
    s->device[0] = '\0';
}

#ifdef TCMG_OS_WINDOWS
static void normalize_com(const char *in, wchar_t *out, size_t cap)
{
    char path[TCMG_SERIAL_PORT_LEN];
    const char *p = in ? in : "";
    tcmg_strlcpy(path, p, sizeof(path));
    while (isspace((unsigned char)*path)) memmove(path, path + 1, strlen(path));
    if (_strnicmp(path, "\\\\.\\", 4) == 0) {
        MultiByteToWideChar(CP_UTF8, 0, path, -1, out, (int)cap);
        return;
    }
    if (_strnicmp(path, "COM", 3) == 0) {
        char buf[TCMG_SERIAL_PORT_LEN];
        snprintf(buf, sizeof(buf), "\\\\.\\%s", path);
        MultiByteToWideChar(CP_UTF8, 0, buf, -1, out, (int)cap);
        return;
    }
    char buf[TCMG_SERIAL_PORT_LEN];
    snprintf(buf, sizeof(buf), "\\\\.\\COM%s", path);
    MultiByteToWideChar(CP_UTF8, 0, buf, -1, out, (int)cap);
}

static int win_set_rts(HANDLE h, int high)
{
    return EscapeCommFunction(h, high ? SETRTS : CLRRTS) ? 0 : -1;
}

static int win_configure(HANDLE h, int parity)
{
    DCB dcb;
    COMMTIMEOUTS to;
    memset(&dcb, 0, sizeof(dcb));
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(h, &dcb)) return -1;
    dcb.BaudRate = SERIAL_BAUD;
    dcb.ByteSize = 8;
    dcb.StopBits = TWOSTOPBITS;
    dcb.Parity = (parity == 0) ? EVENPARITY : (parity == 1 ? ODDPARITY : NOPARITY);
    dcb.fBinary = TRUE;
    dcb.fParity = (parity != 2);
    dcb.fDtrControl = DTR_CONTROL_ENABLE;
    dcb.fRtsControl = RTS_CONTROL_DISABLE;
    dcb.fOutxCtsFlow = FALSE;
    dcb.fOutxDsrFlow = FALSE;
    dcb.fInX = FALSE;
    dcb.fOutX = FALSE;
    if (!SetCommState(h, &dcb)) return -1;
    memset(&to, 0, sizeof(to));
    to.ReadIntervalTimeout = 50;
    to.ReadTotalTimeoutMultiplier = 0;
    to.ReadTotalTimeoutConstant = SERIAL_IO_TIMEOUT_MS;
    to.WriteTotalTimeoutMultiplier = 0;
    to.WriteTotalTimeoutConstant = 1500;
    if (!SetCommTimeouts(h, &to)) return -1;
    PurgeComm(h, PURGE_RXABORT | PURGE_RXCLEAR | PURGE_TXABORT | PURGE_TXCLEAR);
    return 0;
}

static int serial_open_slot(S_SERIAL_SLOT *s, const char *device, int parity)
{
    wchar_t wide[TCMG_SERIAL_PORT_LEN];
    normalize_com(device, wide, sizeof(wide) / sizeof(wide[0]));
    HANDLE h = CreateFileW(wide, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (win_configure(h, parity) < 0) {
        CloseHandle(h);
        return -1;
    }
    s->h = h;
    s->open = 1;
    s->parity = parity;
    s->current_baud = SERIAL_BAUD;
    s->requested_baud = SERIAL_BAUD;
    return 0;
}

static int serial_write_all(S_SERIAL_SLOT *s, const uint8_t *buf, size_t len, int timeout_ms)
{
    (void)timeout_ms;
    while (len) {
        DWORD n = 0;
        if (!WriteFile(s->h, buf, (DWORD)len, &n, NULL)) return -1;
        if (!n) return -1;
        buf += n;
        len -= n;
    }
    return 0;
}

static int serial_read_byte(S_SERIAL_SLOT *s, uint8_t *out, int timeout_ms)
{
    COMMTIMEOUTS to;
    memset(&to, 0, sizeof(to));
    to.ReadIntervalTimeout = 50;
    to.ReadTotalTimeoutMultiplier = 0;
    to.ReadTotalTimeoutConstant = (DWORD)timeout_ms;
    SetCommTimeouts(s->h, &to);
    DWORD n = 0;
    if (!ReadFile(s->h, out, 1, &n, NULL)) return -1;
    return n == 1 ? 0 : -1;
}
#else
static int unix_configure(int fd, int parity)
{
    struct termios tio;
    if (tcgetattr(fd, &tio) < 0) return -1;
    cfmakeraw(&tio);
    tio.c_cflag |= CLOCAL | CREAD;
    tio.c_cflag &= ~(CSIZE | CRTSCTS | CSTOPB);
    tio.c_cflag |= CS8 | CSTOPB;
    if (parity == 2) {
        tio.c_cflag &= (tcflag_t)~PARENB;
        tio.c_cflag &= (tcflag_t)~PARODD;
    } else {
        tio.c_cflag |= PARENB;
        if (parity == 0) tio.c_cflag &= (tcflag_t)~PARODD;
        else tio.c_cflag |= PARODD;
    }
    cfsetispeed(&tio, B9600);
    cfsetospeed(&tio, B9600);
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 1;
    if (tcsetattr(fd, TCSANOW, &tio) < 0) return -1;
    tcflush(fd, TCIOFLUSH);
    return 0;
}

static speed_t unix_baud_speed(uint32_t requested, uint32_t *actual)
{
    struct baud_pair { uint32_t rate; speed_t speed; };
    static const struct baud_pair rates[] = {
        { 9600u, B9600 },
#ifdef B19200
        { 19200u, B19200 },
#endif
#ifdef B38400
        { 38400u, B38400 },
#endif
#ifdef B57600
        { 57600u, B57600 },
#endif
#ifdef B76800
        { 76800u, B76800 },
#endif
#ifdef B115200
        { 115200u, B115200 },
#endif
#ifdef B153600
        { 153600u, B153600 },
#endif
#ifdef B230400
        { 230400u, B230400 },
#endif
#ifdef B460800
        { 460800u, B460800 },
#endif
#ifdef B921600
        { 921600u, B921600 },
#endif
    };
    size_t best = 0;
    uint64_t best_diff = UINT64_MAX;
    for (size_t i = 0; i < sizeof(rates) / sizeof(rates[0]); i++) {
        uint64_t a = rates[i].rate;
        uint64_t b = requested;
        uint64_t diff = a > b ? a - b : b - a;
        if (diff < best_diff) { best_diff = diff; best = i; }
    }
    if (actual) *actual = rates[best].rate;

    if (best_diff * 100u > (uint64_t)requested * 5u) {
        if (actual) *actual = 9600u;
        return B9600;
    }
    return rates[best].speed;
}

static int unix_set_rts(int fd, int high)
{
#if defined(TIOCM_RTS) && (defined(TIOCMBIS) || defined(TIOCMBIC))
    int bits = TIOCM_RTS;
    return ioctl(fd, high ? TIOCMBIS : TIOCMBIC, &bits) == 0 ? 0 : -1;
#elif defined(TIOCM_RTS) && defined(TIOCMGET) && defined(TIOCMSET)
    int bits = 0;
    if (ioctl(fd, TIOCMGET, &bits) < 0) return -1;
    if (high) bits |= TIOCM_RTS;
    else bits &= ~TIOCM_RTS;
    return ioctl(fd, TIOCMSET, &bits) == 0 ? 0 : -1;
#else
    (void)fd; (void)high;
    return -1;
#endif
}

static int serial_open_slot(S_SERIAL_SLOT *s, const char *device, int parity)
{
    int fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) return -1;
    if (unix_configure(fd, parity) < 0) {
        close(fd);
        return -1;
    }
    s->fd = fd;
    s->open = 1;
    s->parity = parity;
    s->current_baud = SERIAL_BAUD;
    s->requested_baud = SERIAL_BAUD;
    return 0;
}

static int serial_write_all(S_SERIAL_SLOT *s, const uint8_t *buf, size_t len, int timeout_ms)
{
    size_t off = 0;
    while (off < len) {
        fd_set wf;
        FD_ZERO(&wf); FD_SET(s->fd, &wf);
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        int rc = select(s->fd + 1, NULL, &wf, NULL, &tv);
        if (rc <= 0) return -1;
        ssize_t n = write(s->fd, buf + off, len - off);
        if (n > 0) off += (size_t)n;
        else if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        else return -1;
    }
    return 0;
}

static int serial_read_byte(S_SERIAL_SLOT *s, uint8_t *out, int timeout_ms)
{
    fd_set rf;
    FD_ZERO(&rf); FD_SET(s->fd, &rf);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    int rc = select(s->fd + 1, &rf, NULL, NULL, &tv);
    if (rc <= 0) return -1;
    for (;;) {
        ssize_t n = read(s->fd, out, 1);
        if (n == 1) return 0;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -1;
        return -1;
    }
}
#endif

static int serial_apply_baud(S_SERIAL_SLOT *s, uint32_t requested, uint32_t *actual_out)
{
    if (!s || requested == 0) return -1;
#ifdef TCMG_OS_WINDOWS
    if (!s->open || s->h == INVALID_HANDLE_VALUE) return -1;
    DCB dcb;
    memset(&dcb, 0, sizeof(dcb));
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(s->h, &dcb)) return -1;
    dcb.BaudRate = requested;
    if (!SetCommState(s->h, &dcb)) return -1;
    s->requested_baud = requested;
    s->current_baud = requested;
    if (actual_out) *actual_out = requested;
    return 0;
#else
    if (!s->open || s->fd < 0) return -1;
    uint32_t actual = SERIAL_BAUD;
    speed_t speed = unix_baud_speed(requested, &actual);
    struct termios tio;
    if (tcgetattr(s->fd, &tio) < 0) return -1;
    if (cfsetispeed(&tio, speed) < 0 || cfsetospeed(&tio, speed) < 0) return -1;
    if (tcsetattr(s->fd, TCSANOW, &tio) < 0) return -1;
    s->requested_baud = requested;
    s->current_baud = actual;
    if (actual_out) *actual_out = actual;
    return 0;
#endif
}

static int serial_read_n(S_SERIAL_SLOT *s, uint8_t *buf, size_t len, int timeout_ms)
{
    for (size_t i = 0; i < len; i++)
        if (serial_read_byte(s, &buf[i], timeout_ms) < 0) return -1;
    return 0;
}

static int serial_drain(S_SERIAL_SLOT *s, size_t len)
{
    uint8_t b;
    for (size_t i = 0; i < len; i++)
        if (serial_read_byte(s, &b, 2500) < 0) return -1;
    return 0;
}

static int read_atr(S_SERIAL_SLOT *s, int first_timeout_ms)
{
    uint8_t *a = s->atr;
    memset(a, 0, sizeof(s->atr));
    s->atr_len = 0;
    s->t0_fi = 1;
    s->t0_di = 1;
    s->t0_d = 1;
    s->t0_wi = 10;
    s->t0_n = 0;
    s->t0_ta1 = 0x11;
    s->t0_ta1_present = 0;
    s->t0_ta2 = 0;
    s->t0_ta2_present = 0;

    if (first_timeout_ms <= 0) first_timeout_ms = SERIAL_ATR_TIMEOUT_MS;
    if (serial_read_byte(s, &a[0], first_timeout_ms) < 0) return -1;
    if (a[0] != 0x3B && a[0] != 0x3F) return -1;
    if (serial_read_byte(s, &a[1], 500) < 0) return -1;

    uint8_t y = (uint8_t)((a[1] >> 4) & 0x0F);
    int hist = a[1] & 0x0F;
    int group = 1;
    int has_tck = 0;
    int proto = 0;
    int first_proto = 0;
    int protocol_count = 1;
    size_t n = 2;

    for (;;) {
        if (y & 0x01) {
            if (n >= sizeof(s->atr) || serial_read_byte(s, &a[n], 500) < 0) return -1;
            if (group == 1) {
                s->t0_ta1 = a[n];
                s->t0_ta1_present = 1;
                s->t0_fi = (uint8_t)(a[n] >> 4);
                s->t0_di = (uint8_t)(a[n] & 0x0F);
            } else if (group == 2) {
                s->t0_ta2 = a[n];
                s->t0_ta2_present = 1;
            }
            n++;
        }
        if (y & 0x02) {
            if (n >= sizeof(s->atr) || serial_read_byte(s, &a[n], 500) < 0) return -1;
            n++;
        }
        if (y & 0x04) {
            if (n >= sizeof(s->atr) || serial_read_byte(s, &a[n], 500) < 0) return -1;
            if (group == 1) s->t0_n = a[n];
            if (group == 2) s->t0_wi = a[n] ? a[n] : 10;
            n++;
        }
        if (y & 0x08) {
            if (n >= sizeof(s->atr) || serial_read_byte(s, &a[n], 500) < 0) return -1;
            y = (uint8_t)((a[n] >> 4) & 0x0F);
            proto = a[n] & 0x0F;
            if (group == 1) first_proto = proto;
            if (proto != 0) has_tck = 1;
            group++;
            protocol_count++;
            n++;
            if (group > 8) return -1;
            continue;
        }
        break;
    }

    if (n + (size_t)hist + (has_tck ? 1u : 0u) > sizeof(s->atr)) return -1;
    for (int i = 0; i < hist; i++)
        if (serial_read_byte(s, &a[n++], 500) < 0) return -1;
    if (has_tck && serial_read_byte(s, &a[n++], 500) < 0) return -1;

    if (has_tck) {
        uint8_t tck = 0;
        for (size_t i = 1; i < n; i++) tck ^= a[i];
        if (tck != 0) {
            tcmg_log_dbg(D_READER, "ATR TCK mismatch device=%s len=%zu -- discarding", s->device, n);
            return -1;
        }
    }

    if (a[0] == 0x3F) return -1;
    if (s->t0_fi >= 16u || s->t0_fi == 0u) s->t0_fi = 1;
    if (s->t0_di >= 16u || s->t0_di == 0u) s->t0_di = 1;

    static const uint16_t f_table[16] = {
        0, 372, 558, 744, 1116, 1488, 1860, 0,
        0, 512, 768, 1024, 1536, 2048, 0, 0
    };
    static const uint8_t d_table[16] = {
        0, 1, 2, 4, 8, 16, 32, 64, 12, 20, 0, 0, 0, 0, 0, 0
    };
    if (f_table[s->t0_fi] == 0 || d_table[s->t0_di] == 0) {
        s->t0_fi = 1;
        s->t0_di = 1;
    }
    s->t0_d = d_table[s->t0_di];
    s->t0_wwt_ms = 960u * (uint32_t)s->t0_d * (uint32_t)s->t0_wi;
    uint32_t initial_etu_us = (uint32_t)(((uint64_t)f_table[s->t0_fi] * 1000000u + 3579545u / 2u) / 3579545u);
    uint64_t wwt_us = (uint64_t)s->t0_wwt_ms * initial_etu_us;
    s->t0_wwt_ms = (uint32_t)((wwt_us + 999u) / 1000u);
    if (s->t0_wwt_ms < 250u) s->t0_wwt_ms = 250u;
    if (s->t0_wwt_ms > 10000u) s->t0_wwt_ms = 10000u;

    s->atr_len = n;
    s->protocol = first_proto;
    tcmg_log_dbg(D_READER,
                 "ATR proto=T%d FI=%u DI=%u D=%u WI=%u TA1=%s%02X TA2=%s%02X baud-base=%u",
                 s->protocol, s->t0_fi, s->t0_di, s->t0_d, s->t0_wi,
                 s->t0_ta1_present ? "" : "-", s->t0_ta1,
                 s->t0_ta2_present ? "" : "-", s->t0_ta2,
                 SERIAL_CARD_BAUD_BASE);
    (void)protocol_count;
    return 0;
}

static int serial_pts_exchange(S_SERIAL_SLOT *s, uint8_t ta1)
{
    uint8_t req[4] = { 0xFF, 0x10, ta1, 0x00 };
    uint8_t confirm[4] = { 0 };
    req[3] = (uint8_t)(req[0] ^ req[1] ^ req[2]);
    if (serial_write_all(s, req, sizeof(req), 1000) < 0) return -1;
    if (serial_drain(s, sizeof(req)) < 0) return -1;
    for (size_t i = 0; i < sizeof(confirm); i++)
        if (serial_read_byte(s, &confirm[i], 1000) < 0) return -1;
    if (memcmp(req, confirm, sizeof(req)) != 0) return -1;
    return 0;
}

static uint32_t serial_target_baud(const S_SERIAL_SLOT *s)
{
    static const uint16_t f_table[16] = {
        0, 372, 558, 744, 1116, 1488, 1860, 0,
        0, 512, 768, 1024, 1536, 2048, 0, 0
    };
    uint32_t d = s && s->t0_d ? s->t0_d : 1u;
    uint32_t f = (s && s->t0_fi < 16u) ? f_table[s->t0_fi] : 372u;
    if (!f) f = 372u;
    uint64_t baud = (uint64_t)SERIAL_CARD_BAUD_BASE * d * 372u;
    baud = (baud + f / 2u) / f;
    if (baud < 9600u) baud = 9600u;
    if (baud > 921600u) baud = 921600u;
    return (uint32_t)baud;
}

static int serial_select_speed_after_atr(S_SERIAL_SLOT *s)
{
    if (!s || !s->open) return -1;
    if (s->protocol != 0) return -2;

    int specific = s->t0_ta2_present != 0;
    int pts_ok = 0;
    if (!specific && s->t0_ta1_present && s->t0_ta1 != 0x11) {
        if (serial_pts_exchange(s, s->t0_ta1) == 0) {
            pts_ok = 1;
            tcmg_log_dbg(D_READER, "PTS accepted device=%s TA1=%02X D=%u",
                         s->device, s->t0_ta1, s->t0_d);
        } else {
            s->t0_fi = 1;
            s->t0_di = 1;
            s->t0_d = 1;
            tcmg_log_dbg(D_READER, "PTS rejected device=%s TA1=%02X; keeping 9600/default timing",
                         s->device, s->t0_ta1);
        }
    } else if (specific && (s->t0_ta2 & 0x10u) == 0 && s->t0_ta1_present) {
        pts_ok = 1;
    }

    uint32_t target = pts_ok ? serial_target_baud(s) : SERIAL_BAUD;
    uint32_t actual = SERIAL_BAUD;
    if (target != s->current_baud) {
        if (serial_apply_baud(s, target, &actual) < 0) return -3;
    } else {
        actual = s->current_baud;
        s->requested_baud = target;
    }
    s->current_baud = actual;
    tcmg_log_dbg(D_READER, "speed device=%s requested=%u actual=%u D=%u WWT=%ums",
                 s->device, target, actual, s->t0_d, s->t0_wwt_ms);
    return 0;
}

static int do_reset_parity(S_SERIAL_SLOT *s, int parity, int *got, int atr_first_timeout_ms, int fast_reset)
{
    slot_close(s);
#ifdef TCMG_OS_WINDOWS
    if (serial_open_slot(s, s->device, parity) < 0) return -1;
    if (win_set_rts(s->h, 1) < 0) { slot_close(s); return -1; }
#else
    if (serial_open_slot(s, s->device, parity) < 0) return -1;
    if (unix_set_rts(s->fd, 1) < 0) { slot_close(s); return -1; }
#endif
    tcmg_sleep_ms(fast_reset ? SERIAL_FAST_RESET_SETTLE_MS : SERIAL_OPEN_SETTLE_MS);
    slot_close(s);

    if (serial_open_slot(s, s->device, parity) < 0) return -1;
#ifdef TCMG_OS_WINDOWS
    if (win_set_rts(s->h, 0) < 0) { slot_close(s); return -1; }
#else
    if (unix_set_rts(s->fd, 0) < 0) { slot_close(s); return -1; }
#endif
    tcmg_sleep_ms(fast_reset ? SERIAL_FAST_RESET_SETTLE_MS : SERIAL_OPEN_SETTLE_MS);
    if (read_atr(s, atr_first_timeout_ms) < 0) {
        slot_close(s);
        return -1;
    }
    s->parity = parity;
    if (serial_select_speed_after_atr(s) < 0) {
        slot_close(s);
        return -1;
    }
    s->present = 1;
    s->ready = 1;
    if (got) *got = 1;
    return 0;
}

static int serial_fast_reset_mode(S_SERIAL_SLOT *s, int quick_probe)
{
    static const int parities[] = { 0, 1, 2 };
    int order[sizeof(parities) / sizeof(parities[0])];
    size_t norder = 0;
    int got = 0;
    int first_timeout = quick_probe ? SERIAL_PROBE_ATR_FIRST_MS : SERIAL_ATR_TIMEOUT_MS;
    int64_t t0 = mono_ms();

    if (!s || !s->device[0]) return -1;

    if (s->parity >= 0 && s->parity <= 2) order[norder++] = s->parity;
    for (size_t i = 0; i < sizeof(parities) / sizeof(parities[0]); i++) {
        if (norder && parities[i] == order[0]) continue;
        order[norder++] = parities[i];
    }

    for (size_t i = 0; i < norder; i++) {
        if (do_reset_parity(s, order[i], &got, first_timeout, !quick_probe) == 0) {
            s->last_reset_ms = mono_ms();
            s->last_attempt_ms = s->last_reset_ms;
            tcmg_log_force("%s ok device=%s parity=%s ATR=%zu baud=%u D=%u elapsed=%lldms",
                           quick_probe ? "quick probe" : "fast reset",
                           s->device, order[i] == 0 ? "even" : (order[i] == 1 ? "odd" : "none"),
                           s->atr_len, s->current_baud, s->t0_d,
                           (long long)(mono_ms() - t0));
            return 0;
        }

    }
    s->present = 0;
    s->ready = 0;
    s->atr_len = 0;
    s->last_attempt_ms = mono_ms();
    if (!quick_probe)
        tcmg_log_dbg(D_READER, "fast reset failed device=%s elapsed=%lldms",
                     s->device, (long long)(mono_ms() - t0));
    return -1;
}

static int serial_fast_reset(S_SERIAL_SLOT *s)
{
    return serial_fast_reset_mode(s, 0);
}

static int serial_quick_probe(S_SERIAL_SLOT *s)
{
    return serial_fast_reset_mode(s, 1);
}

static void serial_purge_and_close(S_SERIAL_SLOT *s)
{
    if (!s) return;
#ifdef TCMG_OS_WINDOWS
    if (s->h != INVALID_HANDLE_VALUE) PurgeComm(s->h, PURGE_RXABORT | PURGE_RXCLEAR | PURGE_TXABORT | PURGE_TXCLEAR);
#else
    if (s->fd >= 0) tcflush(s->fd, TCIOFLUSH);
#endif
    slot_close(s);
}

static void serial_reset_runtime_state(S_SERIAL_SLOT *s)
{
    if (!s) return;
    char device[TCMG_SERIAL_PORT_LEN];
    tcmg_strlcpy(device, s->device, sizeof(device));
    serial_purge_and_close(s);
    s->present = 0;
    s->ready = 0;
    s->protocol = 0;
    s->parity = -1;
    s->t0_fi = 1;
    s->t0_di = 1;
    s->t0_d = 1;
    s->t0_wi = 10;
    s->t0_n = 0;
    s->t0_ta1 = 0x11;
    s->t0_ta1_present = 0;
    s->t0_ta2 = 0;
    s->t0_ta2_present = 0;
    s->current_baud = SERIAL_BAUD;
    s->requested_baud = SERIAL_BAUD;
    s->t0_wwt_ms = 1000;
    s->last_reset_ms = 0;
    s->last_attempt_ms = 0;
    s->last_poll_ms = 0;
    s->ecm_active = 0;
    s->atr_len = 0;
    memset(s->atr, 0, sizeof(s->atr));
    tcmg_strlcpy(s->device, device, sizeof(s->device));
}

static int serial_reinitialize(S_SERIAL_SLOT *s)
{
    if (!s || !s->device[0]) return -1;
    serial_reset_runtime_state(s);
    tcmg_sleep_ms(100);
    return serial_fast_reset_mode(s, 1);
}

static void serial_mark_unavailable(S_SERIAL_SLOT *s)
{
    if (!s) return;
    s->present = 0;
    s->ready = 0;
    s->atr_len = 0;
    s->last_attempt_ms = mono_ms();
    slot_close(s);
}

static int t0_transmit(S_SERIAL_SLOT *s, const uint8_t *apdu, size_t apdu_len,
                       const char *context, uint8_t *rsp, size_t *rsp_len)
{
    if (!s || !s->open || !apdu || apdu_len < 5 || apdu_len > 260 || !rsp || !rsp_len || *rsp_len < 2)
        return -1;

    size_t body = apdu_len - 4;
    int case2 = (body == 1);
    int case3 = (apdu[4] > 0 && body == (size_t)apdu[4] + 1u);
    if (!case2 && !case3) return -2;

    const char *trace = (context && *context) ? context : "exchange";
    tcmg_dump_dbg(D_READER, apdu, (int32_t)apdu_len, "SERIAL >> APDU context=%s", trace);
    if (serial_write_all(s, apdu, 5, 1500) < 0) return -3;
    if (serial_drain(s, 5) < 0) return -4;

    const uint8_t ins = apdu[1];
    const size_t le = apdu[4] ? apdu[4] : 256u;
    const size_t lc = apdu[4];
    size_t out = 0;
    size_t sent = 0;

    for (int guard = 0; guard < 600; guard++) {
        uint8_t p = 0;
        uint32_t procedure_timeout = s->t0_wwt_ms ? s->t0_wwt_ms : 2500u;
        if (procedure_timeout > SERIAL_T0_NO_PROCEDURE_MS)
            procedure_timeout = SERIAL_T0_NO_PROCEDURE_MS;
        if (serial_read_byte(s, &p, (int)procedure_timeout) < 0) return -5;
        tcmg_log_dbg(D_READER, "T0 procedure context=%s ins=%02X byte=%02X", trace, apdu[1], p);
        if (p == 0x60) continue;
        if ((p & 0xF0) == 0x60 || (p & 0xF0) == 0x90) {
            if (out + 2 > *rsp_len) return -6;
            rsp[out++] = p;
            if (serial_read_byte(s, &rsp[out++], (int)(s->t0_wwt_ms ? s->t0_wwt_ms : 2500u)) < 0) return -7;
            *rsp_len = out;
            tcmg_dump_dbg(D_READER, rsp, (int32_t)*rsp_len, "SERIAL << RESPONSE context=%s", trace);
            return 0;
        }

        if ((p & 0x0E) == (ins & 0x0E)) {
            if (!case3) {
                if (le + 2 > *rsp_len) return -8;
                if (serial_read_n(s, rsp, le + 2, (int)(s->t0_wwt_ms ? s->t0_wwt_ms : 2500u)) < 0) return -9;
                *rsp_len = le + 2;
                tcmg_dump_dbg(D_READER, rsp, (int32_t)*rsp_len, "SERIAL << RESPONSE context=%s", trace);
                return 0;
            }
            if (sent != 0) return -10;
            if (serial_write_all(s, apdu + 5, lc, 1500) < 0) return -11;
            if (serial_drain(s, lc) < 0) return -12;
            sent = lc;
        }
        else if ((p & 0x0E) == ((uint8_t)(~ins) & 0x0E)) {
            if (!case3) {
                if (out + 1 > *rsp_len) return -13;
                if (serial_read_byte(s, &rsp[out++], (int)(s->t0_wwt_ms ? s->t0_wwt_ms : 2500u)) < 0) return -14;
                if (out >= le) {
                    if (out + 2 > *rsp_len) return -15;
                    if (serial_read_n(s, rsp + out, 2, (int)(s->t0_wwt_ms ? s->t0_wwt_ms : 2500u)) < 0) return -16;
                    out += 2;
                    *rsp_len = out;
                    tcmg_dump_dbg(D_READER, rsp, (int32_t)*rsp_len, "SERIAL << RESPONSE context=%s", trace);
                    return 0;
                }
            } else {
                if (sent >= lc) return -17;
                if (serial_write_all(s, apdu + 5 + sent, 1, 1500) < 0) return -18;
                if (serial_drain(s, 1) < 0) return -19;
                sent++;
            }
        }
        else return -20;
    }
    return -21;
}


#define SERIAL_ECM_NOT_FOUND (-11)

static int conax_ecm(S_SERIAL_SLOT *s, const uint8_t *ecm, size_t ecm_len, uint8_t cw[16], int allow_ca)
{
    uint8_t apdu[260];
    uint8_t rsp[320];
    size_t rsp_len = sizeof(rsp);
    if (!ecm || ecm_len == 0 || ecm_len > 249 || !cw) return -1;

    size_t apdu_len = 8 + ecm_len;
    apdu[0] = 0xDD;
    apdu[1] = 0xA2;
    apdu[2] = 0x00;
    apdu[3] = 0x00;
    apdu[4] = (uint8_t)(ecm_len + 3);
    apdu[5] = 0x14;
    apdu[6] = (uint8_t)(ecm_len + 1);
    apdu[7] = 0x00;
    memcpy(apdu + 8, ecm, ecm_len);

    if (t0_transmit(s, apdu, apdu_len, allow_ca ? "ecm" : "old-ecm", rsp, &rsp_len) < 0) return -2;
    if (rsp_len < 2) return -3;

    uint8_t sw1 = rsp[rsp_len - 2];
    uint8_t sw2 = rsp[rsp_len - 1];
    if (sw1 != 0x90 && sw1 != 0x98) return -5;

    int got = 0;
    if (sw1 == 0x90 && sw2 == 0x00) {
        if (tcmg_parse_conax_cw(rsp, rsp_len, cw, &got) == -2) return -6;
    }
    if (!allow_ca) return got == 3 ? 0 : SERIAL_ECM_NOT_FOUND;

    while (sw1 == 0x98 && sw2 != 0x00 && sw2 != 0xFF) {
        uint8_t ins_ca[5] = {0xDD, 0xCA, 0x00, 0x00, sw2};
        rsp_len = sizeof(rsp);
        if (t0_transmit(s, ins_ca, sizeof(ins_ca), allow_ca ? "ecm-ca" : "old-ecm-ca", rsp, &rsp_len) < 0) return -7;
        if (rsp_len < 2) return -8;
        sw1 = rsp[rsp_len - 2];
        sw2 = rsp[rsp_len - 1];
        if (sw1 == 0x98 || (sw1 == 0x90 && sw2 == 0x00)) {
            int part = 0;
            if (tcmg_parse_conax_cw(rsp, rsp_len, cw, &part) == -2) return -9;
            got |= part;
        } else return -10;
    }
    return got == 3 ? 0 : SERIAL_ECM_NOT_FOUND;
}

static int serial_open_and_reset(S_SERIAL_SLOT *s, const char *device)
{
    if (!device || !*device) return -1;
    if (s->device[0] && strcmp(s->device, device) != 0) slot_clear(s);
    if (!s->device[0]) tcmg_strlcpy(s->device, device, sizeof(s->device));
    if (s->ready) return 0;

    int64_t now = mono_ms();
    if (s->last_attempt_ms != 0 && now - s->last_attempt_ms < SERIAL_UNAVAILABLE_COOLDOWN_MS)
        return -7;
    s->last_attempt_ms = now;
    return serial_quick_probe(s);
}

static void *serial_thread(void *arg)
{
    (void)arg;
    while (atomic_load(&s_running)) {
        int min_poll = 1000;
        S_READER cfg_readers[MAX_READERS];
        int reader_count = cfg_runtime_reader_snapshot_indexed(cfg_readers, MAX_READERS);

        for (int i = 0; i < MAX_READERS; i++) {
            S_READER *cfg = (i < reader_count) ? &cfg_readers[i] : NULL;
            int want = cfg && cfg->in_use && cfg->enabled && !strcasecmp(cfg->protocol, "serial");
            const char *device = want ? cfg->device : NULL;
            if (want && cfg->poll_ms > 0 && cfg->poll_ms < min_poll) min_poll = cfg->poll_ms;

            if (pthread_mutex_trylock(&s_slots[i].mtx) != 0)
                continue;
            if (!want || !device || !*device) {
                slot_clear(&s_slots[i]);
            } else {
                if (s_slots[i].device[0] && strcmp(s_slots[i].device, device) != 0) slot_clear(&s_slots[i]);
                tcmg_strlcpy(s_slots[i].device, device, sizeof(s_slots[i].device));
                int64_t now = mono_ms();
                if (!s_slots[i].ready &&
                    (s_slots[i].last_attempt_ms == 0 || now - s_slots[i].last_attempt_ms >= SERIAL_UNAVAILABLE_COOLDOWN_MS)) {
                    s_slots[i].last_attempt_ms = now;
                    if (serial_quick_probe(&s_slots[i]) < 0)
                        tcmg_log_dbg(D_READER, "reader[%d]: quick probe failed device=%s", i + 1, device);
                }
                reader_old_ecm_sync(&s_slots[i].old_ecm, cfg);
                if (s_slots[i].ready && s_slots[i].present) {
                    reader_old_ecm_bind(&s_slots[i].old_ecm, cfg, s_slots[i].device,
                                        s_slots[i].atr, s_slots[i].atr_len);
                } else {
                    reader_old_ecm_unbind(&s_slots[i].old_ecm);
                }

                if (cfg->maintenance_mode == TCMG_READER_MAINT_OLD_ECM &&
                    s_slots[i].ready && s_slots[i].present && s_slots[i].ecm_active == 0) {
                    const uint8_t *old_ecm = NULL;
                    size_t old_ecm_len = 0;
                    if (reader_old_ecm_due(cfg, &s_slots[i].old_ecm, s_slots[i].ecm_active != 0) &&
                        reader_old_ecm_get(&s_slots[i].old_ecm, &old_ecm, &old_ecm_len) == 0) {
                        uint8_t ecm_copy[TCMG_OLD_ECM_MAX_LEN];
                        uint8_t cw[16] = {0};
                        memcpy(ecm_copy, old_ecm, old_ecm_len);
                        tcmg_log_dbg(D_READER, "OLD ECM start device=%s source=%s len=%zu",
                                     s_slots[i].device,
                                     cfg->old_ecm_source == TCMG_OLD_ECM_SOURCE_MANUAL ? "manual" : "auto",
                                     old_ecm_len);
                        reader_old_ecm_note_attempt(&s_slots[i].old_ecm);
                        s_slots[i].ecm_active++;
                        int old_rc = conax_ecm(&s_slots[i], ecm_copy, old_ecm_len, cw, 0);
                        if (s_slots[i].ecm_active > 0) s_slots[i].ecm_active--;
                        s_slots[i].last_activity_ms = mono_ms();
                        tcmg_log_dbg(D_READER, "OLD ECM result=%s device=%s elapsed=%lldms",
                                     old_rc == 0 ? "success" : "failed", s_slots[i].device,
                                     (long long)(mono_ms() - now));
                    }
                    s_slots[i].last_poll_ms = now;
                    pthread_mutex_unlock(&s_slots[i].mtx);
                    continue;
                }

                if (cfg->maintenance_mode == TCMG_READER_MAINT_FAST_RESET && cfg->fast_reset > 0) {
                    const int idle_enabled = cfg->fast_reset_idle > 0;
                    const int idle = idle_enabled && now - s_slots[i].last_activity_ms >=
                                     (int64_t)cfg->fast_reset_idle * 1000LL;
                    if (s_slots[i].fast_reset_paused) {
                        if (s_slots[i].last_activity_ms != s_slots[i].last_activity_seen_ms) {
                            s_slots[i].fast_reset_paused = 0;
                            s_slots[i].last_activity_seen_ms = s_slots[i].last_activity_ms;
                            s_slots[i].last_reset_ms = now;
                            tcmg_log_force("fast reset resumed device=%s", device);
                        }
                    } else if (idle) {
                        s_slots[i].fast_reset_paused = 1;
                        s_slots[i].last_activity_seen_ms = s_slots[i].last_activity_ms;
                        tcmg_log_force("fast reset paused device=%s idle=%ds", device, cfg->fast_reset_idle);
                    }
                    if (!s_slots[i].fast_reset_paused &&
                        now - s_slots[i].last_reset_ms >= (int64_t)cfg->fast_reset * 1000LL) {
                        if (serial_fast_reset(&s_slots[i]) < 0)
                            tcmg_log("reader[%d]: fast reset failed device=%s", i + 1, device);
                    }
                } else {
                    s_slots[i].fast_reset_paused = 0;
                }
                s_slots[i].last_poll_ms = now;
            }
            pthread_mutex_unlock(&s_slots[i].mtx);
        }

        if (min_poll < 50) min_poll = 50;
        if (min_poll > 10000) min_poll = 10000;
        tcmg_sleep_ms(min_poll);
    }
    return NULL;
}

int serial_start(void)
{
    slots_init();
    if (atomic_exchange(&s_running, 1)) return 0;
    if (pthread_create(&s_tid, NULL, serial_thread, NULL) != 0) {
        atomic_store(&s_running, 0);
        return -1;
    }
    tcmg_log("reader support enabled");
    return 0;
}

void serial_stop(void)
{
    slots_init();
    if (atomic_exchange(&s_running, 0)) pthread_join(s_tid, NULL);
    for (int i = 0; i < MAX_READERS; i++) {
        pthread_mutex_lock(&s_slots[i].mtx);
        slot_clear(&s_slots[i]);
        pthread_mutex_unlock(&s_slots[i].mtx);
    }
}

int serial_reader_get(int index, S_SERIAL_READER *out)
{
    if (!out || index < 0 || index >= MAX_READERS) return -1;
    slots_init();
    pthread_mutex_lock(&s_slots[index].mtx);
    memset(out, 0, sizeof(*out));
    tcmg_strlcpy(out->device, s_slots[index].device, sizeof(out->device));
    out->present = s_slots[index].present;
    out->ready = s_slots[index].ready;
    out->atr_len = s_slots[index].atr_len;
    if (out->atr_len > sizeof(out->atr)) out->atr_len = sizeof(out->atr);
    memcpy(out->atr, s_slots[index].atr, out->atr_len);
    out->protocol = s_slots[index].protocol;
    pthread_mutex_unlock(&s_slots[index].mtx);
    return out->device[0] ? 0 : -1;
}

int serial_reader_count(void)
{
    int n = 0;
    slots_init();
    for (int i = 0; i < MAX_READERS; i++) {
        pthread_mutex_lock(&s_slots[i].mtx);
        if (s_slots[i].device[0]) n++;
        pthread_mutex_unlock(&s_slots[i].mtx);
    }
    return n;
}

int serial_do_ecm_reader(int index, uint16_t caid,
                         const uint8_t *ecm, size_t ecm_len,
                         uint8_t cw[16], int32_t whitelist, E_READER_FAILURE *failure)
{
    if (failure) *failure = READER_FAILURE_READER_ERROR;
    if (index < 0 || index >= MAX_READERS || !ecm || !cw || ecm_len == 0 || ecm_len > 249) return -1;
    if ((caid & 0xFF00u) != 0x0B00u) return -2;
    if (whitelist > 0 && ecm_len != (size_t)whitelist) {
        if (failure) *failure = READER_FAILURE_REJECTED;
        return -3;
    }

    slots_init();
    S_READER cfg;
    if (!cfg_runtime_reader_get(index, &cfg)) return -4;
    if (!cfg.enabled || strcasecmp(cfg.protocol, "serial") != 0) return -5;

    S_SERIAL_SLOT *s = &s_slots[index];
    pthread_mutex_lock(&s->mtx);
    if (serial_open_and_reset(s, cfg.device) < 0) {
        if (failure) *failure = READER_FAILURE_TRANSPORT_ERROR;
        pthread_mutex_unlock(&s->mtx);
        return -6;
    }

    int64_t ecm_t0 = mono_ms();
    s->last_activity_ms = ecm_t0;
    s->ecm_active++;
    int rc = conax_ecm(s, ecm, ecm_len, cw, 1);
    if (rc < 0 && rc != SERIAL_ECM_NOT_FOUND && (rc == -2 || rc == -7)) {
        serial_mark_unavailable(s);
        int reinitialized = serial_reinitialize(s);
        tcmg_log_dbg(D_READER,
                     "transport recovery device=%s status=%s",
                     s->device, reinitialized == 0 ? "ready" : "failed");
        if (reinitialized == 0) {
            int retry_rc = conax_ecm(s, ecm, ecm_len, cw, 1);
            tcmg_log_dbg(D_READER,
                         "transport retry device=%s result=%s",
                         s->device, retry_rc == 0 ? "found" :
                         (retry_rc == SERIAL_ECM_NOT_FOUND ? "not-found" : "failed"));
            rc = retry_rc;
        }
    } else if (rc < 0 && rc != SERIAL_ECM_NOT_FOUND) {
        serial_mark_unavailable(s);
    }
    if (rc == 0) {
        int64_t success_now = mono_ms();
        reader_old_ecm_sync(&s->old_ecm, &cfg);
        if (s->ready && s->present)
            reader_old_ecm_bind(&s->old_ecm, &cfg, s->device, s->atr, s->atr_len);
        reader_old_ecm_note_success(&s->old_ecm, &cfg, ecm, ecm_len);
    }
    if (failure) {
        if (rc == 0) *failure = READER_FAILURE_NONE;
        else if (rc == SERIAL_ECM_NOT_FOUND) *failure = READER_FAILURE_NOT_FOUND;
        else if (rc == -2 || rc == -7) *failure = READER_FAILURE_TRANSPORT_ERROR;
        else *failure = READER_FAILURE_CARD_ERROR;
    }
    if (s->ecm_active > 0) s->ecm_active--;
    int64_t ecm_ms = mono_ms() - ecm_t0;
    if (rc < 0) {
        tcmg_log_dbg(D_READER,
                     "ECM failed device=%s rc=%d elapsed=%lldms%s",
                     s->device, rc, (long long)ecm_ms,
                     rc == SERIAL_ECM_NOT_FOUND ? "; card returned no CW, keeping reader ready" : "; reader marked unavailable");
    } else {
        tcmg_log_dbg(D_ECM, "ECM ok device=%s elapsed=%lldms", s->device, (long long)ecm_ms);
    }
    pthread_mutex_unlock(&s->mtx);
    return rc;
}

size_t serial_list_ports(char out[][TCMG_SERIAL_PORT_LEN], size_t max_ports)
{
    if (!out || max_ports == 0) return 0;
#ifdef TCMG_OS_WINDOWS
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\SERIALCOMM", 0, KEY_READ, &key) != ERROR_SUCCESS)
        return 0;
    size_t count = 0;
    for (DWORD i = 0; count < max_ports; i++) {
        wchar_t name[256]; wchar_t data[256]; DWORD name_len = (DWORD)(sizeof(name) / sizeof(name[0]));
        DWORD data_len = (DWORD)(sizeof(data)); DWORD type = 0;
        LONG rc = RegEnumValueW(key, i, name, &name_len, NULL, &type, (LPBYTE)data, &data_len);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS || type != REG_SZ) continue;
        char utf8[TCMG_SERIAL_PORT_LEN];
        int n = WideCharToMultiByte(CP_UTF8, 0, data, (int)(data_len / sizeof(wchar_t)), utf8, (int)sizeof(utf8) - 1, NULL, NULL);
        if (n <= 0) continue;
        utf8[n] = '\0';
        if (strncmp(utf8, "COM", 3) != 0) continue;
        tcmg_strlcpy(out[count++], utf8, TCMG_SERIAL_PORT_LEN);
    }
    RegCloseKey(key);
    return count;
#else
    static const char *patterns[] = {
        "/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS*", "/dev/cu.*", "/dev/tty.usb*"
    };
    size_t count = 0;
    for (size_t p = 0; p < sizeof(patterns) / sizeof(patterns[0]) && count < max_ports; p++) {
        glob_t g;
        memset(&g, 0, sizeof(g));
        if (glob(patterns[p], 0, NULL, &g) == 0) {
            for (size_t i = 0; i < g.gl_pathc && count < max_ports; i++) {
                int dup = 0;
                for (size_t j = 0; j < count; j++) if (!strcmp(out[j], g.gl_pathv[i])) { dup = 1; break; }
                if (!dup) tcmg_strlcpy(out[count++], g.gl_pathv[i], TCMG_SERIAL_PORT_LEN);
            }
        }
        globfree(&g);
    }
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            if (strcmp(out[j], out[i]) < 0) {
                char tmp[TCMG_SERIAL_PORT_LEN];
                memcpy(tmp, out[i], sizeof(tmp));
                memcpy(out[i], out[j], sizeof(tmp));
                memcpy(out[j], tmp, sizeof(tmp));
            }
        }
    }
    return count;
#endif
}
