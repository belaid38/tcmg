#define MODULE_LOG_PREFIX "internal"
#include "internal.h"
#include "internal_t0.h"
#include "reader_backend.h"
#include "../config/runtime_access.h"
#include "../core/constants.h"
#include "../reader/card_utils.h"
#include "../core/utils.h"
#include "../log/log.h"
#include "../platform/platform.h"
#include "../reader/failure.h"
#include "../reader/old_ecm.h"

#ifndef TCMG_OS_WINDOWS

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define TCMG_INTERNAL_ECM_QUEUE_CAP 16
#define TCMG_INTERNAL_ECM_WAIT_MS 20000
#define TCMG_INTERNAL_MAX_NULLS 32
#define TCMG_INTERNAL_IO_WRITE_MS 1500
#define TCMG_INTERNAL_ATR_BYTE_MS 1000
#define TCMG_INTERNAL_RESET_SETTLE_MS 50
#define TCMG_INTERNAL_SCI_SETTLE_MS 150
#define TCMG_INTERNAL_DEFAULT_ETU 372u
#define TCMG_INTERNAL_DEFAULT_FS 27u
#define TCMG_INTERNAL_DEFAULT_WI 10u
#define TCMG_INTERNAL_DREAMBOX_CARDMHZ 2700u
#define TCMG_INTERNAL_PLL_START_FS 10u
#define TCMG_INTERNAL_PLL_RETRIES 7u
#define TCMG_INTERNAL_SYNC_POLL_MS 250

#ifdef __linux__
#define SCI_IOW_MAGIC 's'
typedef struct sci_parameters {
    unsigned char T;
    uint32_t fs;
    uint32_t ETU;
    uint32_t WWT;
    uint32_t CWT;
    uint32_t BWT;
    uint32_t EGT;
    unsigned char clock_stop_polarity;
    unsigned char check;
    unsigned char P;
    unsigned char I;
    unsigned char U;
} SCI_PARAMETERS;
#define SCI_SET_RESET _IOW(SCI_IOW_MAGIC, 1, uint32_t)
#define SCI_SET_PARAMETERS _IOW(SCI_IOW_MAGIC, 4, SCI_PARAMETERS)
#define SCI_GET_PARAMETERS _IOW(SCI_IOW_MAGIC, 5, SCI_PARAMETERS)
#define SCI_GET_PRESENT _IOW(SCI_IOW_MAGIC, 8, uint32_t)
#define SCI_SET_ATR_READY _IOW(SCI_IOW_MAGIC, 11, uint32_t)
#endif

enum internal_job_state {
    INTERNAL_JOB_FREE = 0,
    INTERNAL_JOB_QUEUED,
    INTERNAL_JOB_RUNNING,
    INTERNAL_JOB_DONE,
    INTERNAL_JOB_CANCELLED
};

typedef struct {
    int state;
    int rc;
    int recoverable;
    uint8_t ecm[249];
    size_t ecm_len;
    uint8_t cw[16];
    unsigned waiters;
} S_INTERNAL_JOB;

typedef struct {
    int fd;
    int exclusive;
    int params_applied;
    int present;
    int ready;
    int protocol;
    int64_t last_reset_ms;
    int64_t last_activity_ms;
    int64_t last_activity_seen_ms;
    int fast_reset_paused;
    S_READER_OLD_ECM_STATE old_ecm;
    uint32_t sci_etu;
    uint32_t sci_fs;
    uint32_t t0_wwt_etu;
    uint32_t t0_egt_etu;
    uint32_t t0_wwt_ms;
    uint8_t t0_fi;
    uint8_t t0_di;
    uint8_t t0_d;
    uint8_t t0_wi;
    uint8_t t0_n;
    uint8_t t0_i;
    int worker_running;
    int worker_stop;
    int ecm_active;
    int queue_head;
    int queue_tail;
    int queue_count;
    int queue_slots[TCMG_INTERNAL_ECM_QUEUE_CAP];
    S_INTERNAL_JOB jobs[TCMG_INTERNAL_ECM_QUEUE_CAP];
    uint8_t atr[TCMG_INTERNAL_MAX_ATR];
    size_t atr_len;
    char reset_fail[96];
    int deprecated_cfg;
    int deprecated_active;
    char device[256];
    char target_device[256];
    pthread_t worker_tid;
    pthread_cond_t cv;
    pthread_mutex_t mtx;
    S_INTERNAL_BACKEND backend;
} S_INTERNAL_SLOT;

static S_INTERNAL_SLOT s_slots[MAX_READERS];
static pthread_t s_tid;
static _Atomic int8_t s_running = 0;
static pthread_mutex_t s_slots_init_mtx = PTHREAD_MUTEX_INITIALIZER;
static int s_slots_initialized = 0;

static int64_t mono_ms(void)
{
    return tcmg_mono_ms();
}

static int wait_readable(int fd, uint32_t timeout_ms)
{
    if (fd < 0) return -1;
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv = {
        .tv_sec = (time_t)(timeout_ms / 1000u),
        .tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u)
    };

    int rc;
    do {
        rc = select(fd + 1, &rfds, NULL, NULL, &tv);
    } while (rc < 0 && errno == EINTR);
    return rc > 0 ? 0 : -1;
}

static int read_byte_timeout(int fd, uint8_t *out, uint32_t timeout_ms)
{
    const int64_t deadline = mono_ms() + (int64_t)timeout_ms;
    if (!out || wait_readable(fd, timeout_ms) < 0) return -1;
    for (;;) {
        ssize_t n = read(fd, out, 1);
        if (n == 1) return 0;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int64_t left = deadline - mono_ms();
            if (left <= 0) return -1;
            tcmg_sleep_ms(left > 2 ? 2u : (uint32_t)left);
            if (wait_readable(fd, (uint32_t)(deadline - mono_ms() > 0 ? deadline - mono_ms() : 1)) < 0) return -1;
            continue;
        }
        return -1;
    }
}

static int write_flush(int fd)
{
    if (tcflush(fd, TCIFLUSH) == 0) return 0;
    if (errno == ENOTTY || errno == EINVAL || errno == ENOSYS) return 0;
    return -1;
}

static void slots_init(void)
{
    pthread_mutex_lock(&s_slots_init_mtx);
    if (!s_slots_initialized) {
        for (int i = 0; i < MAX_READERS; i++) {
            s_slots[i].fd = -1;
            internal_backend_init(&s_slots[i].backend);
            pthread_mutex_init(&s_slots[i].mtx, NULL);
            pthread_cond_init(&s_slots[i].cv, NULL);
        }
        s_slots_initialized = 1;
    }
    pthread_mutex_unlock(&s_slots_init_mtx);
}

static void queue_reset_locked(S_INTERNAL_SLOT *s)
{
    s->queue_head = 0;
    s->queue_tail = 0;
    s->queue_count = 0;
    for (int i = 0; i < TCMG_INTERNAL_ECM_QUEUE_CAP; i++) {
        s->queue_slots[i] = -1;
        s->jobs[i].state = INTERNAL_JOB_FREE;
        s->jobs[i].rc = -1;
        s->jobs[i].recoverable = 0;
        s->jobs[i].ecm_len = 0;
        memset(s->jobs[i].ecm, 0, sizeof(s->jobs[i].ecm));
        memset(s->jobs[i].cw, 0, sizeof(s->jobs[i].cw));
        s->jobs[i].waiters = 0;
    }
}

static int queue_submit_locked(S_INTERNAL_SLOT *s, const uint8_t *ecm,
                               size_t ecm_len, int *joined)
{
    if (joined) *joined = 0;

    for (int i = 0; i < TCMG_INTERNAL_ECM_QUEUE_CAP; i++) {
        S_INTERNAL_JOB *job = &s->jobs[i];
        if ((job->state == INTERNAL_JOB_QUEUED || job->state == INTERNAL_JOB_RUNNING) &&
            job->ecm_len == ecm_len && memcmp(job->ecm, ecm, ecm_len) == 0) {
            job->waiters++;
            if (joined) *joined = 1;
            return i;
        }
    }

    if (s->queue_count >= TCMG_INTERNAL_ECM_QUEUE_CAP) return -1;

    int job_index = -1;
    for (int i = 0; i < TCMG_INTERNAL_ECM_QUEUE_CAP; i++) {
        if (s->jobs[i].state == INTERNAL_JOB_FREE) {
            job_index = i;
            break;
        }
    }
    if (job_index < 0) return -1;

    S_INTERNAL_JOB *job = &s->jobs[job_index];
    job->state = INTERNAL_JOB_QUEUED;
    job->rc = -1;
    job->recoverable = 0;
    job->ecm_len = ecm_len;
    memcpy(job->ecm, ecm, ecm_len);
    memset(job->cw, 0, sizeof(job->cw));
    job->waiters = 1;
    s->queue_slots[s->queue_tail] = job_index;
    s->queue_tail = (s->queue_tail + 1) % TCMG_INTERNAL_ECM_QUEUE_CAP;
    s->queue_count++;
    return job_index;
}

static int queue_pop_locked(S_INTERNAL_SLOT *s)
{
    if (s->queue_count <= 0) return -1;
    int job_index = s->queue_slots[s->queue_head];
    s->queue_slots[s->queue_head] = -1;
    s->queue_head = (s->queue_head + 1) % TCMG_INTERNAL_ECM_QUEUE_CAP;
    s->queue_count--;
    return job_index;
}

static void queue_release_locked(S_INTERNAL_JOB *job)
{
    if (!job) return;
    job->state = INTERNAL_JOB_FREE;
    job->rc = -1;
    job->ecm_len = 0;
    job->waiters = 0;
    memset(job->ecm, 0, sizeof(job->ecm));
    memset(job->cw, 0, sizeof(job->cw));
}

static int queue_waiter_count_locked(const S_INTERNAL_SLOT *s)
{
    int total = 0;
    for (int i = 0; i < TCMG_INTERNAL_ECM_QUEUE_CAP; i++)
        total += (int)s->jobs[i].waiters;
    return total;
}

static void slot_close_fd(S_INTERNAL_SLOT *s)
{
    if (!s) return;
    internal_backend_close(&s->backend);
    s->fd = -1;
    s->exclusive = 0;
}

static void slot_clear(S_INTERNAL_SLOT *s)
{
    slot_close_fd(s);
    s->params_applied = 0;
    s->present = 0;
    s->ready = 0;
    s->protocol = 0;
    s->last_reset_ms = 0;
    s->last_activity_ms = mono_ms();
    s->last_activity_seen_ms = s->last_activity_ms;
    s->fast_reset_paused = 0;
    memset(&s->old_ecm, 0, sizeof(s->old_ecm));
    s->sci_etu = 0;
    s->sci_fs = 0;
    s->t0_wwt_etu = 0;
    s->t0_egt_etu = 0;
    s->t0_wwt_ms = 0;
    s->t0_fi = 1;
    s->t0_di = 1;
    s->t0_d = 1;
    s->t0_wi = TCMG_INTERNAL_DEFAULT_WI;
    s->t0_n = 0;
    s->t0_i = 0;
    queue_reset_locked(s);
    s->atr_len = 0;
    memset(s->atr, 0, sizeof(s->atr));
    s->device[0] = '\0';
    internal_backend_init(&s->backend);
}

static void slot_reset_state(S_INTERNAL_SLOT *s)
{
    memset(&s->atr, 0, sizeof(s->atr));
    s->fd = -1;
    s->exclusive = 0;
    s->params_applied = 0;
    s->present = 0;
    s->ready = 0;
    s->protocol = 0;
    s->last_reset_ms = 0;
    s->last_activity_ms = mono_ms();
    s->last_activity_seen_ms = s->last_activity_ms;
    s->fast_reset_paused = 0;
    memset(&s->old_ecm, 0, sizeof(s->old_ecm));
    s->sci_etu = 0;
    s->sci_fs = 0;
    s->t0_wwt_etu = 0;
    s->t0_egt_etu = 0;
    s->t0_wwt_ms = 0;
    s->t0_fi = 1;
    s->t0_di = 1;
    s->t0_d = 1;
    s->t0_wi = TCMG_INTERNAL_DEFAULT_WI;
    s->t0_n = 0;
    s->t0_i = 0;
    s->worker_running = 0;
    s->worker_stop = 0;
    s->ecm_active = 0;
    s->atr_len = 0;
    s->device[0] = '\0';
    s->target_device[0] = '\0';
    internal_backend_init(&s->backend);
    queue_reset_locked(s);
}

static int slot_open(S_INTERNAL_SLOT *s, const char *device)
{
    const char *resolved;

    if (!s) return -1;
    resolved = (device && *device) ? device : "auto";
    if (internal_backend_is_open(&s->backend) && strcmp(s->target_device, resolved) == 0) return 0;

    slot_close_fd(s);
    s->params_applied = 0;
    s->present = 0;
    s->ready = 0;
    s->protocol = 0;
    s->atr_len = 0;

    if (internal_backend_open(&s->backend, resolved) < 0)
        return -1;

    s->fd = internal_backend_get_fd(&s->backend);
    s->exclusive = s->backend.exclusive;
    tcmg_strlcpy(s->device, internal_backend_device(&s->backend), sizeof(s->device));
    if (!s->device[0]) tcmg_strlcpy(s->device, resolved, sizeof(s->device));
    tcmg_log_force("internal backend detected backend=%s device=%s platform=%s",
                   internal_backend_name(&s->backend), s->device, internal_backend_platform_name());
    return 0;
}

static int reader_present(S_INTERNAL_SLOT *s)
{
    if (!s || !internal_backend_is_open(&s->backend)) return 0;
    int present = internal_backend_present(&s->backend);
    if (present >= 0) {
        s->present = present ? 1 : 0;
        if (!s->present) {
            s->ready = 0;
            s->atr_len = 0;
        }
        return s->present;
    }
    s->present = 0;
    s->ready = 0;
    s->atr_len = 0;
    tcmg_log_dbg(D_READER, "present poll failed backend=%s device=%s errno=%d",
                 internal_backend_name(&s->backend), s->device, errno);
    return -1;
}

static void sci_parameters_defaults(SCI_PARAMETERS *p)
{
    memset(p, 0, sizeof(*p));
    p->T = 0;
    p->fs = TCMG_INTERNAL_DEFAULT_FS;
    p->ETU = TCMG_INTERNAL_DEFAULT_ETU;
    p->EGT = 0;
}

static uint32_t clamp_u32(uint64_t value, uint32_t minv, uint32_t maxv)
{
    if (value < minv) return minv;
    if (value > maxv) return maxv;
    return (uint32_t)value;
}

static uint32_t calc_etu_us(const S_INTERNAL_SLOT *s)
{
    if (!s || s->sci_etu == 0 || s->sci_fs == 0) return 120;

    const uint32_t clock_10khz = TCMG_INTERNAL_DREAMBOX_CARDMHZ / s->sci_fs;
    if (clock_10khz == 0) return 120;

    uint64_t us = ((uint64_t)s->sci_etu * 100u + clock_10khz / 2u) / clock_10khz;
    return clamp_u32(us, 10, 5000);
}

static void calculate_t0_timing(S_INTERNAL_SLOT *s)
{
    uint32_t etu_us = calc_etu_us(s);
    uint64_t wwt_us = (uint64_t)s->t0_wwt_etu * etu_us;
    uint32_t wwt_ms = (uint32_t)((wwt_us + 999u) / 1000u);
    s->t0_wwt_ms = clamp_u32(wwt_ms, 250, 10000);
}

static int parse_atr_buffer(S_INTERNAL_SLOT *s, const uint8_t *buffer, size_t length)
{
    if (!s || !buffer || length < 2 || length > sizeof(s->atr)) return -1;

    uint8_t raw[TCMG_INTERNAL_MAX_ATR];
    for (size_t i = 0; i < length; i++) {
        uint8_t b = buffer[i];
        if (buffer[0] == 0x03u) {
            b = (uint8_t)~((((b << 7) & 0x80u) | ((b << 5) & 0x40u) |
                            ((b << 3) & 0x20u) | ((b << 1) & 0x10u) |
                            ((b >> 1) & 0x08u) | ((b >> 3) & 0x04u) |
                            ((b >> 5) & 0x02u) | ((b >> 7) & 0x01u)));
        }
        raw[i] = b;
    }

    size_t n = 0;
    uint8_t ts = raw[n++];
    uint8_t t0 = raw[n++];
    uint8_t y = t0;
    unsigned first_protocol = 0;
    unsigned current_protocol = 0;
    int tck_required = 0;
    uint8_t fi = 1;
    uint8_t di = 1;
    uint8_t d = 1;
    uint8_t wi = TCMG_INTERNAL_DEFAULT_WI;
    uint8_t n_extra = 0;
    uint8_t current_i = 0;

    for (unsigned group = 1; group <= 8; group++) {
        if (y & 0x10u) {
            if (n >= length) return -2;
            uint8_t ta = raw[n++];
            if (group == 1) { fi = (uint8_t)(ta >> 4); di = (uint8_t)(ta & 0x0Fu); }
        }
        if (y & 0x20u) {
            if (n >= length) return -3;
            uint8_t tb = raw[n++];
            if (group == 1) current_i = (uint8_t)((tb & 0x60u) >> 5);
        }
        if (y & 0x40u) {
            if (n >= length) return -4;
            uint8_t tc = raw[n++];
            if (group == 1) n_extra = tc;
            if (group == 2 && current_protocol == 0) wi = tc ? tc : TCMG_INTERNAL_DEFAULT_WI;
        }
        if (!(y & 0x80u)) break;
        if (n >= length) return -5;
        uint8_t td = raw[n++];
        current_protocol = td & 0x0Fu;
        if (group == 1) first_protocol = current_protocol;
        if (current_protocol != 0) tck_required = 1;
        y = td;
    }

    uint8_t historical = (uint8_t)(t0 & 0x0Fu);
    if (n + historical + (tck_required ? 1u : 0u) > length) return -6;
    n += historical;
    if (tck_required) n++;
    if (n != length) return -7;

    static const uint16_t f_table[16] = { 0, 372, 558, 744, 1116, 1488, 1860, 0, 0, 512, 768, 1024, 1536, 2048, 0, 0 };
    static const uint8_t d_table[16] = { 0, 1, 2, 4, 8, 16, 32, 64, 12, 20, 0, 0, 0, 0, 0, 0 };
    if (fi == 0 || fi >= 16 || di == 0 || di >= 16 || !f_table[fi] || !d_table[di]) { fi = 1; di = 1; }
    d = d_table[di];

    if (first_protocol != 0) {
        tcmg_log("reader unsupported ATR protocol T=%u backend=%s device=%s",
                 first_protocol, internal_backend_name(&s->backend), s->device);
        return -8;
    }

    s->atr_len = length;
    memcpy(s->atr, raw, length);
    s->protocol = 0;
    s->t0_fi = fi;
    s->t0_di = di;
    s->t0_d = d;
    s->t0_wi = wi ? wi : TCMG_INTERNAL_DEFAULT_WI;
    s->t0_n = n_extra;
    s->t0_i = current_i;
    s->t0_wwt_etu = 960u * (uint32_t)s->t0_d * (uint32_t)s->t0_wi;
    s->t0_egt_etu = n_extra == 255u ? 0u : n_extra;

    tcmg_log_dbg(D_READER,
                 "ATR backend=%s TS=%02X T0=%02X proto=T0 FI=%u DI=%u D=%u WI=%u N=%u I=%u WWT=%uETU",
                 internal_backend_name(&s->backend), ts, t0, fi, di, s->t0_d, s->t0_wi, s->t0_n, s->t0_i, s->t0_wwt_etu);
    tcmg_dump_dbg(D_READER, s->atr, (int32_t)s->atr_len, "INTERNAL ATR");
    return 0;
}

static int parse_atr(S_INTERNAL_SLOT *s, size_t *atr_len_out)
{
    if (!s || s->fd < 0 || !atr_len_out) return -1;

    size_t n = 0;
    uint8_t ts = 0;
    uint8_t t0 = 0;
    if (read_byte_timeout(s->fd, &ts, TCMG_INTERNAL_ATR_BYTE_MS) < 0 ||
        read_byte_timeout(s->fd, &t0, TCMG_INTERNAL_ATR_BYTE_MS) < 0)
        return -1;

    if (n + 2 > sizeof(s->atr)) return -2;
    s->atr[n++] = ts;
    s->atr[n++] = t0;

    uint8_t y = t0;
    unsigned current_protocol = 0;
    unsigned first_protocol = 0;
    unsigned protocol_count = 1;
    int tck_required = 0;
    uint8_t fi = 1;
    uint8_t di = 1;
    uint8_t d = 1;
    uint8_t wi = TCMG_INTERNAL_DEFAULT_WI;
    uint8_t n_extra = 0;
    uint8_t current_i = 0;

    for (unsigned group = 1; group <= 8; group++) {
        if (y & 0x10u) {
            if (n >= sizeof(s->atr) || read_byte_timeout(s->fd, &s->atr[n], TCMG_INTERNAL_ATR_BYTE_MS) < 0)
                return -3;
            uint8_t ta = s->atr[n++];
            if (group == 1) {
                fi = (uint8_t)(ta >> 4);
                di = (uint8_t)(ta & 0x0Fu);
            }
        }
        if (y & 0x20u) {
            if (n >= sizeof(s->atr) || read_byte_timeout(s->fd, &s->atr[n], TCMG_INTERNAL_ATR_BYTE_MS) < 0)
                return -4;
            if (group == 1) current_i = (uint8_t)((s->atr[n] & 0x60u) >> 5);
            n++;
        }
        if (y & 0x40u) {
            if (n >= sizeof(s->atr) || read_byte_timeout(s->fd, &s->atr[n], TCMG_INTERNAL_ATR_BYTE_MS) < 0)
                return -5;
            uint8_t tc = s->atr[n++];
            if (group == 1) n_extra = tc;
            if (group == 2 && current_protocol == 0) wi = tc ? tc : TCMG_INTERNAL_DEFAULT_WI;
        }
        if (!(y & 0x80u))
            break;
        if (n >= sizeof(s->atr) || read_byte_timeout(s->fd, &s->atr[n], TCMG_INTERNAL_ATR_BYTE_MS) < 0)
            return -6;

        uint8_t td = s->atr[n++];
        current_protocol = td & 0x0Fu;
        if (group == 1) first_protocol = current_protocol;
        if (current_protocol != 0) tck_required = 1;
        y = td;
        protocol_count++;
    }

    const uint8_t historical = t0 & 0x0Fu;
    if (n + historical + (tck_required ? 1u : 0u) > sizeof(s->atr))
        return -7;
    for (uint8_t i = 0; i < historical; i++) {
        if (read_byte_timeout(s->fd, &s->atr[n], TCMG_INTERNAL_ATR_BYTE_MS) < 0)
            return -8;
        n++;
    }
    if (tck_required) {
        if (read_byte_timeout(s->fd, &s->atr[n], TCMG_INTERNAL_ATR_BYTE_MS) < 0)
            return -9;
        n++;
    }

    if (fi == 0 || fi >= 16) fi = 1;
    if (di == 0 || di >= 16) di = 1;

    static const uint16_t f_table[16] = {
        0, 372, 558, 744, 1116, 1488, 1860, 0,
        0, 512, 768, 1024, 1536, 2048, 0, 0
    };
    static const uint8_t d_table[16] = {
        0, 1, 2, 4, 8, 16, 32, 64, 12, 20, 0, 0, 0, 0, 0, 0
    };

    if (f_table[fi] == 0 || d_table[di] == 0) {
        fi = 1;
        di = 1;
    }
    d = d_table[di];

    if (first_protocol != 0) {
        tcmg_log("reader unsupported ATR protocol T=%u device=%s",
                 first_protocol, s->device);
        return -10;
    }

    s->atr_len = n;
    s->protocol = 0;
    s->t0_fi = fi;
    s->t0_di = di;
    s->t0_d = d;
    s->t0_wi = wi ? wi : TCMG_INTERNAL_DEFAULT_WI;
    s->t0_n = n_extra;
    s->t0_i = current_i;
    s->t0_wwt_etu = 960u * (uint32_t)s->t0_d * (uint32_t)s->t0_wi;
    s->t0_egt_etu = n_extra == 255 ? 0 : n_extra;

    *atr_len_out = n;
    tcmg_log_dbg(D_READER,
                 "ATR TS=%02X T0=%02X proto=T0 FI=%u DI=%u D=%u WI=%u N=%u I=%u WWT=%uETU",
                 ts, t0, fi, di, s->t0_d, s->t0_wi, s->t0_n, s->t0_i,
                 s->t0_wwt_etu);
    tcmg_dump_dbg(D_READER, s->atr, (int32_t)s->atr_len, "INTERNAL ATR");

    (void)protocol_count;
    return 0;
}


static void apply_initial_sci_parameters(S_INTERNAL_SLOT *s, SCI_PARAMETERS *p, uint32_t fs)
{
    (void)s;
    sci_parameters_defaults(p);
    p->fs = fs;
}

static uint32_t dreambox_target_clock_10khz(uint8_t fi)
{
    static const uint32_t fsmax_10khz[16] = {
        500u, 500u, 600u, 800u, 1200u, 1600u, 2000u, 0u,
        0u, 500u, 750u, 1000u, 1500u, 2000u, 0u, 0u
    };
    return (fi < 16u) ? fsmax_10khz[fi] : 0u;
}

static uint32_t atr_f(uint8_t fi)
{
    static const uint16_t f_table[16] = {
        0, 372, 558, 744, 1116, 1488, 1860, 0,
        0, 512, 768, 1024, 1536, 2048, 0, 0
    };
    return (fi < 16u) ? f_table[fi] : 0u;
}

static uint32_t dreambox_pll_divider(uint32_t target_clock_10khz)
{
    if (target_clock_10khz == 0) target_clock_10khz = 500u;
    uint32_t div = (TCMG_INTERNAL_DREAMBOX_CARDMHZ + target_clock_10khz - 1u) / target_clock_10khz;
    return div ? div : 1u;
}

static void apply_deprecated_timing(S_INTERNAL_SLOT *s)
{
    s->t0_fi = 1;
    s->t0_di = 1;
    s->t0_d = 1;
    s->t0_wi = TCMG_INTERNAL_DEFAULT_WI;
    s->t0_n = 0;
    s->t0_i = 0;
    s->t0_wwt_etu = 960u * (uint32_t)s->t0_wi;
    s->t0_egt_etu = 0;
}

static void finalize_t0_timing(S_INTERNAL_SLOT *s, SCI_PARAMETERS *post)
{
    const uint32_t target_clock = dreambox_target_clock_10khz(s->t0_fi);
    const uint32_t divider = dreambox_pll_divider(target_clock);
    const uint32_t work_etu = atr_f(s->t0_fi) / (s->t0_d ? s->t0_d : 1u);

    post->T = 0;
    post->fs = divider;
    post->ETU = work_etu ? work_etu : TCMG_INTERNAL_DEFAULT_ETU;
    post->WWT = s->t0_wwt_etu;
    post->CWT = 0;
    post->BWT = 0;
    post->EGT = s->t0_egt_etu;
    post->P = 5;
    post->I = s->t0_i;

    s->sci_fs = post->fs;
    s->sci_etu = post->ETU;
    calculate_t0_timing(s);

    tcmg_log_dbg(D_READER,
                 "SCI ATR settings FI=%u D=%u target=%u.%02uMHz divider=%u actual=%u.%02uMHz ETU=%u WWT=%ums EGT=%u",
                 s->t0_fi, s->t0_d,
                 target_clock / 100u, target_clock % 100u * 10u,
                 divider,
                 (TCMG_INTERNAL_DREAMBOX_CARDMHZ / divider) / 100u,
                 ((TCMG_INTERNAL_DREAMBOX_CARDMHZ / divider) % 100u) * 10u,
                 post->ETU, s->t0_wwt_ms, post->EGT);
}

static int sci_write_parameters(S_INTERNAL_SLOT *s, const SCI_PARAMETERS *p)
{
#ifdef __linux__
    if (!s || s->fd < 0 || !p) return -1;
    SCI_PARAMETERS next = *p;
    if (ioctl(s->fd, SCI_SET_PARAMETERS, &next) < 0)
        return -1;
    s->params_applied = 1;
    s->sci_fs = next.fs;
    s->sci_etu = next.ETU;
    return 0;
#else
    (void)s;
    (void)p;
    return -1;
#endif
}

static int sci_reset_card_once(S_INTERNAL_SLOT *s, const char *reason, int deprecated)
{
#ifdef __linux__
    if (!s || s->fd < 0) return -1;
    const int64_t reset_t0 = mono_ms();

    s->reset_fail[0] = '\0';
    if (reader_present(s) <= 0) {
        s->ready = 0;
        snprintf(s->reset_fail, sizeof(s->reset_fail), "no card detected (SCI_GET_PRESENT errno=%d)", errno);
        return -1;
    }

    int success = -1;
    for (unsigned attempt = 0; attempt <= TCMG_INTERNAL_PLL_RETRIES; attempt++) {
        uint32_t initial_fs = (attempt == 0) ? TCMG_INTERNAL_DEFAULT_FS
                                             : (TCMG_INTERNAL_PLL_START_FS - attempt);
        if (initial_fs < 3u) initial_fs = 3u;

        SCI_PARAMETERS p;
        apply_initial_sci_parameters(s, &p, initial_fs);
        if (sci_write_parameters(s, &p) < 0) {
            snprintf(s->reset_fail, sizeof(s->reset_fail), "SCI_SET_PARAMETERS failed fs=%u errno=%d", initial_fs, errno);
            s->params_applied = 0;
            if (attempt == TCMG_INTERNAL_PLL_RETRIES) break;
            continue;
        }

        tcmg_sleep_ms(TCMG_INTERNAL_SCI_SETTLE_MS);
        (void)write_flush(s->fd);
        tcmg_sleep_ms(TCMG_INTERNAL_RESET_SETTLE_MS);

        uint32_t reset = 1;
        if (ioctl(s->fd, SCI_SET_RESET, &reset) < 0) {
            snprintf(s->reset_fail, sizeof(s->reset_fail), "SCI_SET_RESET failed fs=%u errno=%d", initial_fs, errno);
            tcmg_log_dbg(D_READER,
                         "reset ioctl failed device=%s attempt=%u fs=%u errno=%d",
                         s->device, attempt + 1u, initial_fs, errno);
            s->ready = 0;
            if (attempt == TCMG_INTERNAL_PLL_RETRIES) break;
            continue;
        }

        s->ready = 0;
        s->atr_len = 0;
        int atr_rc = parse_atr(s, &s->atr_len);
        if (atr_rc < 0) {
            snprintf(s->reset_fail, sizeof(s->reset_fail), "ATR read failed fs=%u code=%d got=%zu bytes", initial_fs, atr_rc, s->atr_len);
            tcmg_log_dbg(D_READER,
                         "ATR read failed device=%s attempt=%u fs=%u",
                         s->device, attempt + 1u, initial_fs);
            if (attempt == TCMG_INTERNAL_PLL_RETRIES) break;
            continue;
        }

        uint32_t atr_ready = 1;
        if (ioctl(s->fd, SCI_SET_ATR_READY, &atr_ready) < 0) {
            snprintf(s->reset_fail, sizeof(s->reset_fail), "SCI_SET_ATR_READY failed errno=%d", errno);
            tcmg_log("ATR_READY failed device=%s errno=%d", s->device, errno);
            s->ready = 0;
            break;
        }

        if (deprecated) apply_deprecated_timing(s);
        SCI_PARAMETERS post = p;
        finalize_t0_timing(s, &post);
        if (sci_write_parameters(s, &post) < 0) {
            snprintf(s->reset_fail, sizeof(s->reset_fail), "post-ATR SCI_SET_PARAMETERS failed errno=%d", errno);
            tcmg_log("post-ATR SCI parameters failed device=%s errno=%d",
                     s->device, errno);
            s->ready = 0;
            break;
        }

        calculate_t0_timing(s);
        tcmg_sleep_ms(TCMG_INTERNAL_SCI_SETTLE_MS);
        s->present = 1;
        s->ready = 1;
        s->last_reset_ms = mono_ms();
        success = 0;
        break;
    }

    if (success == 0) {
        const uint32_t actual_clock = s->sci_fs ?
            TCMG_INTERNAL_DREAMBOX_CARDMHZ / s->sci_fs : 0;
        tcmg_log_force("card reset ok%s reason=%s device=%s T=%d ATR=%zu fs=%u clock=%u.%02uMHz ETU=%u WWT=%ums D=%u WI=%u FI=%u elapsed=%lldms",
                       deprecated ? " (deprecated mode)" : "",
                       reason && *reason ? reason : "unknown",
                       s->device, s->protocol, s->atr_len,
                       s->sci_fs, actual_clock / 100u, (actual_clock % 100u) * 10u,
                       s->sci_etu, s->t0_wwt_ms, s->t0_d, s->t0_wi, s->t0_fi,
                       (long long)(mono_ms() - reset_t0));
    }
    return success;
#else
    (void)s;
    (void)reason;
    return -1;
#endif
}

static int sci_reset_card(S_INTERNAL_SLOT *s, const char *reason)
{
    const int deprecated = s->deprecated_cfg || s->deprecated_active;
    int rc = sci_reset_card_once(s, reason, deprecated);
    if (rc == 0 || deprecated || reader_present(s) <= 0)
        return rc;
    tcmg_log("reader device=%s: Normal mode failed (%s), reverting to Deprecated Mode",
             s->device, s->reset_fail[0] ? s->reset_fail : "card not recognised");
    rc = sci_reset_card_once(s, reason, 1);
    if (rc == 0) s->deprecated_active = 1;
    return rc;
}

static int backend_reset_card_once(S_INTERNAL_SLOT *s, const char *reason, int deprecated);

static int backend_reset_card(S_INTERNAL_SLOT *s, const char *reason)
{
    const int deprecated = s->deprecated_cfg || s->deprecated_active;
    int rc = backend_reset_card_once(s, reason, deprecated);
    if (rc == 0 || deprecated || reader_present(s) <= 0)
        return rc;
    tcmg_log("reader device=%s: Normal mode failed, reverting to Deprecated Mode", s->device);
    rc = backend_reset_card_once(s, reason, 1);
    if (rc == 0) s->deprecated_active = 1;
    return rc;
}

static int backend_reset_card_once(S_INTERNAL_SLOT *s, const char *reason, int deprecated)
{
    if (!s || !internal_backend_is_open(&s->backend)) return -1;
    int64_t reset_t0 = mono_ms();
    if (reader_present(s) <= 0) { s->ready = 0; return -1; }
    uint8_t atr[TCMG_INTERNAL_MAX_ATR];
    size_t atr_len = sizeof(atr);
    if (internal_backend_reset(&s->backend, atr, &atr_len) < 0) {
        s->ready = 0;
        return -1;
    }
    if (parse_atr_buffer(s, atr, atr_len) < 0) {
        s->ready = 0;
        return -1;
    }
    if (deprecated) apply_deprecated_timing(s);
    calculate_t0_timing(s);
    s->present = 1;
    s->ready = 1;
    s->params_applied = 0;
    s->last_reset_ms = mono_ms();
    tcmg_log_force("card reset ok reason=%s backend=%s device=%s T=%d ATR=%zu ETU=%u WWT=%ums D=%u WI=%u FI=%u elapsed=%lldms",
                   reason && *reason ? reason : "unknown", internal_backend_name(&s->backend), s->device,
                   s->protocol, s->atr_len, s->sci_etu, s->t0_wwt_ms, s->t0_d, s->t0_wi, s->t0_fi,
                   (long long)(mono_ms() - reset_t0));
    return 0;
}

static ssize_t t0_backend_read(void *ctx, uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    return internal_backend_read((S_INTERNAL_BACKEND *)ctx, buf, len, timeout_ms);
}

static ssize_t t0_backend_write(void *ctx, const uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    return internal_backend_write((S_INTERNAL_BACKEND *)ctx, buf, len, timeout_ms);
}

static int t0_backend_flush(void *ctx)
{
    return internal_backend_flush((S_INTERNAL_BACKEND *)ctx);
}

static int conax_sct_length(const uint8_t *ecm, size_t ecm_len, size_t *out_len)
{
    if (!ecm || !out_len || ecm_len < 3) return -1;
    size_t declared = 3u + (((size_t)(ecm[1] & 0x0Fu) << 8) | ecm[2]);
    if (declared < 3 || declared > ecm_len || declared > 249) return -1;
    *out_len = declared;
    return 0;
}


static int internal_conax_ecm(S_INTERNAL_SLOT *s, const uint8_t *ecm, size_t ecm_len,
                              uint8_t cw[16], int *recoverable, int allow_ca)
{
    if (recoverable) *recoverable = 0;
    if (!s || !ecm || !cw || ecm_len == 0 || ecm_len > 249)
        return -1;

    size_t n = ecm_len;
    (void)conax_sct_length(ecm, ecm_len, &n);

    uint8_t apdu[260];
    uint8_t rsp[320];
    size_t rsp_len = sizeof(rsp);
    size_t apdu_len = 8u + n;

    apdu[0] = 0xDD;
    apdu[1] = 0xA2;
    apdu[2] = 0x00;
    apdu[3] = 0x00;
    apdu[4] = (uint8_t)(n + 3u);
    apdu[5] = 0x14;
    apdu[6] = (uint8_t)(n + 1u);
    apdu[7] = 0x00;
    memcpy(apdu + 8, ecm, n);

    S_INTERNAL_T0_CHANNEL ch = {
        .fd = s->fd,
        .ctx = &s->backend,
        .read_fn = t0_backend_read,
        .write_fn = t0_backend_write,
        .flush_fn = t0_backend_flush,
        .wwt_ms = s->t0_wwt_ms,
        .io_write_timeout_ms = TCMG_INTERNAL_IO_WRITE_MS,
        .max_nulls = TCMG_INTERNAL_MAX_NULLS
    };

    int t0_rc;
    if (s->backend.kind == TCMG_INTERNAL_BACKEND_COOLAPI) {
        const char *trace = allow_ca ? "ecm" : "old-ecm";
        tcmg_dump_dbg(D_READER, apdu, (int32_t)apdu_len, "INTERNAL COOLAPI >> APDU context=%s", trace);
        t0_rc = internal_backend_transceive(&s->backend, apdu, apdu_len, rsp, &rsp_len,
                                            s->t0_wwt_ms ? s->t0_wwt_ms : 4000u);
        if (t0_rc == 0)
            tcmg_dump_dbg(D_READER, rsp, (int32_t)rsp_len, "INTERNAL COOLAPI << RESPONSE context=%s", trace);
    } else {
        t0_rc = internal_t0_exchange(&ch, apdu, apdu_len, allow_ca ? "ecm" : "old-ecm", rsp, &rsp_len);
    }
    if (t0_rc < 0) {
        tcmg_log_dbg(D_READER, "Conax DD A2 transport failed context=%s rc=%d", allow_ca ? "ecm" : "old-ecm", t0_rc);
        if (recoverable) *recoverable = 1;
        return -2;
    }
    if (rsp_len < 2) {
        if (recoverable) *recoverable = 1;
        return -3;
    }

    uint8_t sw1 = rsp[rsp_len - 2];
    uint8_t sw2 = rsp[rsp_len - 1];
    int got = 0;

    if (sw1 == 0x6F && sw2 == 0x01) {
        if (recoverable) *recoverable = 1;
        return -4;
    }
    if (sw1 != 0x90 && sw1 != 0x98)
        return -5;

    if (sw1 == 0x90 && sw2 == 0x00) {
        if (tcmg_parse_conax_cw(rsp, rsp_len, cw, &got) == -2)
            return -6;
    }
    if (!allow_ca) return got == 3 ? 0 : -13;

    unsigned ca_round = 0;
    while (sw1 == 0x98 && sw2 != 0x00 && sw2 != 0xFF) {
        if (++ca_round > 8) return -7;

        uint8_t ins_ca[5] = { 0xDD, 0xCA, 0x00, 0x00, sw2 };
        rsp_len = sizeof(rsp);
        int ca_rc;
        if (s->backend.kind == TCMG_INTERNAL_BACKEND_COOLAPI) {
            const char *trace = allow_ca ? "ecm-ca" : "old-ecm-ca";
            tcmg_dump_dbg(D_READER, ins_ca, sizeof(ins_ca), "INTERNAL COOLAPI >> APDU context=%s", trace);
            ca_rc = internal_backend_transceive(&s->backend, ins_ca, sizeof(ins_ca), rsp, &rsp_len,
                                                s->t0_wwt_ms ? s->t0_wwt_ms : 4000u);
            if (ca_rc == 0)
                tcmg_dump_dbg(D_READER, rsp, (int32_t)rsp_len, "INTERNAL COOLAPI << RESPONSE context=%s", trace);
        } else {
            ca_rc = internal_t0_exchange(&ch, ins_ca, sizeof(ins_ca), allow_ca ? "ecm-ca" : "old-ecm-ca", rsp, &rsp_len);
        }
        if (ca_rc < 0) {
            if (recoverable) *recoverable = 1;
            return -8;
        }
        if (rsp_len < 2) {
            if (recoverable) *recoverable = 1;
            return -9;
        }

        sw1 = rsp[rsp_len - 2];
        sw2 = rsp[rsp_len - 1];
        if (sw1 == 0x6F && sw2 == 0x01) {
            if (recoverable) *recoverable = 1;
            return -10;
        }
        if (sw1 != 0x98 && !(sw1 == 0x90 && sw2 == 0x00))
            return -11;

        int part = 0;
        if (tcmg_parse_conax_cw(rsp, rsp_len, cw, &part) == -2)
            return -12;
        got |= part;
    }

    return got == 3 ? 0 : -13;
}

static int worker_wait(S_INTERNAL_SLOT *s, int timeout_ms)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&s->mtx);
    if (!s->worker_stop && s->queue_count == 0)
        (void)pthread_cond_timedwait(&s->cv, &s->mtx, &ts);
    int stop = s->worker_stop;
    pthread_mutex_unlock(&s->mtx);
    return stop ? -1 : 0;
}

static void *internal_reader_worker(void *arg)
{
    int index = (int)(intptr_t)arg;
    S_INTERNAL_SLOT *s = &s_slots[index];

    for (;;) {
        S_READER cfg;
        if (!cfg_runtime_reader_get(index, &cfg) ||
            !cfg.in_use || !cfg.enabled ||
            strcasecmp(cfg.protocol, "internal") != 0)
            break;

        const char *target_device = cfg.device[0] ? cfg.device : "auto";
        s->deprecated_cfg = cfg.deprecated ? 1 : 0;

        pthread_mutex_lock(&s->mtx);
        if (s->worker_stop) {
            pthread_mutex_unlock(&s->mtx);
            break;
        }
        tcmg_strlcpy(s->target_device, target_device, sizeof(s->target_device));
        int fd_ready = internal_backend_is_open(&s->backend) && strcmp(s->target_device, target_device) == 0;
        pthread_mutex_unlock(&s->mtx);

        if (!fd_ready) {
            pthread_mutex_lock(&s->mtx);
            if (!s->worker_stop && slot_open(s, target_device) < 0) {
                s->present = 0;
                s->ready = 0;
            }
            pthread_mutex_unlock(&s->mtx);
            if (!internal_backend_is_open(&s->backend)) {
                worker_wait(s, 1000);
                continue;
            }
        }

        pthread_mutex_lock(&s->mtx);
        if (s->worker_stop) {
            pthread_mutex_unlock(&s->mtx);
            break;
        }

        int present = reader_present(s);
        if (!present) {
            s->deprecated_active = 0;
            s->ready = 0;
            s->params_applied = 0;
            s->fast_reset_paused = 0;
            reader_old_ecm_unbind(&s->old_ecm);
        } else {
            const int64_t now_ms = mono_ms();
            if (s->ready) {
                reader_old_ecm_sync(&s->old_ecm, &cfg);
                reader_old_ecm_bind(&s->old_ecm, &cfg, s->device, s->atr, s->atr_len);
            } else {
                reader_old_ecm_unbind(&s->old_ecm);
            }

            int interval_due = 0;
            if (cfg.maintenance_mode == TCMG_READER_MAINT_FAST_RESET && cfg.fast_reset > 0 && s->ready && s->present) {
                const int idle_enabled = cfg.fast_reset_idle > 0;
                const int idle = idle_enabled && now_ms - s->last_activity_ms >=
                                 (int64_t)cfg.fast_reset_idle * 1000LL;
                if (s->fast_reset_paused) {
                    if (s->last_activity_ms != s->last_activity_seen_ms) {
                        s->fast_reset_paused = 0;
                        s->last_activity_seen_ms = s->last_activity_ms;
                        s->last_reset_ms = now_ms;
                        tcmg_log_force("fast reset resumed device=%s", s->device);
                    }
                } else if (idle) {
                    s->fast_reset_paused = 1;
                    s->last_activity_seen_ms = s->last_activity_ms;
                    tcmg_log_force("fast reset paused device=%s idle=%ds", s->device, cfg.fast_reset_idle);
                }
                interval_due = !s->fast_reset_paused &&
                               s->queue_count == 0 && s->ecm_active == 0 &&
                               s->last_reset_ms > 0 &&
                               now_ms - s->last_reset_ms >= (int64_t)cfg.fast_reset * 1000LL;
            } else if (cfg.maintenance_mode != TCMG_READER_MAINT_FAST_RESET) {
                s->fast_reset_paused = 0;
            }

            int need_reset = !s->ready;
            const char *reason = "startup";
            if (interval_due) {
                need_reset = 1;
                reason = "periodic";
            }
            if (need_reset) {
                int reset_rc = (s->backend.kind == TCMG_INTERNAL_BACKEND_SCI)
                    ? sci_reset_card(s, reason) : backend_reset_card(s, reason);
                if (reset_rc < 0)
                    tcmg_log("reader[%d]: %s reset failed backend=%s device=%s%s%s", index + 1, reason,
                             internal_backend_name(&s->backend), s->device,
                             s->reset_fail[0] ? " why=" : "", s->reset_fail);
                if (s->ready) {
                    reader_old_ecm_sync(&s->old_ecm, &cfg);
                    reader_old_ecm_bind(&s->old_ecm, &cfg, s->device, s->atr, s->atr_len);
                }
            }

            if (cfg.maintenance_mode == TCMG_READER_MAINT_OLD_ECM && s->ready && s->present &&
                s->queue_count == 0 && s->ecm_active == 0 &&
                reader_old_ecm_due(&cfg, &s->old_ecm, s->ecm_active != 0)) {
                const uint8_t *old_ecm = NULL;
                size_t old_ecm_len = 0;
                if (reader_old_ecm_get(&s->old_ecm, &old_ecm, &old_ecm_len) == 0) {
                    uint8_t ecm_copy[TCMG_OLD_ECM_MAX_LEN];
                    memcpy(ecm_copy, old_ecm, old_ecm_len);
                    tcmg_log_dbg(D_READER, "OLD ECM start device=%s source=%s len=%zu",
                                 s->device,
                                 cfg.old_ecm_source == TCMG_OLD_ECM_SOURCE_MANUAL ? "manual" : "auto",
                                 old_ecm_len);
                    reader_old_ecm_note_attempt(&s->old_ecm);
                    s->ecm_active++;
                    pthread_mutex_unlock(&s->mtx);

                    uint8_t cw[16] = {0};
                    int recoverable = 0;
                    int64_t old_t0 = mono_ms();
                    int old_rc = internal_conax_ecm(s, ecm_copy, old_ecm_len, cw, &recoverable, 0);

                    pthread_mutex_lock(&s->mtx);
                    if (s->ecm_active > 0) s->ecm_active--;
                    s->last_activity_ms = mono_ms();
                    tcmg_log_dbg(D_READER, "OLD ECM result=%s device=%s elapsed=%lldms",
                                 old_rc == 0 ? "success" : "failed", s->device,
                                 (long long)(mono_ms() - old_t0));
                }
            }
        }

        int job_index = (s->ready && s->present) ? queue_pop_locked(s) : -1;
        if (job_index >= 0) {
            S_INTERNAL_JOB *job = &s->jobs[job_index];
            if (job->state == INTERNAL_JOB_CANCELLED) {
                queue_release_locked(job);
                pthread_cond_broadcast(&s->cv);
                pthread_mutex_unlock(&s->mtx);
                continue;
            }

            job->state = INTERNAL_JOB_RUNNING;
            s->ecm_active++;
            const size_t ecm_len = job->ecm_len;
            uint8_t ecm[249];
            memcpy(ecm, job->ecm, ecm_len);
            pthread_mutex_unlock(&s->mtx);

            uint8_t cw[16] = {0};
            int recoverable = 0;
            int rc = internal_conax_ecm(s, ecm, ecm_len, cw, &recoverable, 1);
            if (rc == 0) {
                reader_old_ecm_sync(&s->old_ecm, &cfg);
                if (s->ready && s->present)
                    reader_old_ecm_bind(&s->old_ecm, &cfg, s->device, s->atr, s->atr_len);
                reader_old_ecm_note_success(&s->old_ecm, &cfg, ecm, ecm_len);
            }

            if (rc < 0 && recoverable) {
                pthread_mutex_lock(&s->mtx);
                int reset_rc = (s->backend.kind == TCMG_INTERNAL_BACKEND_SCI)
                    ? sci_reset_card(s, "ecm-recovery") : backend_reset_card(s, "ecm-recovery");
                pthread_mutex_unlock(&s->mtx);
                if (reset_rc == 0) {
                    memset(cw, 0, sizeof(cw));
                    recoverable = 0;
                    rc = internal_conax_ecm(s, ecm, ecm_len, cw, &recoverable, 1);
                }
                if (rc < 0 && recoverable && !s->deprecated_cfg && !s->deprecated_active) {
                    pthread_mutex_lock(&s->mtx);
                    tcmg_log("reader device=%s: ECM failed in normal mode, reverting to Deprecated Mode", s->device);
                    s->deprecated_active = 1;
                    reset_rc = (s->backend.kind == TCMG_INTERNAL_BACKEND_SCI)
                        ? sci_reset_card(s, "ecm-deprecated") : backend_reset_card(s, "ecm-deprecated");
                    if (reset_rc < 0) s->deprecated_active = 0;
                    pthread_mutex_unlock(&s->mtx);
                    if (reset_rc == 0) {
                        memset(cw, 0, sizeof(cw));
                        recoverable = 0;
                        rc = internal_conax_ecm(s, ecm, ecm_len, cw, &recoverable, 1);
                    }
                }
            }

            pthread_mutex_lock(&s->mtx);
            if (s->ecm_active > 0) s->ecm_active--;
            if (job->state == INTERNAL_JOB_CANCELLED) {
                queue_release_locked(job);
            } else {
                job->rc = rc;
                job->recoverable = recoverable;
                if (rc == 0)
                    memcpy(job->cw, cw, sizeof(job->cw));
                job->state = INTERNAL_JOB_DONE;
                if (job->waiters == 0)
                    queue_release_locked(job);
            }
            pthread_cond_broadcast(&s->cv);
            pthread_mutex_unlock(&s->mtx);
            continue;
        }

        pthread_mutex_unlock(&s->mtx);

        if (worker_wait(s, TCMG_INTERNAL_SYNC_POLL_MS) < 0) break;
    }

    pthread_mutex_lock(&s->mtx);
    for (int i = 0; i < TCMG_INTERNAL_ECM_QUEUE_CAP; i++) {
        if (s->jobs[i].state != INTERNAL_JOB_FREE && s->jobs[i].state != INTERNAL_JOB_DONE) {
            s->jobs[i].rc = -9;
            s->jobs[i].recoverable = 0;
            s->jobs[i].state = INTERNAL_JOB_DONE;
        }
    }
    s->worker_running = 0;
    s->worker_stop = 0;
    s->ecm_active = 0;
    s->target_device[0] = '\0';
    pthread_cond_broadcast(&s->cv);
    while (queue_waiter_count_locked(s) > 0)
        (void)pthread_cond_wait(&s->cv, &s->mtx);
    slot_clear(s);
    pthread_mutex_unlock(&s->mtx);
    return NULL;
}

static int start_reader_worker(int index, const char *device)
{
    S_INTERNAL_SLOT *s = &s_slots[index];
    pthread_mutex_lock(&s->mtx);
    if (s->worker_running) {
        pthread_mutex_unlock(&s->mtx);
        return 0;
    }
    s->worker_stop = 0;
    queue_reset_locked(s);
    tcmg_strlcpy(s->target_device, device ? device : "", sizeof(s->target_device));
    s->worker_running = 1;
    int trc = pthread_create(&s->worker_tid, NULL, internal_reader_worker, (void *)(intptr_t)index);
    if (trc != 0) {
        s->worker_running = 0;
        s->target_device[0] = '\0';
        pthread_mutex_unlock(&s->mtx);
        tcmg_log("internal reader %d worker thread failed rc=%d (%s)", index, trc, strerror(trc));
        return -1;
    }
    pthread_mutex_unlock(&s->mtx);
    return 0;
}

static void stop_reader_worker(int index)
{
    S_INTERNAL_SLOT *s = &s_slots[index];
    pthread_t tid;
    int join = 0;

    pthread_mutex_lock(&s->mtx);
    if (s->worker_running) {
        s->worker_stop = 1;
        tid = s->worker_tid;
        join = 1;
        pthread_cond_broadcast(&s->cv);
    }
    pthread_mutex_unlock(&s->mtx);

    if (join) pthread_join(tid, NULL);

    pthread_mutex_lock(&s->mtx);
    if (!internal_backend_is_open(&s->backend)) slot_reset_state(s);
    pthread_mutex_unlock(&s->mtx);
}

static int internal_sync_once(void)
{
    S_READER cfg_readers[MAX_READERS];
    int reader_count = cfg_runtime_reader_snapshot_indexed(cfg_readers, MAX_READERS);

    for (int i = 0; i < MAX_READERS; i++) {
        S_READER *cfg = (i < reader_count) ? &cfg_readers[i] : NULL;
        int want = cfg && cfg->in_use && cfg->enabled &&
                   strcasecmp(cfg->protocol, "internal") == 0;
        const char *target_device = want && cfg->device[0] ? cfg->device : (want ? "auto" : "");

        pthread_mutex_lock(&s_slots[i].mtx);
        int running = s_slots[i].worker_running;
        int matches = running && strcmp(s_slots[i].target_device, target_device) == 0;
        pthread_mutex_unlock(&s_slots[i].mtx);

        if (!want) {
            if (running) stop_reader_worker(i);
            continue;
        }

        if (!matches) {
            if (running) stop_reader_worker(i);
            if (start_reader_worker(i, target_device) < 0)
                tcmg_log("reader[%d]: failed to start worker device=%s",
                         i + 1, target_device);
        }
    }
    return 250;
}

static void *internal_thread(void *arg)
{
    (void)arg;
    while (atomic_load(&s_running)) {
        int poll = internal_sync_once();
        tcmg_sleep_ms(poll);
    }
    return NULL;
}

int internal_start(void)
{
    slots_init();
    if (atomic_exchange(&s_running, 1)) return 0;
    (void)internal_sync_once();
    int trc = pthread_create(&s_tid, NULL, internal_thread, NULL);
    if (trc != 0) {
        atomic_store(&s_running, 0);
        for (int i = 0; i < MAX_READERS; i++) stop_reader_worker(i);
        tcmg_log("internal manager thread failed rc=%d (%s)", trc, strerror(trc));
        return -1;
    }
    tcmg_log("reader support enabled");
    return 0;
}

void internal_stop(void)
{
    slots_init();
    if (atomic_exchange(&s_running, 0)) pthread_join(s_tid, NULL);
    for (int i = 0; i < MAX_READERS; i++) stop_reader_worker(i);
}

int internal_reader_get(int index, S_INTERNAL_READER *out)
{
    if (!out || index < 0 || index >= MAX_READERS) return -1;
    slots_init();
    pthread_mutex_lock(&s_slots[index].mtx);
    memset(out, 0, sizeof(*out));
    out->owned = internal_backend_is_open(&s_slots[index].backend);
    out->exclusive = s_slots[index].backend.exclusive;
    tcmg_strlcpy(out->device,
                  s_slots[index].target_device[0] ? s_slots[index].target_device : s_slots[index].device,
                  sizeof(out->device));
    out->present = s_slots[index].present;
    out->ready = s_slots[index].ready;
    out->atr_len = s_slots[index].atr_len;
    if (out->atr_len > sizeof(out->atr)) out->atr_len = sizeof(out->atr);
    memcpy(out->atr, s_slots[index].atr, out->atr_len);
    out->protocol = s_slots[index].protocol;
    if (s_slots[index].backend.name[0])
        tcmg_strlcpy(out->backend, s_slots[index].backend.name, sizeof(out->backend));
    int owned = out->owned;
    pthread_mutex_unlock(&s_slots[index].mtx);
    return owned ? 0 : -1;
}

int internal_reader_count(void)
{
    int n = 0;
    slots_init();
    for (int i = 0; i < MAX_READERS; i++) {
        pthread_mutex_lock(&s_slots[i].mtx);
        if (internal_backend_is_open(&s_slots[i].backend)) n++;
        pthread_mutex_unlock(&s_slots[i].mtx);
    }
    return n;
}

int internal_do_ecm_reader(int index, uint16_t caid,
                           const uint8_t *ecm, size_t ecm_len,
                           uint8_t cw[16], int32_t whitelist, E_READER_FAILURE *failure)
{
    if (failure) *failure = READER_FAILURE_READER_ERROR;
    if (index < 0 || index >= MAX_READERS || !ecm || !cw || ecm_len == 0 || ecm_len > 249)
        return -1;
    if ((caid & 0xFF00u) != 0x0B00u) return -2;
    if (whitelist > 0 && ecm_len != (size_t)whitelist) return -3;

    slots_init();
    S_READER cfg;
    if (!cfg_runtime_reader_get(index, &cfg)) return -4;
    if (!cfg.enabled || strcasecmp(cfg.protocol, "internal") != 0) return -5;

    S_INTERNAL_SLOT *s = &s_slots[index];
    pthread_mutex_lock(&s->mtx);
    if (!s->worker_running || !internal_backend_is_open(&s->backend) || !s->ready || !s->present) {
        if (failure) *failure = READER_FAILURE_TRANSPORT_ERROR;
        pthread_mutex_unlock(&s->mtx);
        return -6;
    }
    s->last_activity_ms = mono_ms();

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += TCMG_INTERNAL_ECM_WAIT_MS / 1000;
    ts.tv_nsec += (long)(TCMG_INTERNAL_ECM_WAIT_MS % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    int joined = 0;
    int job_index = -1;
    for (;;) {
        job_index = queue_submit_locked(s, ecm, ecm_len, &joined);
        if (job_index >= 0) break;
        int wait_rc = pthread_cond_timedwait(&s->cv, &s->mtx, &ts);
        if (wait_rc == ETIMEDOUT || !s->worker_running || s->worker_stop) {
            if (failure) *failure = READER_FAILURE_TRANSPORT_ERROR;
            pthread_mutex_unlock(&s->mtx);
            return -7;
        }
        if (!s->ready || !s->present) {
            if (failure) *failure = READER_FAILURE_TRANSPORT_ERROR;
            pthread_mutex_unlock(&s->mtx);
            return -6;
        }
    }

    S_INTERNAL_JOB *job = &s->jobs[job_index];
    if (joined) {
        tcmg_log_dbg(D_READER,
                     "coalesced ECM index=%d device=%s waiters=%u",
                     index, s->device, job->waiters);
    }
    pthread_cond_signal(&s->cv);

    while (job->state != INTERNAL_JOB_DONE && s->worker_running && !s->worker_stop) {
        int wait_rc = pthread_cond_timedwait(&s->cv, &s->mtx, &ts);
        if (wait_rc == ETIMEDOUT) {
            if (failure) *failure = READER_FAILURE_TRANSPORT_ERROR;
            if (job->waiters > 0) job->waiters--;
            if (job->state == INTERNAL_JOB_QUEUED && job->waiters == 0)
                job->state = INTERNAL_JOB_CANCELLED;
            pthread_cond_broadcast(&s->cv);
            pthread_mutex_unlock(&s->mtx);
            return -8;
        }
    }

    if (job->state != INTERNAL_JOB_DONE) {
        if (failure) *failure = READER_FAILURE_TRANSPORT_ERROR;
        if (job->waiters > 0) job->waiters--;
        if (job->state == INTERNAL_JOB_CANCELLED && job->waiters == 0)
            queue_release_locked(job);
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mtx);
        return -9;
    }

    int rc = job->rc;
    if (failure) {
        if (rc == 0) *failure = READER_FAILURE_NONE;
        else if (job->recoverable) *failure = READER_FAILURE_TRANSPORT_ERROR;
        else if (rc == -13) *failure = READER_FAILURE_NOT_FOUND;
        else *failure = READER_FAILURE_CARD_ERROR;
    }
    if (rc == 0) memcpy(cw, job->cw, sizeof(job->cw));
    if (job->waiters > 0) job->waiters--;
    if (job->waiters == 0) queue_release_locked(job);
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mtx);
    return rc;
}

#else

int internal_start(void) { return 0; }
void internal_stop(void) { }
int internal_reader_get(int index, S_INTERNAL_READER *out)
{
    (void)index;
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    return -1;
}
int internal_reader_count(void) { return 0; }
int internal_do_ecm_reader(int index, uint16_t caid,
                           const uint8_t *ecm, size_t ecm_len,
                           uint8_t cw[16], int32_t whitelist, E_READER_FAILURE *failure)
{
    if (failure) *failure = READER_FAILURE_READER_ERROR;
    (void)index;
    (void)caid;
    (void)ecm;
    (void)ecm_len;
    (void)cw;
    (void)whitelist;
    return -100;
}

#endif
