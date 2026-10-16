#define MODULE_LOG_PREFIX "internal"
#include "reader_backend.h"
#include "../core/utils.h"
#include "../log/log.h"

#include <stdlib.h>
#include <string.h>

#ifndef TCMG_OS_WINDOWS

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/utsname.h>
#include <termios.h>
#include <unistd.h>

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
#define SCI_GET_PRESENT _IOW(SCI_IOW_MAGIC, 8, uint32_t)
#define SCI_SET_ATR_READY _IOW(SCI_IOW_MAGIC, 11, uint32_t)
#endif

typedef struct {
    unsigned char value;
    uint8_t present;
} OSC_ATR_IB;

typedef struct {
    unsigned length;
    unsigned char TS;
    unsigned char T0;
    OSC_ATR_IB ib[7][4];
    OSC_ATR_IB TCK;
    unsigned pn;
    unsigned char hb[15];
    unsigned hbn;
} OSC_ATR;

#ifdef TCMG_STAPI_STATIC
#ifndef TCMG_STAPI_STATIC5
#define TCMG_STAPI_STATIC5 0
#endif
extern int32_t STReader_Open(char *, uint32_t *);
extern int32_t STReader_GetStatus(uint32_t, int32_t *);
extern int32_t STReader_Reset(uint32_t, OSC_ATR *);
extern int32_t STReader_Transmit(uint32_t, unsigned char *, uint32_t);
extern int32_t STReader_Receive(uint32_t, unsigned char *, uint32_t);
extern int32_t STReader_Close(uint32_t);
extern int32_t STReader_SetProtocol(uint32_t, unsigned char *, unsigned *, uint32_t);
extern int32_t STReader_SetClockrate(uint32_t);
#ifdef TCMG_STAPI_STATIC5
extern char *STReader_GetRevision(void);
#endif

uint16_t cs_dblevel;

void cs_sleepms(uint32_t msec)
{
    tcmg_sleep_ms(msec);
}

void cs_log_txt(const char *log_prefix, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    tcmg_log_force_txt(log_prefix && *log_prefix ? log_prefix : "stapi", "%s", buf);
}

void cs_log_hex(const char *log_prefix, const uint8_t *buf, int32_t n, const char *fmt, ...)
{
    char msg[768];
    char hex[512];
    size_t pos = 0;
    va_list ap;
    hex[0] = 0;
    if (!buf || n < 0) return;
    va_start(ap, fmt);
    if (fmt) vsnprintf(msg, sizeof(msg), fmt, ap);
    else msg[0] = 0;
    va_end(ap);
    for (int32_t i = 0; i < n && pos + 3 < sizeof(hex); i++)
        pos += (size_t)snprintf(hex + pos, sizeof(hex) - pos, "%02X%s", buf[i], i + 1 < n ? " " : "");
    tcmg_log_force_txt(log_prefix && *log_prefix ? log_prefix : "stapi", "%s %s", msg, hex);
}

void cs_log(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    tcmg_log_force_txt("stapi", "%s", buf);
}

int32_t ATR_InitFromArray(OSC_ATR *atr, const unsigned char buffer[33], uint32_t length)
{
    static const uint32_t num_ib[16] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};
    unsigned char b[33];
    unsigned char td;
    unsigned p = 0;
    unsigned ptr = 1;
    if (!atr || !buffer || length < 2 || length > sizeof(b)) return 2;
    memset(atr, 0, sizeof(*atr));
    if (buffer[0] == 0x03) {
        for (uint32_t i = 0; i < length; i++) {
            unsigned char v = buffer[i];
            b[i] = (unsigned char)~((((v << 7) & 0x80) | ((v << 5) & 0x40) |
                                    ((v << 3) & 0x20) | ((v << 1) & 0x10) |
                                    ((v >> 1) & 0x08) | ((v >> 3) & 0x04) |
                                    ((v >> 5) & 0x02) | ((v >> 7) & 0x01)));
        }
    } else {
        memcpy(b, buffer, length);
    }
    atr->TS = b[0];
    td = atr->T0 = b[1];
    atr->hbn = td & 0x0f;
    atr->TCK.present = 0;
    while (ptr < length) {
        if (p >= 7 || ptr + num_ib[(td >> 4) & 0x0f] >= length) return 2;
        if (td & 0x10) { atr->ib[p][0].value = b[++ptr]; atr->ib[p][0].present = 1; }
        if (td & 0x20) { atr->ib[p][1].value = b[++ptr]; atr->ib[p][1].present = 1; }
        if (td & 0x40) { atr->ib[p][2].value = b[++ptr]; atr->ib[p][2].present = 1; }
        if (td & 0x80) {
            atr->ib[p][3].value = b[++ptr];
            atr->ib[p][3].present = 1;
            atr->TCK.present = (atr->ib[p][3].value & 0x0f) != 0;
            td = atr->ib[p][3].value;
            p++;
            continue;
        }
        break;
    }
    atr->pn = p + 1;
    if (ptr + atr->hbn + 1 > length) return 2;
    memcpy(atr->hb, b + ptr + 1, atr->hbn);
    ptr += atr->hbn;
    if (atr->TCK.present) {
        if (ptr + 1 >= length) return 2;
        atr->TCK.value = b[++ptr];
    }
    atr->length = ptr + 1;
    return 0;
}


#endif

typedef int32_t (*fn_st_open)(char *, uint32_t *);
typedef int32_t (*fn_st_status)(uint32_t, int32_t *);
typedef int32_t (*fn_st_reset)(uint32_t, OSC_ATR *);
typedef int32_t (*fn_st_tx)(uint32_t, unsigned char *, uint32_t);
typedef int32_t (*fn_st_rx)(uint32_t, unsigned char *, uint32_t);
typedef int32_t (*fn_st_close)(uint32_t);
typedef int32_t (*fn_st_set_protocol)(uint32_t, unsigned char *, unsigned *, uint32_t);
typedef int32_t (*fn_st_clock)(uint32_t);
typedef char *(*fn_st_revision)(void);

typedef struct {
    void *lib;
    uint32_t handle;
    fn_st_open open;
    fn_st_status status;
    fn_st_reset reset;
    fn_st_tx tx;
    fn_st_rx rx;
    fn_st_close close;
    fn_st_set_protocol set_protocol;
    fn_st_clock clock;
    fn_st_revision revision;
    int is_static;
} STAPI_CTX;

#ifdef TCMG_STAPI_STATIC
static int stapi_bind_static(STAPI_CTX *c)
{
    memset(c, 0, sizeof(*c));
    c->open = STReader_Open;
    c->status = STReader_GetStatus;
    c->reset = STReader_Reset;
    c->tx = STReader_Transmit;
    c->rx = STReader_Receive;
    c->close = STReader_Close;
    c->set_protocol = STReader_SetProtocol;
    c->clock = STReader_SetClockrate;
#ifdef TCMG_STAPI_STATIC5
    c->revision = STReader_GetRevision;
#endif
    c->is_static = 1;
    return 0;
}
#endif

typedef struct {
    unsigned char atr[33];
    int atr_len;
} AMSMC_ATR;
#define AMSMC_IOC_MAGIC 'C'
#define AMSMC_IOC_RESET _IOR(AMSMC_IOC_MAGIC, 0x00, AMSMC_ATR)
#define AMSMC_IOC_GET_STATUS _IOR(AMSMC_IOC_MAGIC, 0x01, int)

typedef struct {
    void *lib;
    void *handle;
    void (*kal_initialize)(void);
    void (*kal_terminate)(void);
    void (*drv_init)(void);
    void (*drv_term)(void);
    int32_t (*smc_init)(void *);
    int32_t (*smc_open)(void *, int32_t *, void *, void *);
    int32_t (*smc_enable_flow_control)(void *, int32_t);
    int32_t (*smc_get_state)(void *, int32_t *);
    int32_t (*smc_get_clock_freq)(void *, uint32_t *);
    int32_t (*smc_reset_card)(void *, int32_t, void *, void *);
    int32_t (*smc_get_atr)(void *, unsigned char *, int32_t *);
    int32_t (*smc_read_write)(void *, int8_t, uint8_t *, uint32_t, uint8_t *, uint32_t *, int32_t, void *);
    int32_t (*smc_set_clock_freq)(void *, int32_t);
    int32_t (*smc_close)(void *);
    int initialized;
} COOL_CTX;

typedef struct {
    int32_t reserved;
    unsigned char reserved2[63];
} AZBOX_BUF;
#define SCARD_IOC_MAGIC 'S'
#define SCARD_IOC_WARMRESET _IO('S', 0)
#define SCARD_IOC_CHECKCARD _IO('S', 3)

static int wait_fd(int fd, int writable, uint32_t timeout_ms)
{
    if (fd < 0) return -1;
    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    struct timeval tv;
    tv.tv_sec = (time_t)(timeout_ms / 1000u);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
    int rc;
    do {
        rc = select(fd + 1, writable ? NULL : &set, writable ? &set : NULL, NULL, &tv);
    } while (rc < 0 && errno == EINTR);
    return rc > 0 ? 0 : -1;
}

static int open_fd_device(S_INTERNAL_BACKEND *b, const char *device)
{
    int fd;
    int exclusive = 0;
    fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
#if defined(TIOCEXCL)
    if (ioctl(fd, TIOCEXCL) == 0) exclusive = 1;
#endif
    if (!exclusive && flock(fd, LOCK_EX | LOCK_NB) == 0) exclusive = 1;
    b->fd = fd;
    b->exclusive = exclusive;
    tcmg_strlcpy(b->device, device, sizeof(b->device));
    return 0;
}

static void close_fd_device(S_INTERNAL_BACKEND *b)
{
    if (b->fd < 0) return;
    if (b->exclusive) (void)flock(b->fd, LOCK_UN);
    close(b->fd);
    b->fd = -1;
    b->exclusive = 0;
}

static void *open_library(const char *explicit_path, const char *const *names)
{
    if (explicit_path && *explicit_path) {
        void *h = dlopen(explicit_path, RTLD_NOW | RTLD_LOCAL);
        if (h) return h;
    }
    if (names) {
        for (size_t i = 0; names[i]; i++) {
            void *h = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);
            if (h) return h;
        }
    }
    return NULL;
}

static void *load_symbol(void *lib, const char *name)
{
    return lib ? dlsym(lib, name) : NULL;
}

#define LOAD_FUNCTION(dst, lib, sym) do { \
    void *loaded_symbol = load_symbol((lib), (sym)); \
    memset(&(dst), 0, sizeof(dst)); \
    memcpy(&(dst), &loaded_symbol, sizeof(dst) < sizeof(loaded_symbol) ? sizeof(dst) : sizeof(loaded_symbol)); \
} while (0)

static int stapi_bind(STAPI_CTX *c, void *lib)
{
    memset(c, 0, sizeof(*c));
    c->lib = lib;
    LOAD_FUNCTION(c->open, lib, "STReader_Open");
    LOAD_FUNCTION(c->status, lib, "STReader_GetStatus");
    LOAD_FUNCTION(c->reset, lib, "STReader_Reset");
    LOAD_FUNCTION(c->tx, lib, "STReader_Transmit");
    LOAD_FUNCTION(c->rx, lib, "STReader_Receive");
    LOAD_FUNCTION(c->close, lib, "STReader_Close");
    LOAD_FUNCTION(c->set_protocol, lib, "STReader_SetProtocol");
    LOAD_FUNCTION(c->clock, lib, "STReader_SetClockrate");
    LOAD_FUNCTION(c->revision, lib, "STReader_GetRevision");
    if (!c->open || !c->status || !c->reset || !c->tx || !c->rx || !c->close) {
        dlclose(lib);
        memset(c, 0, sizeof(*c));
        return -1;
    }
    if (c->revision) (void)c->revision();
    return 0;
}

static size_t stapi_atr_raw(const OSC_ATR *a, uint8_t *out, size_t cap)
{
    size_t n = 0;
    unsigned protocols;
    if (!a || !out || cap < 2) return 0;
    protocols = a->pn;
    if (protocols == 0 || protocols > 7) return 0;
    out[n++] = a->TS;
    out[n++] = a->T0;
    for (unsigned p = 0; p < protocols; p++) {
        if (a->ib[p][0].present) { if (n >= cap) return 0; out[n++] = a->ib[p][0].value; }
        if (a->ib[p][1].present) { if (n >= cap) return 0; out[n++] = a->ib[p][1].value; }
        if (a->ib[p][2].present) { if (n >= cap) return 0; out[n++] = a->ib[p][2].value; }
        if (a->ib[p][3].present) { if (n >= cap) return 0; out[n++] = a->ib[p][3].value; }
    }
    if (a->hbn > 15 || n + a->hbn > cap) return 0;
    memcpy(out + n, a->hb, a->hbn);
    n += a->hbn;
    if (a->TCK.present) { if (n >= cap) return 0; out[n++] = a->TCK.value; }
    return n;
}

static int stapi_try_open(STAPI_CTX *c, const char *device)
{
    uint32_t h = 0;
    char name[64];
    tcmg_strlcpy(name, device, sizeof(name));
    if (c->open(name, &h) != 0) return -1;
    c->handle = h;
    return 0;
}

static int load_stapi(S_INTERNAL_BACKEND *b, const char *spec, int stapi5)
{
    static const char *const libs5[] = { "liboscam_stapi5.so", "libstapi5.so", NULL };
    static const char *const libs[] = { "liboscam_stapi.so", "libstapi.so", NULL };
    STAPI_CTX *c = (STAPI_CTX *)calloc(1, sizeof(*c));
    const char *env = getenv("TCMG_STAPI_LIB");
    void *lib = NULL;
    const char *device = spec;
    if (!c) return -1;
#ifdef TCMG_STAPI_STATIC
    if ((stapi5 != 0) == (TCMG_STAPI_STATIC5 != 0)) {
        if (stapi_bind_static(c) != 0) { free(c); return -1; }
    } else
#endif
    {
        lib = open_library(env, stapi5 ? libs5 : libs);
        if (!lib || stapi_bind(c, lib) < 0) { free(c); return -1; }
    }
    if (device && *device) {
        if (stapi_try_open(c, device) < 0) {
            if (c->lib) dlclose(c->lib);
            free(c);
            return -1;
        }
    } else {
        static const char *const candidates[] = { "SC0", "SC1", "SC2", "SC3", "sci0", "sci1", "0", "1", NULL };
        int opened = 0;
        for (size_t i = 0; candidates[i]; i++) {
            if (stapi_try_open(c, candidates[i]) == 0) { device = candidates[i]; opened = 1; break; }
        }
        if (!opened) { if (c->lib) dlclose(c->lib); free(c); return -1; }
    }
    b->ctx = c;
    b->kind = stapi5 ? TCMG_INTERNAL_BACKEND_STAPI5 : TCMG_INTERNAL_BACKEND_STAPI;
    b->fd = -1;
    tcmg_strlcpy(b->name, stapi5 ? "stapi5" : "stapi", sizeof(b->name));
    tcmg_strlcpy(b->device, device, sizeof(b->device));
    return 0;
}

static int amsmc_open(S_INTERNAL_BACKEND *b, const char *device)
{
    const char *d = device;
    if (!d || !*d) return -1;
    if (open_fd_device(b, d) < 0) return -1;
    b->kind = TCMG_INTERNAL_BACKEND_AMSMC;
    tcmg_strlcpy(b->name, "amsmc", sizeof(b->name));
    return 0;
}

static int azbox_open(S_INTERNAL_BACKEND *b, const char *device)
{
    const char *d = (device && *device) ? device : "/dev/scard";
    if (open_fd_device(b, d) < 0) return -1;
    b->kind = TCMG_INTERNAL_BACKEND_AZBOX;
    tcmg_strlcpy(b->name, "azbox", sizeof(b->name));
    return 0;
}

static int cool_bind(COOL_CTX *c, void *lib)
{
    memset(c, 0, sizeof(*c));
    c->lib = lib;
    LOAD_FUNCTION(c->kal_initialize, lib, "kal_initialize");
    LOAD_FUNCTION(c->kal_terminate, lib, "kal_terminate");
    LOAD_FUNCTION(c->drv_init, lib, "drv_init");
    LOAD_FUNCTION(c->drv_term, lib, "drv_term");
    LOAD_FUNCTION(c->smc_init, lib, "cnxt_smc_init");
    LOAD_FUNCTION(c->smc_open, lib, "cnxt_smc_open");
    LOAD_FUNCTION(c->smc_enable_flow_control, lib, "cnxt_smc_enable_flow_control");
    LOAD_FUNCTION(c->smc_get_state, lib, "cnxt_smc_get_state");
    LOAD_FUNCTION(c->smc_get_clock_freq, lib, "cnxt_smc_get_clock_freq");
    LOAD_FUNCTION(c->smc_reset_card, lib, "cnxt_smc_reset_card");
    LOAD_FUNCTION(c->smc_get_atr, lib, "cnxt_smc_get_atr");
    LOAD_FUNCTION(c->smc_read_write, lib, "cnxt_smc_read_write");
    LOAD_FUNCTION(c->smc_set_clock_freq, lib, "cnxt_smc_set_clock_freq");
    LOAD_FUNCTION(c->smc_close, lib, "cnxt_smc_close");
    return (!c->smc_open || !c->smc_get_state || !c->smc_reset_card || !c->smc_get_atr ||
            !c->smc_read_write || !c->smc_close) ? -1 : 0;
}


static pthread_mutex_t cool_api_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned cool_api_refs;
static void *cool_api_lib;
static COOL_CTX cool_api_template;

static int cool_api_acquire(COOL_CTX *c, void *lib)
{
    pthread_mutex_lock(&cool_api_lock);
    if (cool_api_refs == 0) {
        if (c->kal_initialize) c->kal_initialize();
        if (c->drv_init) c->drv_init();
        if (c->smc_init && c->smc_init(NULL) != 0) {
            if (c->drv_term) c->drv_term();
            if (c->kal_terminate) c->kal_terminate();
            pthread_mutex_unlock(&cool_api_lock);
            return -1;
        }
        cool_api_lib = lib;
        memcpy(&cool_api_template, c, sizeof(cool_api_template));
    } else if (cool_api_lib != lib) {
        pthread_mutex_unlock(&cool_api_lock);
        return -1;
    }
    cool_api_refs++;
    pthread_mutex_unlock(&cool_api_lock);
    return 0;
}

static void cool_api_release(COOL_CTX *c)
{
    (void)c;
    pthread_mutex_lock(&cool_api_lock);
    if (cool_api_refs > 0) cool_api_refs--;
    if (cool_api_refs == 0) {
        if (cool_api_template.drv_term) cool_api_template.drv_term();
        if (cool_api_template.kal_terminate) cool_api_template.kal_terminate();
        cool_api_lib = NULL;
        memset(&cool_api_template, 0, sizeof(cool_api_template));
    }
    pthread_mutex_unlock(&cool_api_lock);
}

static int cool_open(S_INTERNAL_BACKEND *b, int slot)
{
    static const char *const libs[] = { "libnxp.so", "libcoolapi.so", NULL };
    COOL_CTX *c = (COOL_CTX *)calloc(1, sizeof(*c));
    void *lib = open_library(getenv("TCMG_COOLAPI_LIB"), libs);
    int32_t reader_nb = (int32_t)slot;
    if (!c || !lib || cool_bind(c, lib) < 0) {
        if (lib) dlclose(lib);
        free(c);
        return -1;
    }
    if (cool_api_acquire(c, lib) != 0) {
        dlclose(lib);
        free(c);
        return -1;
    }
    if (c->smc_open(&c->handle, &reader_nb, NULL, NULL) != 0) {
        cool_api_release(c);
        dlclose(lib);
        free(c);
        return -1;
    }
    if (c->smc_enable_flow_control) (void)c->smc_enable_flow_control(c->handle, 0);
    c->initialized = 1;
    b->ctx = c;
    b->kind = TCMG_INTERNAL_BACKEND_COOLAPI;
    b->fd = -1;
    snprintf(b->device, sizeof(b->device), "%d", slot);
    tcmg_strlcpy(b->name, "coolapi", sizeof(b->name));
    return 0;
}

static int try_open_sci(S_INTERNAL_BACKEND *b, const char *device)
{
    uint32_t present;
    if (open_fd_device(b, device) < 0) return -1;
    if (ioctl(b->fd, SCI_GET_PRESENT, &present) < 0) {
        close_fd_device(b);
        return -1;
    }
    b->kind = TCMG_INTERNAL_BACKEND_SCI;
    tcmg_strlcpy(b->name, "sci", sizeof(b->name));
    return 0;
}

static int platform_contains(const char *text, const char *needle)
{
    if (!text || !*text || !needle || !*needle) return 0;
    while (*text) {
        const char *a = text;
        const char *n = needle;
        while (*a && *n && tolower((unsigned char)*a) == tolower((unsigned char)*n)) {
            a++;
            n++;
        }
        if (!*n) return 1;
        text++;
    }
    return 0;
}

static int platform_prefers_azbox(void)
{
    const char *p = internal_backend_platform_name();
    return platform_contains(p, "azbox");
}

static int platform_prefers_coolapi(void)
{
    const char *p = internal_backend_platform_name();
    return platform_contains(p, "coolstream");
}

static int try_stapi_then_sci(S_INTERNAL_BACKEND *b)
{
    if (load_stapi(b, NULL, 1) == 0) return 0;
    if (load_stapi(b, NULL, 0) == 0) return 0;
    return -1;
}

static int try_sci(S_INTERNAL_BACKEND *b)
{
    char path[64];
    for (unsigned i = 0; i < 8; i++) {
        snprintf(path, sizeof(path), "/dev/sci%u", i);
        if (access(path, R_OK | W_OK) == 0 && try_open_sci(b, path) == 0) return 0;
    }
    return -1;
}

static int try_amsmc(S_INTERNAL_BACKEND *b)
{
    char path[64];
    for (unsigned i = 0; i < 8; i++) {
        snprintf(path, sizeof(path), "/dev/amsmc%u", i);
        if (access(path, R_OK | W_OK) == 0 && amsmc_open(b, path) == 0) return 0;
    }
    for (unsigned i = 0; i < 4; i++) {
        snprintf(path, sizeof(path), "/dev/aml_smc%u", i);
        if (access(path, R_OK | W_OK) == 0 && amsmc_open(b, path) == 0) return 0;
    }
    return -1;
}

static int try_azbox(S_INTERNAL_BACKEND *b)
{
    if (access("/dev/scard", R_OK | W_OK) == 0 && azbox_open(b, "/dev/scard") == 0) return 0;
    return -1;
}

static int try_cool(S_INTERNAL_BACKEND *b)
{
    for (int i = 0; i < 2; i++)
        if (cool_open(b, i) == 0) return 0;
    return -1;
}

static int try_auto(S_INTERNAL_BACKEND *b)
{
    if (platform_prefers_azbox() && try_azbox(b) == 0) return 0;
    if (platform_prefers_coolapi() && try_cool(b) == 0) return 0;
    if (try_sci(b) == 0) return 0;
    if (try_amsmc(b) == 0) return 0;
    if (!platform_prefers_azbox() && try_azbox(b) == 0) return 0;
    if (!platform_prefers_coolapi() && try_cool(b) == 0) return 0;
    if (try_stapi_then_sci(b) == 0) return 0;
    return -1;
}

void internal_backend_init(S_INTERNAL_BACKEND *b)
{
    if (!b) return;
    memset(b, 0, sizeof(*b));
    b->kind = TCMG_INTERNAL_BACKEND_NONE;
    b->fd = -1;
}

int internal_backend_open(S_INTERNAL_BACKEND *b, const char *spec)
{
    const char *value;
    if (!b || !spec || !*spec) return -1;
    internal_backend_close(b);
    internal_backend_init(b);
    if (!strcasecmp(spec, "auto") || !strcasecmp(spec, "internal"))
        return try_auto(b);
    if (!strncasecmp(spec, "sci:", 4)) return try_open_sci(b, spec + 4);
    if (!strncasecmp(spec, "stapi5:", 7)) return load_stapi(b, spec + 7, 1);
    if (!strncasecmp(spec, "stapi:", 6)) return load_stapi(b, spec + 6, 0);
    if (!strncasecmp(spec, "amsmc:", 6)) return amsmc_open(b, spec + 6);
    if (!strncasecmp(spec, "azbox:", 6)) return azbox_open(b, spec + 6);
    if (!strncasecmp(spec, "cool:", 5)) {
        value = spec + 5;
        char *end = NULL;
        long slot = strtol(value, &end, 10);
        if (!value[0] || (end && *end) || slot < 0 || slot > 1) return -1;
        return cool_open(b, (int)slot);
    }
    if (!strncasecmp(spec, "stapi5", 6) && (spec[6] == '\0' || spec[6] == ':'))
        return load_stapi(b, spec + (spec[6] == ':' ? 7 : 6), 1);
    if (!strncasecmp(spec, "stapi", 5) && (spec[5] == '\0' || spec[5] == ':'))
        return load_stapi(b, spec + (spec[5] == ':' ? 6 : 5), 0);
    if (!strncasecmp(spec, "amsmc", 5) && (spec[5] == '\0' || spec[5] == ':'))
        return amsmc_open(b, spec + (spec[5] == ':' ? 6 : 5));
    if (!strncasecmp(spec, "azbox", 5) && (spec[5] == '\0' || spec[5] == ':'))
        return azbox_open(b, spec + (spec[5] == ':' ? 6 : 5));
#ifdef __linux__
    if (!strncmp(spec, "/dev/sci", 8)) return try_open_sci(b, spec);
#endif
    if (access(spec, R_OK | W_OK) == 0) return try_open_sci(b, spec);
    return -1;
}

int internal_backend_present(S_INTERNAL_BACKEND *b)
{
    if (!b || b->kind == TCMG_INTERNAL_BACKEND_NONE) return 0;
    switch (b->kind) {
    case TCMG_INTERNAL_BACKEND_SCI: {
#ifdef __linux__
        uint32_t present = 0;
        if (ioctl(b->fd, SCI_GET_PRESENT, &present) == 0) return present ? 1 : 0;
#endif
        return -1;
    }
    case TCMG_INTERNAL_BACKEND_STAPI:
    case TCMG_INTERNAL_BACKEND_STAPI5: {
        STAPI_CTX *c = (STAPI_CTX *)b->ctx;
        int32_t present = 0;
        return c && c->status && c->status(c->handle, &present) == 0 ? (present ? 1 : 0) : -1;
    }
    case TCMG_INTERNAL_BACKEND_AMSMC: {
        int status = 0;
        return ioctl(b->fd, AMSMC_IOC_GET_STATUS, &status) == 0 ? (status ? 1 : 0) : -1;
    }
    case TCMG_INTERNAL_BACKEND_AZBOX: {
        unsigned char buf[64];
        int rc;
        memset(buf, 0, sizeof(buf));
        rc = ioctl(b->fd, SCARD_IOC_CHECKCARD, &buf);
        return (rc == 0x03 || rc == 0x01) ? 1 : 0;
    }
    case TCMG_INTERNAL_BACKEND_COOLAPI: {
        COOL_CTX *c = (COOL_CTX *)b->ctx;
        int32_t state = 0;
        if (!c || !c->smc_get_state || c->smc_get_state(c->handle, &state) != 0) return -1;
        return state ? 1 : 0;
    }
    default:
        return 0;
    }
}

int internal_backend_reset(S_INTERNAL_BACKEND *b, uint8_t *atr, size_t *atr_len)
{
    if (!b || !atr || !atr_len || b->kind == TCMG_INTERNAL_BACKEND_NONE) return -1;
    *atr_len = 0;
    switch (b->kind) {
    case TCMG_INTERNAL_BACKEND_SCI: {
#ifdef __linux__
        uint32_t reset = 1;
        uint32_t ready = 1;
        if (ioctl(b->fd, SCI_SET_RESET, &reset) < 0) return -1;
        for (size_t i = 0; i < 64; i++) {
            if (wait_fd(b->fd, 0, 1000) < 0) return -1;
            ssize_t n = read(b->fd, atr + *atr_len, 1);
            if (n == 1) {
                (*atr_len)++;
                if (*atr_len >= 2 && (atr[1] & 0x0Fu) <= 15u && !(atr[1] & 0x80u)) break;
            } else if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
                continue;
            } else return -1;
        }
        if (ioctl(b->fd, SCI_SET_ATR_READY, &ready) < 0) return -1;
        return *atr_len >= 2 ? 0 : -1;
#else
        return -1;
#endif
    }
    case TCMG_INTERNAL_BACKEND_STAPI:
    case TCMG_INTERNAL_BACKEND_STAPI5: {
        STAPI_CTX *c = (STAPI_CTX *)b->ctx;
        OSC_ATR a;
        size_t n;
        memset(&a, 0, sizeof(a));
        if (!c || !c->reset || c->reset(c->handle, &a) != 0) return -1;
        n = stapi_atr_raw(&a, atr, 64);
        if (!n) return -1;
        *atr_len = n;
        return 0;
    }
    case TCMG_INTERNAL_BACKEND_AMSMC: {
        AMSMC_ATR a;
        memset(&a, 0, sizeof(a));
        if (ioctl(b->fd, AMSMC_IOC_RESET, &a) < 0 || a.atr_len < 2 || a.atr_len > (int)sizeof(a.atr)) return -1;
        memcpy(atr, a.atr, (size_t)a.atr_len);
        *atr_len = (size_t)a.atr_len;
        return 0;
    }
    case TCMG_INTERNAL_BACKEND_AZBOX: {
        unsigned char buf[128];
        int n;
        int rc;
        memset(buf, 0, sizeof(buf));
        rc = ioctl(b->fd, SCARD_IOC_WARMRESET, &buf);
        (void)rc;
        for (unsigned i = 0; i < 40; i++) {
            unsigned char status[64];
            memset(status, 0, sizeof(status));
            if (ioctl(b->fd, SCARD_IOC_CHECKCARD, &status) == 0x03) break;
            tcmg_sleep_ms(50);
        }
        memset(buf, 0, sizeof(buf));
        buf[0] = 0x01;
        n = ioctl(b->fd, SCARD_IOC_CHECKCARD, &buf);
        if (n <= 0 || n > (int)sizeof(buf)) return -1;
        memcpy(atr, buf, (size_t)n);
        *atr_len = (size_t)n;
        return 0;
    }
    case TCMG_INTERNAL_BACKEND_COOLAPI: {
        COOL_CTX *c = (COOL_CTX *)b->ctx;
        int32_t n = 33;
        if (!c || c->smc_reset_card(c->handle, 1000000, NULL, NULL) != 0) return -1;
        tcmg_sleep_ms(50);
        if (c->smc_get_atr(c->handle, atr, &n) != 0 || n < 2 || n > 64) return -1;
        *atr_len = (size_t)n;
        return 0;
    }
    default:
        return -1;
    }
}

int internal_backend_set_clock(S_INTERNAL_BACKEND *b, uint32_t clock_khz)
{
    if (!b) return -1;
    if (b->kind == TCMG_INTERNAL_BACKEND_COOLAPI) {
        COOL_CTX *c = (COOL_CTX *)b->ctx;
        return c && c->smc_set_clock_freq ? c->smc_set_clock_freq(c->handle, (int32_t)clock_khz * 10) : -1;
    }
    if (b->kind == TCMG_INTERNAL_BACKEND_STAPI || b->kind == TCMG_INTERNAL_BACKEND_STAPI5) {
        STAPI_CTX *c = (STAPI_CTX *)b->ctx;
        (void)clock_khz;
        return c && c->clock ? c->clock(c->handle) : 0;
    }
    return 0;
}

ssize_t internal_backend_read(S_INTERNAL_BACKEND *b, uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    if (!b || !buf || !len) return -1;
    if (b->kind == TCMG_INTERNAL_BACKEND_STAPI || b->kind == TCMG_INTERNAL_BACKEND_STAPI5) {
        STAPI_CTX *c = (STAPI_CTX *)b->ctx;
        if (!c || !c->rx || c->rx(c->handle, buf, (uint32_t)len) != 0) return -1;
        return (ssize_t)len;
    }
    if (b->kind == TCMG_INTERNAL_BACKEND_COOLAPI) return -1;
    if (wait_fd(b->fd, 0, timeout_ms) < 0) return -1;
    for (;;) {
        ssize_t n = read(b->fd, buf, len);
        if (n >= 0) return n;
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
        return -1;
    }
}

ssize_t internal_backend_write(S_INTERNAL_BACKEND *b, const uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    if (!b || !buf || !len) return -1;
    if (b->kind == TCMG_INTERNAL_BACKEND_STAPI || b->kind == TCMG_INTERNAL_BACKEND_STAPI5) {
        STAPI_CTX *c = (STAPI_CTX *)b->ctx;
        (void)timeout_ms;
        return c && c->tx && c->tx(c->handle, (unsigned char *)(uintptr_t)buf, (uint32_t)len) == 0 ? (ssize_t)len : -1;
    }
    if (b->kind == TCMG_INTERNAL_BACKEND_COOLAPI) return -1;
    if (wait_fd(b->fd, 1, timeout_ms) < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(b->fd, buf + off, len - off);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        return -1;
    }
    return (ssize_t)off;
}

int internal_backend_flush(S_INTERNAL_BACKEND *b)
{
    if (!b) return -1;
    if (b->kind == TCMG_INTERNAL_BACKEND_COOLAPI || b->kind == TCMG_INTERNAL_BACKEND_STAPI || b->kind == TCMG_INTERNAL_BACKEND_STAPI5)
        return 0;
    if (tcflush(b->fd, TCIFLUSH) == 0) return 0;
    if (errno == ENOTTY || errno == EINVAL || errno == ENOSYS) return 0;
    return -1;
}

int internal_backend_transceive(S_INTERNAL_BACKEND *b, const uint8_t *tx, size_t tx_len,
                                uint8_t *rx, size_t *rx_len, uint32_t timeout_ms)
{
    if (!b || !tx || !rx || !rx_len) return -1;
    if (b->kind != TCMG_INTERNAL_BACKEND_COOLAPI) return -1;
    COOL_CTX *c = (COOL_CTX *)b->ctx;
    if (!c || !c->smc_read_write) return -1;
    uint32_t got = (uint32_t)((*rx_len > 512u) ? 512u : *rx_len);
    int32_t rc = c->smc_read_write(c->handle, 0, (uint8_t *)(uintptr_t)tx, (uint32_t)tx_len,
                                   rx, &got, (int32_t)timeout_ms, NULL);
    if (rc != 0) return -1;
    *rx_len = got;
    return 0;
}

int internal_backend_is_open(const S_INTERNAL_BACKEND *b)
{
    return b && b->kind != TCMG_INTERNAL_BACKEND_NONE && ((b->kind == TCMG_INTERNAL_BACKEND_SCI || b->kind == TCMG_INTERNAL_BACKEND_AMSMC || b->kind == TCMG_INTERNAL_BACKEND_AZBOX) ? b->fd >= 0 : b->ctx != NULL);
}

int internal_backend_is_fd(const S_INTERNAL_BACKEND *b)
{
    return b && (b->kind == TCMG_INTERNAL_BACKEND_SCI || b->kind == TCMG_INTERNAL_BACKEND_AMSMC || b->kind == TCMG_INTERNAL_BACKEND_AZBOX);
}

int internal_backend_get_fd(const S_INTERNAL_BACKEND *b)
{
    return b ? b->fd : -1;
}

const char *internal_backend_name(const S_INTERNAL_BACKEND *b)
{
    return (b && b->name[0]) ? b->name : "none";
}

const char *internal_backend_device(const S_INTERNAL_BACKEND *b)
{
    return (b && b->device[0]) ? b->device : "";
}

void internal_backend_close(S_INTERNAL_BACKEND *b)
{
    if (!b) return;
    if (b->kind == TCMG_INTERNAL_BACKEND_STAPI || b->kind == TCMG_INTERNAL_BACKEND_STAPI5) {
        STAPI_CTX *c = (STAPI_CTX *)b->ctx;
        if (c) {
            if (c->close) (void)c->close(c->handle);
            if (c->lib) dlclose(c->lib);
            free(c);
        }
    } else if (b->kind == TCMG_INTERNAL_BACKEND_COOLAPI) {
        COOL_CTX *c = (COOL_CTX *)b->ctx;
        if (c) {
            if (c->smc_close && c->handle) (void)c->smc_close(c->handle);
            cool_api_release(c);
            if (c->lib) dlclose(c->lib);
            free(c);
        }
    } else if (b->fd >= 0) {
        close_fd_device(b);
    }
    internal_backend_init(b);
}

const char *internal_backend_platform_name(void)
{
    static char value[256];
    static int initialized;
    if (initialized) return value[0] ? value : "generic";
    initialized = 1;
    value[0] = 0;
#ifdef __linux__
    char boxtype[128] = "";
    char model[128] = "";
    char vumodel[128] = "";
    int azmodel = 0;
    const char *paths[] = { "/proc/stb/info/boxtype", "/proc/stb/info/model", "/proc/stb/info/vumodel", NULL };
    char *outs[] = { boxtype, model, vumodel };
    for (size_t i = 0; paths[i]; i++) {
        FILE *f = fopen(paths[i], "r");
        if (f) {
            if (fgets(outs[i], 128, f)) {
                size_t n = strlen(outs[i]);
                while (n && isspace((unsigned char)outs[i][n - 1])) outs[i][--n] = 0;
            }
            fclose(f);
        }
    }
    {
        FILE *f = fopen("/proc/stb/info/azmodel", "r");
        if (f) { azmodel = 1; fclose(f); }
    }
    if (!boxtype[0] && vumodel[0] && !azmodel) {
        snprintf(value, sizeof(value), "vu%s", vumodel);
        return value;
    }
    if (boxtype[0]) { tcmg_strlcpy(value, boxtype, sizeof(value)); return value; }
    if (azmodel && model[0]) { snprintf(value, sizeof(value), "Azbox-%s", model); return value; }
    if (model[0]) { tcmg_strlcpy(value, model, sizeof(value)); return value; }
#endif
    struct utsname u;
    if (uname(&u) == 0 && u.machine[0]) tcmg_strlcpy(value, u.machine, sizeof(value));
    return value[0] ? value : "generic";
}

#else

void internal_backend_init(S_INTERNAL_BACKEND *b) { if (b) memset(b, 0, sizeof(*b)); }
int internal_backend_open(S_INTERNAL_BACKEND *b, const char *spec) { (void)b; (void)spec; return -1; }
int internal_backend_present(S_INTERNAL_BACKEND *b) { (void)b; return 0; }
int internal_backend_reset(S_INTERNAL_BACKEND *b, uint8_t *a, size_t *n) { (void)b; (void)a; (void)n; return -1; }
int internal_backend_set_clock(S_INTERNAL_BACKEND *b, uint32_t k) { (void)b; (void)k; return -1; }
ssize_t internal_backend_read(S_INTERNAL_BACKEND *b, uint8_t *x, size_t n, uint32_t t) { (void)b; (void)x; (void)n; (void)t; return -1; }
ssize_t internal_backend_write(S_INTERNAL_BACKEND *b, const uint8_t *x, size_t n, uint32_t t) { (void)b; (void)x; (void)n; (void)t; return -1; }
int internal_backend_flush(S_INTERNAL_BACKEND *b) { (void)b; return -1; }
int internal_backend_transceive(S_INTERNAL_BACKEND *b, const uint8_t *x, size_t n, uint8_t *r, size_t *m, uint32_t t) { (void)b; (void)x; (void)n; (void)r; (void)m; (void)t; return -1; }
int internal_backend_is_open(const S_INTERNAL_BACKEND *b) { (void)b; return 0; }
int internal_backend_is_fd(const S_INTERNAL_BACKEND *b) { (void)b; return 0; }
int internal_backend_get_fd(const S_INTERNAL_BACKEND *b) { (void)b; return -1; }
const char *internal_backend_name(const S_INTERNAL_BACKEND *b) { (void)b; return "none"; }
const char *internal_backend_device(const S_INTERNAL_BACKEND *b) { (void)b; return ""; }
void internal_backend_close(S_INTERNAL_BACKEND *b) { (void)b; }
const char *internal_backend_platform_name(void) { return "generic"; }

#endif
