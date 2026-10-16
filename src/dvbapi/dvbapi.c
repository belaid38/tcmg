#define MODULE_LOG_PREFIX "dvbapi"
#include "dvbapi.h"
#include "dvbapi_priv.h"
#include "dvbapi_capmt.h"
#include "config/runtime_access.h"
#include "core/utils.h"
#include "core/runtime_state.h"
#include "platform/platform.h"
#include "log/log.h"
#include "account/account.h"
#include "session/session.h"
#include "client/client.h"
#include "ecm/ecm.h"
#include "crypto/crypto.h"
#include "reader/rules.h"

#if defined(__linux__) && !defined(TCMG_OS_WINDOWS)

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdatomic.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* OSCam uses MAX_DEMUX=32 for associated DVBAPI sockets; allow the same
 * number of Enigma clients instead of rejecting everything after four. */
#define DVB_MAX_CONN     32
#define DVB_MAX_SVC      32
#define DVB_IDX_MAX      32
#define DVB_CA_MAX       32
#define DVB_RBUF         8448
#define DVB_NET_PROTO_VERSION 3u
#define DVB_NET_FILTER_DATA   0xFFFF0000u
#define DVB_NET_CLIENT_INFO   0xFFFF0001u
#define DVB_NET_SERVER_INFO   0xFFFF0002u
#define DVB_NET_CA_SET_DESCR  0x40106F86u
#define DVB_NET_CA_SET_PID    0x40086F87u
#define DVB_NET_DMX_STOP      0x00006F2Au
#define DVB_NET_DMX_SET_FILTER 0x403C6F2Bu
#define DVB_NET_DMX_IMMEDIATE_START 4u
#define DVB_NET_CA_DISABLE_PID 0xFFFFFFFFu
#define DVB_ECM_MAX      1024 /* OSCam MAX_ECM_SIZE */
#define DVB_FAIL_UNLOCK  3
#define DVB_CONFIRM      2      /* identical copies needed before a suspicious ECM is sent */
#define DVB_MAX_RETRY    3      /* re-sends of one ECM that the card refused */
#define DVB_RETRY_MS     1500

/* per ECM pid: OSCam style "one ECM per crypto period" gate */
#define GATE_IDLE     0
#define GATE_PENDING  1         /* handed to the card, waiting for the answer */
#define GATE_DONE     2         /* CW found, wait for the opposite table */
#define GATE_FAILED   3         /* card refused it: same table needs confirmation */
#define FLT_REQ(tid, mask) (0x10000 | ((int)(tid) << 8) | (int)(mask))

#define SVC_FREE      0
#define SVC_ACTIVE    1
#define SVC_STOPPING  2

#define REQ_NONE    (-2)
#define REQ_UNLOCK  (-1)

struct dvb_ca_pid { unsigned int pid; int index; };
struct dvb_ca_descr { unsigned int index; unsigned int parity; unsigned char cw[8]; };
struct dvb_ca_descr_info { unsigned int num; unsigned int type; };
struct dvb_dmx_filter { uint8_t filter[16]; uint8_t mask[16]; uint8_t mode[16]; };
struct dvb_dmx_sct_filter_params {
    uint16_t pid;
    struct dvb_dmx_filter filter;
    uint32_t timeout;
    uint32_t flags;
};

#define DVB_CA_GET_DESCR_INFO  _IOR('o', 131, struct dvb_ca_descr_info)
#define DVB_CA_SET_DESCR       _IOW('o', 134, struct dvb_ca_descr)
#define DVB_CA_SET_PID         _IOW('o', 135, struct dvb_ca_pid)
#define DVB_DMX_STOP           _IO('o', 42)
#define DVB_DMX_SET_FILTER     _IOW('o', 43, struct dvb_dmx_sct_filter_params)
#define DVB_DMX_SET_BUFFER     _IO('o', 45)
#define DVB_DMX_IMMEDIATE_START 4u

typedef struct {
    int    fd;
    size_t rlen;
    uint8_t rbuf[DVB_RBUF];
    bool   network;
    uint16_t proto_version;
    uint32_t tx_msgid;
    char   peer_name[64];
    char   peer_ip[INET_ADDRSTRLEN];
    pthread_mutex_t tx_mtx; /* serializes network packets from service workers */
} dvb_conn_t;

typedef struct {
    int adapter;
    int ca;
    int fd;
    int refs;
} dvb_ca_t;

typedef struct {
    uint8_t  table;             /* 0x80 / 0x81 of the ECM being served, 0 = none yet */
    uint8_t  state;
    int      good_len;          /* length of the last ECM that produced a CW */
    int      sent_len;
    uint8_t  sent[DVB_ECM_MAX];
    int64_t  sent_ms;
    int      tries;
    int      cand_len;
    int      cand_cnt;
    uint8_t  cand[DVB_ECM_MAX];
    int      flt_req;           /* pending hardware filter change for the manager thread */
} dvb_gate_t;

typedef struct dvb_svc {
    atomic_int state;
    atomic_int worker_done;
    atomic_int lock_ecm;
    atomic_int lock_req;
    int        conn;
    char       client_ip[INET_ADDRSTRLEN];
    uint32_t   net_msgid;
    bool       stale;
    int        idx;
    int        fail_count;
    bool       first_done;
    S_DVBAPI_CAPMT pmt;
    int        flt_fd[DVBAPI_MAX_ECM];
    dvb_gate_t gate[DVBAPI_MAX_ECM];            /* guarded by jmtx */

    pthread_mutex_t mtx;
    uint32_t   ca_held;
    bool       pids_set;
    bool       pids_active;
    int        pids_entry;
    uint8_t    last_cw[2][8];
    bool       cw_valid[2];

    pthread_mutex_t jmtx;
    pthread_cond_t  jcv;
    bool       has_job;
    bool       job_busy; /* one ECM request is in flight for this service */
    int        job_entry;
    int        job_len;
    uint32_t   job_msgid;
    uint8_t    job_ecm[DVB_ECM_MAX];

    S_CLIENT   cl;
} dvb_svc_t;

static struct {
    atomic_int running;
    bool       started;
    bool       cfg_enabled;
    bool       inited;
    pthread_t  thread;
    int        listen_fd;
    int        net_listen_fd;
    bool       local_client_mode;
    bool       owns_socket_path;
    int64_t    next_local_connect_ms;
    int        listen_port;
    char       serverip[MAXIPLEN];
    char       path[CFGPATH_LEN];
    char       user[CFGKEY_LEN];
    int        ca_offset;
    int        delay_ms;
    int        max_services;
    int        skip_account;
    S_DVBAPI_BACKEND backend;
    T_DVBAPI_ECM_FN  ecm_fn;
    dvb_conn_t conn[DVB_MAX_CONN];
    dvb_svc_t  svc[DVB_MAX_SVC];
    pthread_mutex_t ca_mtx;
    dvb_ca_t   ca[DVB_MAX_SVC];
} G;

static S_DVBAPI_BACKEND s_hook_backend;
static T_DVBAPI_ECM_FN  s_hook_ecm;
static int              s_hook_skip;
static int              s_hook_set;

/* ------------------------------------------------------------------ */
/* real DVB device backend                                             */
/* ------------------------------------------------------------------ */

static int real_demux_open(int adapter, int demux)
{
    char path[64];
    snprintf(path, sizeof(path), "/dev/dvb/adapter%d/demux%d", adapter, demux);
    return open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
}

static int real_demux_filter(int fd, uint16_t pid, uint8_t tid, uint8_t mask)
{
    struct dvb_dmx_sct_filter_params p;
    memset(&p, 0, sizeof(p));
    p.pid = pid;
    p.filter.filter[0] = tid;
    p.filter.mask[0] = mask;
    p.flags = DVB_DMX_IMMEDIATE_START;
    (void)ioctl(fd, DVB_DMX_SET_BUFFER, 16384UL);
    return ioctl(fd, DVB_DMX_SET_FILTER, &p);
}

static int real_demux_read(int fd, uint8_t *buf, size_t len)
{
    ssize_t n = read(fd, buf, len);
    return n < 0 ? -1 : (int)n;
}

static void real_demux_close(int fd)
{
    (void)ioctl(fd, DVB_DMX_STOP);
    close(fd);
}

static int real_ca_open(int adapter, int ca)
{
    char path[64];
    snprintf(path, sizeof(path), "/dev/dvb/adapter%d/ca%d", adapter, ca + G.ca_offset);
    return open(path, O_RDWR | O_CLOEXEC);
}

static int real_ca_set_pid(int fd, uint16_t pid, int idx)
{
    struct dvb_ca_pid p;
    p.pid = pid;
    p.index = idx;
    return ioctl(fd, DVB_CA_SET_PID, &p);
}

static int real_ca_set_descr(int fd, int idx, int parity, const uint8_t cw[8])
{
    struct dvb_ca_descr d;
    memset(&d, 0, sizeof(d));
    d.index = (unsigned int)idx;
    d.parity = (unsigned int)parity;
    memcpy(d.cw, cw, 8);
    return ioctl(fd, DVB_CA_SET_DESCR, &d);
}

static void real_ca_close(int fd)
{
    close(fd);
}

/* OSCam queries CA_GET_DESCR_INFO at startup. Keep the same safe fallback
 * (16 local descramblers) when a driver does not implement the ioctl. */
static int real_ca_descr_count(int adapter, int ca)
{
    struct dvb_ca_descr_info info;
    int fd = real_ca_open(adapter, ca);
    int count = -1;
    if (fd < 0) return -1;
    memset(&info, 0, sizeof(info));
    if (ioctl(fd, DVB_CA_GET_DESCR_INFO, &info) == 0 && info.num > 0 && (info.type & 1u)) {
        count = info.num > (unsigned int)DVB_IDX_MAX ? DVB_IDX_MAX : (int)info.num;
    }
    close(fd);
    return count;
}

static const S_DVBAPI_BACKEND k_real_backend = {
    real_demux_open, real_demux_filter, real_demux_read, real_demux_close,
    real_ca_open, real_ca_set_pid, real_ca_set_descr, real_ca_close,
    real_ca_descr_count
};

/* ------------------------------------------------------------------ */
/* OSCam DVBAPI TCP network protocol                                   */
/* ------------------------------------------------------------------ */

static uint16_t net_get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t net_get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void net_put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}

static void net_put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static bool conn_is_network(int c)
{
    return c >= 0 && c < DVB_MAX_CONN && G.conn[c].fd >= 0 && G.conn[c].network &&
           G.conn[c].proto_version > 0;
}

static int net_send_raw(int c, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    int fd, rc = 0;
    if (c < 0 || c >= DVB_MAX_CONN || !buf || len == 0) return -1;
    pthread_mutex_lock(&G.conn[c].tx_mtx);
    fd = G.conn[c].fd;
    if (fd < 0) {
        pthread_mutex_unlock(&G.conn[c].tx_mtx);
        return -1;
    }
    while (off < len) {
#ifdef MSG_NOSIGNAL
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
#else
        ssize_t n = send(fd, buf + off, len - off, 0);
#endif
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
            int pr = poll(&pfd, 1, 250);
            if (pr > 0 && (pfd.revents & POLLOUT)) continue;
        }
        rc = -1;
        break;
    }
    pthread_mutex_unlock(&G.conn[c].tx_mtx);
    return rc;
}

static int net_send_command(int c, uint32_t msgid, uint32_t opcode, uint8_t adapter,
                            bool include_adapter, const uint8_t *payload, size_t payload_len)
{
    uint8_t packet[128];
    size_t off = 0;
    uint16_t version;
    if (!conn_is_network(c) || payload_len > sizeof(packet) - 16 || (payload_len && !payload)) return -1;
    version = G.conn[c].proto_version;
    if (version >= 3) {
        packet[off++] = 0xA5;
        net_put_u32(packet + off, msgid); off += 4;
    }
    net_put_u32(packet + off, opcode); off += 4;
    if (include_adapter && version >= 1) packet[off++] = adapter;
    if (payload_len) { memcpy(packet + off, payload, payload_len); off += payload_len; }
    return net_send_raw(c, packet, off);
}

static int net_send_server_info(int c)
{
    static const char info[] = "TCMG DVBAPI network; protocol-compatible";
    uint8_t payload[3 + sizeof(info) - 1];
    net_put_u16(payload, (uint16_t)DVB_NET_PROTO_VERSION);
    payload[2] = (uint8_t)(sizeof(info) - 1);
    memcpy(payload + 3, info, sizeof(info) - 1);
    /* OSCam replies to the initial CLIENT_INFO using message id zero. */
    return net_send_command(c, 0, DVB_NET_SERVER_INFO, 0, false, payload, sizeof(payload));
}

static int net_send_filter(dvb_svc_t *s, int e, uint8_t tid, uint8_t mask)
{
    uint8_t payload[1 + 1 + 2 + 16 + 16 + 16 + 4 + 4];
    size_t off = 0;
    uint32_t token;
    if (!s || e < 0 || e >= s->pmt.n_ecm || !conn_is_network(s->conn)) return -1;
    payload[off++] = (uint8_t)s->idx; /* OSCam's logical demux id */
    payload[off++] = (uint8_t)e;      /* filter number */
    net_put_u16(payload + off, s->pmt.ecm[e].pid); off += 2;
    memset(payload + off, 0, 16); payload[off] = tid; off += 16;
    memset(payload + off, 0, 16); payload[off] = mask; off += 16;
    memset(payload + off, 0, 16); off += 16; /* filter.mode */
    net_put_u32(payload + off, 0); off += 4; /* timeout */
    net_put_u32(payload + off, DVB_NET_DMX_IMMEDIATE_START); off += 4;
    if (net_send_command(s->conn, 0, DVB_NET_DMX_SET_FILTER,
                         (uint8_t)s->pmt.adapter, true, payload, off) < 0) return -1;
    token = 10000u + (uint32_t)s->idx * DVBAPI_MAX_ECM + (uint32_t)e;
    return (int)token;
}

static int net_send_filter_stop(dvb_svc_t *s, int e)
{
    uint8_t payload[1 + 1 + 2];
    if (!s || e < 0 || e >= s->pmt.n_ecm || !conn_is_network(s->conn)) return -1;
    payload[0] = (uint8_t)s->idx;
    payload[1] = (uint8_t)e;
    net_put_u16(payload + 2, s->pmt.ecm[e].pid);
    return net_send_command(s->conn, 0, DVB_NET_DMX_STOP,
                            (uint8_t)s->pmt.adapter, true, payload, sizeof(payload));
}

static int net_send_ca_pid(dvb_svc_t *s, uint16_t pid, uint32_t index, uint32_t msgid)
{
    uint8_t payload[8];
    if (!s || !conn_is_network(s->conn)) return -1;
    net_put_u32(payload, pid);
    net_put_u32(payload + 4, index);
    return net_send_command(s->conn, msgid, DVB_NET_CA_SET_PID,
                            (uint8_t)s->pmt.adapter, true, payload, sizeof(payload));
}

static int net_send_ca_descr(dvb_svc_t *s, int index, int parity, const uint8_t cw[8], uint32_t msgid)
{
    uint8_t payload[16];
    if (!s || !cw || !conn_is_network(s->conn)) return -1;
    net_put_u32(payload, (uint32_t)index);
    net_put_u32(payload + 4, (uint32_t)parity);
    memcpy(payload + 8, cw, 8);
    return net_send_command(s->conn, msgid, DVB_NET_CA_SET_DESCR,
                            (uint8_t)s->pmt.adapter, true, payload, sizeof(payload));
}

/* ------------------------------------------------------------------ */
/* CA device cache                                                     */
/* ------------------------------------------------------------------ */

static int ca_hold(dvb_svc_t *s, int bit)
{
    int fd = -1;
    dvb_ca_t *e = NULL, *freeslot = NULL;
    pthread_mutex_lock(&G.ca_mtx);
    for (int i = 0; i < DVB_MAX_SVC; i++) {
        if (G.ca[i].refs > 0 && G.ca[i].adapter == s->pmt.adapter && G.ca[i].ca == bit) { e = &G.ca[i]; break; }
        if (G.ca[i].refs == 0 && !freeslot) freeslot = &G.ca[i];
    }
    if (!e && freeslot) {
        int nfd = G.backend.ca_open(s->pmt.adapter, bit);
        if (nfd >= 0) {
            freeslot->adapter = s->pmt.adapter;
            freeslot->ca = bit;
            freeslot->fd = nfd;
            freeslot->refs = 0;
            e = freeslot;
        } else {
            tcmg_log("ca%d open failed on adapter %d errno=%d (%s)",
                     bit + G.ca_offset, s->pmt.adapter, errno, strerror(errno));
        }
    }
    if (e) {
        if (!(s->ca_held & (1u << bit))) {
            e->refs++;
            s->ca_held |= 1u << bit;
        }
        fd = e->fd;
    }
    pthread_mutex_unlock(&G.ca_mtx);
    return fd;
}

static void ca_drop_all(dvb_svc_t *s)
{
    pthread_mutex_lock(&G.ca_mtx);
    for (int bit = 0; bit < DVB_CA_MAX; bit++) {
        if (!(s->ca_held & (1u << bit))) continue;
        for (int i = 0; i < DVB_MAX_SVC; i++) {
            if (G.ca[i].refs > 0 && G.ca[i].adapter == s->pmt.adapter && G.ca[i].ca == bit) {
                if (--G.ca[i].refs == 0) {
                    G.backend.ca_close(G.ca[i].fd);
                    G.ca[i].fd = -1;
                }
                break;
            }
        }
    }
    s->ca_held = 0;
    pthread_mutex_unlock(&G.ca_mtx);
}

static bool stream_selected(const S_DVBAPI_ECMPID *e, int stream)
{
    return e->stream_mask == 0 || (e->stream_mask & (1u << (unsigned)stream)) != 0;
}

/* caller holds s->mtx */
static void svc_set_pids(dvb_svc_t *s, int entry, int idx, uint32_t msgid)
{
    int expected = 0, succeeded = 0;
    if (conn_is_network(s->conn)) {
        for (int i = 0; i < s->pmt.n_streams; i++) {
            if (!stream_selected(&s->pmt.ecm[entry], i)) continue;
            expected++;
            if (net_send_ca_pid(s, s->pmt.stream_pid[i], (uint32_t)idx, msgid) == 0) succeeded++;
        }
        s->pids_set = expected > 0 && succeeded == expected;
        s->pids_active = succeeded > 0;
        s->pids_entry = s->pids_active ? entry : -1;
        return;
    }
    for (int bit = 0; bit < DVB_CA_MAX; bit++) {
        if (!(s->pmt.ca_mask & (1u << bit))) continue;
        int fd = ca_hold(s, bit);
        if (fd < 0) continue;
        for (int i = 0; i < s->pmt.n_streams; i++) {
            if (!stream_selected(&s->pmt.ecm[entry], i)) continue;
            expected++;
            if (G.backend.ca_set_pid(fd, s->pmt.stream_pid[i], idx) < 0)
                tcmg_log_dbg(D_DVBAPI, "CA_SET_PID pid=%04X idx=%d failed errno=%d (%s)",
                             s->pmt.stream_pid[i], idx, errno, strerror(errno));
            else {
                succeeded++;
                tcmg_log_dbg(D_DVBAPI, "ca%d pid=%04X -> descrambler %d", bit + G.ca_offset,
                             s->pmt.stream_pid[i], idx);
            }
        }
    }
    s->pids_set = expected > 0 && succeeded == expected;
    s->pids_active = succeeded > 0;
    s->pids_entry = s->pids_active ? entry : -1;
}

/* caller holds s->mtx */
static void svc_clear_pids(dvb_svc_t *s, uint32_t msgid)
{
    if (conn_is_network(s->conn)) {
        if (s->pids_active) {
            for (int i = 0; i < s->pmt.n_streams; i++)
                (void)net_send_ca_pid(s, s->pmt.stream_pid[i], DVB_NET_CA_DISABLE_PID, msgid);
        }
        s->pids_set = false;
        s->pids_active = false;
        s->pids_entry = -1;
        return;
    }
    if (!s->pids_active) {
        s->pids_set = false;
        s->pids_entry = -1;
        return;
    }
    for (int bit = 0; bit < DVB_CA_MAX; bit++) {
        if (!(s->ca_held & (1u << bit))) continue;
        int fd = ca_hold(s, bit);
        if (fd < 0) continue;
        for (int i = 0; i < s->pmt.n_streams; i++)
            (void)G.backend.ca_set_pid(fd, s->pmt.stream_pid[i], -1);
    }
    s->pids_set = false;
    s->pids_active = false;
    s->pids_entry = -1;
}

static void svc_write_cw(dvb_svc_t *s, int entry, const uint8_t cw[CW_LEN], uint32_t msgid)
{
    static const uint8_t zero[8] = {0};
    pthread_mutex_lock(&s->mtx);
    if (atomic_load(&s->state) != SVC_ACTIVE) {
        pthread_mutex_unlock(&s->mtx);
        return;
    }
    if (!s->pids_set || s->pids_entry != entry) {
        if (s->pids_active) svc_clear_pids(s, msgid);
        svc_set_pids(s, entry, s->idx, msgid);
    }
    for (int n = 0; n < 2; n++) {
        const uint8_t *half = cw + 8 * n;
        if (memcmp(half, zero, 8) == 0) continue;
        if (s->cw_valid[n] && memcmp(s->last_cw[n], half, 8) == 0) continue;
        int targets = 0, accepted = 0;
        if (conn_is_network(s->conn)) {
            targets = 1;
            if (net_send_ca_descr(s, s->idx, n, half, msgid) == 0) accepted = 1;
        } else for (int bit = 0; bit < DVB_CA_MAX; bit++) {
            if (!(s->pmt.ca_mask & (1u << bit))) continue;
            targets++;
            int fd = ca_hold(s, bit);
            if (fd < 0) continue;
            if (G.backend.ca_set_descr(fd, s->idx, n, half) < 0)
                tcmg_log("CA_SET_DESCR failed ca%d idx=%d parity=%d errno=%d (%s)",
                         bit + G.ca_offset, s->idx, n, errno, strerror(errno));
            else accepted++;
        }
        if (targets > 0 && accepted == targets) {
            memcpy(s->last_cw[n], half, 8);
            s->cw_valid[n] = true;
        } else {
            /* Retry on the next ECM if the CA device did not accept the CW. */
            s->cw_valid[n] = false;
        }
    }
    pthread_mutex_unlock(&s->mtx);
}

/* ------------------------------------------------------------------ */
/* per-service worker: sends ECMs through the TCMG pipeline            */
/* ------------------------------------------------------------------ */

static void svc_gate_result(dvb_svc_t *s, int e, const uint8_t *ecm, bool ok);

static void svc_process_job(dvb_svc_t *s, int entry, const uint8_t *ecm, int len, uint32_t msgid)
{
    uint8_t cw[CW_LEN];
    S_ECM_RESULT res;
    uint16_t caid = s->pmt.ecm[entry].caid;
    uint32_t provid = s->pmt.ecm[entry].provid;
    int32_t rc;

    if (provid == 0) provid = dvbapi_ecm_provid(caid, ecm, (size_t)len);
    if (!s->first_done) {
        s->first_done = true;
        if (G.delay_ms > 0) tcmg_sleep_ms(G.delay_ms);
    }
    if (!G.skip_account) {
        T_ECM_ACCESS_STATUS access = ecm_access(&s->cl, caid, s->pmt.program, provid);
        if (access != ECM_ACCESS_OK) {
            tcmg_log_dbg(D_DVBAPI, "ECM denied caid=%04X sid=%04X status=%d", caid, s->pmt.program, (int)access);
            svc_gate_result(s, entry, ecm, false);
            return;
        }
    }
    memset(cw, 0, sizeof(cw));
    memset(&res, 0, sizeof(res));
    rc = G.ecm_fn(&s->cl, caid, s->pmt.program, provid, ecm, len, cw, &res);
    {
        static const uint8_t zero[CW_LEN] = {0};
        if (rc < 0 || memcmp(cw, zero, CW_LEN) == 0) {
            s->fail_count++;
            tcmg_log_dbg(D_DVBAPI, "no CW sid=%04X caid=%04X pid=%04X rc=%d fails=%d",
                         s->pmt.program, caid, s->pmt.ecm[entry].pid, (int)rc, s->fail_count);
            if (atomic_load(&s->lock_ecm) == entry && s->fail_count >= DVB_FAIL_UNLOCK) {
                atomic_store(&s->lock_req, REQ_UNLOCK);
                s->fail_count = 0;
            }
            svc_gate_result(s, entry, ecm, false);
            secure_zero(cw, sizeof(cw));
            return;
        }
    }
    s->fail_count = 0;
    svc_gate_result(s, entry, ecm, true);
    svc_write_cw(s, entry, cw, msgid);
    secure_zero(cw, sizeof(cw));
    if (atomic_load(&s->lock_ecm) != entry) atomic_store(&s->lock_req, entry);
}

static void *svc_worker(void *arg)
{
    dvb_svc_t *s = (dvb_svc_t *)arg;
    bool real_session = false;

    if (!G.skip_account) {
        S_ACCOUNT *acc = account_acquire(G.user);
        T_SESSION_INPUT in = { -1, s->client_ip[0] ? s->client_ip : "127.0.0.1" };
        if (!acc) {
            tcmg_log("service sid=%04X: account '%s' not found -- create it in the users list", s->pmt.program, G.user);
            goto done;
        }
        atomic_fetch_add(&g_active_conns, 1);
        session_init(&s->cl, &in, "dvbapi");
        real_session = true;
        if (account_validate(acc, s->client_ip[0] ? s->client_ip : "127.0.0.1") != ACCOUNT_OK || account_session_open(&s->cl, acc) < 0) {
            tcmg_log("service sid=%04X: account '%s' rejected (disabled/expired/ip/max_connections)",
                     s->pmt.program, G.user);
            account_release(acc);
            goto done;
        }
        pthread_mutex_lock(&s->cl.state_mtx);
        tcmg_strlcpy(s->cl.identity.user, acc->user, sizeof(s->cl.identity.user));
        tcmg_strlcpy(s->cl.identity.client_name, "dvbapi", sizeof(s->cl.identity.client_name));
        s->cl.ecm.caid = s->pmt.ecm[0].caid;
        pthread_mutex_unlock(&s->cl.state_mtx);
    } else {
        client_init(&s->cl, -1, s->client_ip[0] ? s->client_ip : "127.0.0.1");
    }

    for (;;) {
        uint8_t ecm[DVB_ECM_MAX];
        int len, entry;
        uint32_t msgid;
        pthread_mutex_lock(&s->jmtx);
        while (!s->has_job && atomic_load(&s->state) == SVC_ACTIVE)
            pthread_cond_wait(&s->jcv, &s->jmtx);
        if (atomic_load(&s->state) != SVC_ACTIVE) {
            pthread_mutex_unlock(&s->jmtx);
            break;
        }
        len = s->job_len;
        entry = s->job_entry;
        msgid = s->job_msgid;
        memcpy(ecm, s->job_ecm, (size_t)len);
        s->has_job = false;
        s->job_busy = true;
        pthread_mutex_unlock(&s->jmtx);
        svc_process_job(s, entry, ecm, len, msgid);
        pthread_mutex_lock(&s->jmtx);
        s->job_busy = false;
        pthread_mutex_unlock(&s->jmtx);
    }

done:
    if (real_session) session_cleanup(&s->cl);
    else if (G.skip_account) {
        pthread_mutex_destroy(&s->cl.auth_mtx);
        pthread_mutex_destroy(&s->cl.state_mtx);
    }
    atomic_store(&s->worker_done, 1);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* service lifecycle (manager thread only)                             */
/* ------------------------------------------------------------------ */

static void svc_close_filters(dvb_svc_t *s, int keep)
{
    for (int e = 0; e < s->pmt.n_ecm; e++) {
        if (e == keep || s->flt_fd[e] < 0) continue;
        if (conn_is_network(s->conn)) (void)net_send_filter_stop(s, e);
        else G.backend.demux_close(s->flt_fd[e]);
        s->flt_fd[e] = -1;
    }
}

static int svc_open_filter(dvb_svc_t *s, int e)
{
    int fd;
    if (conn_is_network(s->conn)) {
        fd = net_send_filter(s, e, 0x80, 0xF0);
        if (fd < 0) {
            tcmg_log("DVBAPI network: DMX_SET_FILTER failed sid=%04X pid=%04X", s->pmt.program, s->pmt.ecm[e].pid);
            return -1;
        }
        s->flt_fd[e] = fd;
        return 0;
    }
    fd = G.backend.demux_open(s->pmt.adapter, s->pmt.demux);
    if (fd < 0) {
        tcmg_log("demux%d open failed on adapter %d errno=%d (%s)", s->pmt.demux, s->pmt.adapter, errno, strerror(errno));
        return -1;
    }
    if (G.backend.demux_filter(fd, s->pmt.ecm[e].pid, 0x80, 0xF0) < 0) {
        tcmg_log("DMX_SET_FILTER failed pid=%04X errno=%d (%s)", s->pmt.ecm[e].pid, errno, strerror(errno));
        G.backend.demux_close(fd);
        return -1;
    }
    s->flt_fd[e] = fd;
    return 0;
}

static void svc_stop(dvb_svc_t *s)
{
    if (atomic_load(&s->state) != SVC_ACTIVE) return;
    pthread_mutex_lock(&s->mtx);
    atomic_store(&s->state, SVC_STOPPING);
    svc_close_filters(s, -1);
    svc_clear_pids(s, 0);
    if (!conn_is_network(s->conn)) ca_drop_all(s);
    pthread_mutex_unlock(&s->mtx);
    pthread_mutex_lock(&s->jmtx);
    pthread_cond_signal(&s->jcv);
    pthread_mutex_unlock(&s->jmtx);
    /* Routine zapping creates many stop/start events; keep them in DVBAPI debug. */
    tcmg_log_dbg(D_DVBAPI, "service stopped sid=%04X", s->pmt.program);
}

static int svc_descr_limit(const S_DVBAPI_CAPMT *p, int conn)
{
    int limit = DVB_IDX_MAX;
    /* A network client owns its CA device; local device probing is irrelevant. */
    if (conn_is_network(conn)) return DVB_IDX_MAX;
    bool found = false;
    for (int bit = 0; bit < DVB_CA_MAX; bit++) {
        int n;
        if (!(p->ca_mask & (1u << bit))) continue;
        n = G.backend.ca_descr_count ? G.backend.ca_descr_count(p->adapter, bit) : -1;
        if (n <= 0) n = 16; /* OSCam's safe local fallback */
        if (n > DVB_IDX_MAX) n = DVB_IDX_MAX;
        if (n < limit) limit = n;
        found = true;
    }
    return found ? limit : 16;
}

static int svc_alloc_index(const S_DVBAPI_CAPMT *p, int conn)
{
    int max_idx = svc_descr_limit(p, conn);
    for (int idx = 0; idx < max_idx; idx++) {
        bool used = false;
        for (int i = 0; i < DVB_MAX_SVC && !used; i++) {
            dvb_svc_t *o = &G.svc[i];
            if (atomic_load(&o->state) != SVC_ACTIVE) continue;
            if (o->idx == idx) {
                /* Remote DVBAPI clients have independent demux/descrambler namespaces.
                 * Local services still share the physical CA device. */
                bool old_net = conn_is_network(o->conn);
                bool new_net = conn_is_network(conn);
                if ((old_net || new_net) && o->conn != conn) continue;
                if (o->pmt.adapter != p->adapter || !(o->pmt.ca_mask & p->ca_mask)) continue;
                used = true;
            }
        }
        if (!used) return idx;
    }
    return -1;
}

static bool pmt_same(const S_DVBAPI_CAPMT *a, const S_DVBAPI_CAPMT *b)
{
    if (a->program != b->program || a->version != b->version ||
        a->pmt_pid != b->pmt_pid || a->ens != b->ens ||
        a->tsid != b->tsid || a->onid != b->onid ||
        a->service_type_mask != b->service_type_mask ||
        a->n_ecm != b->n_ecm || a->n_streams != b->n_streams ||
        a->demux != b->demux || a->adapter != b->adapter || a->ca_mask != b->ca_mask)
        return false;
    for (int i = 0; i < a->n_ecm; i++) {
        if (a->ecm[i].caid != b->ecm[i].caid || a->ecm[i].pid != b->ecm[i].pid ||
            a->ecm[i].provid != b->ecm[i].provid ||
            a->ecm[i].stream_mask != b->ecm[i].stream_mask) return false;
    }
    for (int i = 0; i < a->n_streams; i++) {
        if (a->stream_pid[i] != b->stream_pid[i] ||
            a->stream_type[i] != b->stream_type[i]) return false;
    }
    return true;
}

static void svc_start(int conn, const S_DVBAPI_CAPMT *in, uint32_t net_msgid)
{
    dvb_svc_t *s = NULL;
    S_DVBAPI_CAPMT pmt = *in;
    int active = 0;

    for (int i = 0; i < DVB_MAX_SVC; i++) {
        if (atomic_load(&G.svc[i].state) == SVC_ACTIVE) active++;
        else if (!s && atomic_load(&G.svc[i].state) == SVC_FREE) s = &G.svc[i];
    }
    if (!s || active >= G.max_services) {
        tcmg_log("service sid=%04X ignored: max_services=%d reached", pmt.program, G.max_services);
        return;
    }

    if (!G.skip_account) {
        S_ACCOUNT *acc = account_acquire(G.user);
        int n = 0;
        if (!acc) {
            tcmg_log("service sid=%04X: account '%s' not found -- create it in the users list", pmt.program, G.user);
            return;
        }
        for (int e = 0; e < pmt.n_ecm; e++) {
            const S_DVBAPI_ECMPID *candidate = &pmt.ecm[e];
            if (!account_allows_caid(acc, candidate->caid)) {
                tcmg_log_dbg(D_DVBAPI, "sid=%04X caid=%04X not allowed for account '%s'",
                             pmt.program, candidate->caid, G.user);
                continue;
            }
            /* Like OSCam's matching_reader() in dvbapi_start_descrambling(),
             * do not open a filter for a CAID/PID that no configured reader
             * can possibly service. ECM length is not known until the first
             * section; ecmwhitelist remains checked by ecm_process(). */
            if (!reader_dvbapi_candidate(acc, candidate->caid, pmt.program, candidate->provid)) {
                tcmg_log_dbg(D_DVBAPI,
                             "sid=%04X skip ecm pid=%04X caid=%04X provid=%06X: no matching reader",
                             pmt.program, candidate->pid, candidate->caid,
                             (unsigned)candidate->provid);
                continue;
            }
            if (n != e) pmt.ecm[n] = pmt.ecm[e];
            n++;
        }
        pmt.n_ecm = n;
        account_release(acc);
    }
    if (pmt.n_ecm == 0) {
        tcmg_log_dbg(D_DVBAPI, "sid=%04X has no usable ECM pid (free-to-air or caid not allowed)", pmt.program);
        return;
    }

    memset(&s->pmt, 0, sizeof(s->pmt));
    s->pmt = pmt;
    s->idx = svc_alloc_index(&pmt, conn);
    if (s->idx < 0) {
        tcmg_log("service sid=%04X: no free descrambler index", pmt.program);
        return;
    }
    s->conn = conn;
    tcmg_strlcpy(s->client_ip,
                 (conn >= 0 && conn < DVB_MAX_CONN && G.conn[conn].peer_ip[0])
                     ? G.conn[conn].peer_ip : "127.0.0.1",
                 sizeof(s->client_ip));
    s->net_msgid = net_msgid;
    s->stale = false;
    s->fail_count = 0;
    s->first_done = false;
    s->ca_held = 0;
    s->pids_set = false;
    s->pids_active = false;
    s->pids_entry = -1;
    s->cw_valid[0] = s->cw_valid[1] = false;
    s->has_job = false;
    s->job_busy = false;
    atomic_store(&s->lock_ecm, -1);
    atomic_store(&s->lock_req, REQ_NONE);
    atomic_store(&s->worker_done, 0);
    for (int e = 0; e < DVBAPI_MAX_ECM; e++) s->flt_fd[e] = -1;
    pthread_mutex_lock(&s->jmtx);
    memset(s->gate, 0, sizeof(s->gate));
    pthread_mutex_unlock(&s->jmtx);

    {
        int opened = 0;
        for (int e = 0; e < s->pmt.n_ecm; e++)
            if (svc_open_filter(s, e) == 0) opened++;
        if (opened == 0) {
            svc_close_filters(s, -1);
            return;
        }
    }

    atomic_store(&s->state, SVC_ACTIVE);
    {
        pthread_t th;
        pthread_attr_t attr;
        int prc = pthread_attr_init(&attr);
        bool attr_ready = (prc == 0);
        if (prc == 0) {
            prc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            if (prc == 0) {
                int src = pthread_attr_setstacksize(&attr, 256 * 1024);
                if (src != 0)
                    tcmg_log_dbg(D_DVBAPI,
                                 "service sid=%04X: stack size request failed rc=%d (%s); using default stack",
                                 pmt.program, src, strerror(src));
                prc = pthread_create(&th, &attr, svc_worker, s);
            }
        }
        if (attr_ready) pthread_attr_destroy(&attr);
        if (prc != 0) {
            tcmg_log("service sid=%04X: worker thread setup failed rc=%d (%s)",
                     pmt.program, prc, strerror(prc));
            atomic_store(&s->state, SVC_STOPPING);
            svc_close_filters(s, -1);
            atomic_store(&s->worker_done, 1);
            return;
        }
    }
    /* Service lifecycle is useful for diagnosis, but too noisy at normal log level. */
    tcmg_log_dbg(D_DVBAPI, "service started sid=%04X adapter=%d demux=%d ca_mask=%X descrambler=%d ecm_pids=%d streams=%d",
                 pmt.program, pmt.adapter, pmt.demux, (unsigned)pmt.ca_mask, s->idx, pmt.n_ecm, pmt.n_streams);
    for (int e = 0; e < s->pmt.n_ecm; e++)
        tcmg_log_dbg(D_DVBAPI, "  ecm caid=%04X pid=%04X provid=%06X", s->pmt.ecm[e].caid, s->pmt.ecm[e].pid, (unsigned)s->pmt.ecm[e].provid);
}

static void svc_apply_requests(dvb_svc_t *s)
{
    int r = atomic_exchange(&s->lock_req, REQ_NONE);
    if (r == REQ_NONE || atomic_load(&s->state) != SVC_ACTIVE) return;
    if (r >= 0 && r < s->pmt.n_ecm) {
        svc_close_filters(s, r);
        atomic_store(&s->lock_ecm, r);
        tcmg_log_dbg(D_DVBAPI, "sid=%04X locked on ecm pid=%04X", s->pmt.program, s->pmt.ecm[r].pid);
    } else if (r == REQ_UNLOCK) {
        atomic_store(&s->lock_ecm, -1);
        for (int e = 0; e < s->pmt.n_ecm; e++) {
            if (s->flt_fd[e] < 0) (void)svc_open_filter(s, e);
            pthread_mutex_lock(&s->jmtx);
            memset(&s->gate[e], 0, sizeof(s->gate[e]));
            pthread_mutex_unlock(&s->jmtx);
        }
        tcmg_log_dbg(D_DVBAPI, "sid=%04X lost lock, scanning all ecm pids", s->pmt.program);
    }
}

/*
 * ECM acceptance, same idea as OSCam's dvbapi_process_input():
 *  - one ECM per table (0x80 / 0x81): while it is being decrypted, and after its CW was
 *    found, every further section of the same table is ignored until the opposite table
 *    arrives (the demux filter is switched to the opposite table too, see svc_apply_filters);
 *  - the section stream is not CRC protected, so a noisy signal delivers copies of the ECM
 *    with a few flipped bytes. A section that looks wrong (different length than the last
 *    good ECM) or that follows a refused one is only sent once the same bytes were
 *    seen twice, which a random corruption never does.
 */
static void svc_on_section(dvb_svc_t *s, int e, const uint8_t *buf, int n, uint32_t msgid)
{
    int len;
    bool send = false, same_sent;
    int64_t now;
    dvb_gate_t *g;

    if (n < 4) return;
    if (buf[0] != 0x80 && buf[0] != 0x81) return;
    len = (((int)buf[1] & 0x0F) << 8 | buf[2]) + 3;
    if (len > n || len > DVB_ECM_MAX || len < 4) return;
    now = tcmg_mono_ms();

    pthread_mutex_lock(&s->jmtx);
    g = &s->gate[e];
    /* OSCam flips the ECM section filter before dispatching request_cw().
     * TCMG applies the hardware filter update from the manager thread after the
     * result returns, so enforce the same single-in-flight rule in software.
     * This also prevents one PID's request overwriting the shared job slot for
     * another PID while the reader is still processing it. */
    if (s->job_busy || s->has_job || g->state == GATE_PENDING ||
        (g->state == GATE_DONE && g->table == buf[0])) {
        pthread_mutex_unlock(&s->jmtx);
        return;
    }
    same_sent = g->table == buf[0] && g->sent_len == len && memcmp(g->sent, buf, (size_t)len) == 0;
    {
        bool fresh = g->state == GATE_IDLE || g->table != buf[0];
        bool suspect = g->good_len != 0 && len != g->good_len;
        if (fresh && !suspect) {
            send = true;
        } else {
            if (g->cand_len == len && memcmp(g->cand, buf, (size_t)len) == 0) {
                g->cand_cnt++;
            } else {
                memcpy(g->cand, buf, (size_t)len);
                g->cand_len = len;
                g->cand_cnt = 1;
            }
            if (g->cand_cnt >= DVB_CONFIRM) {
                if (!same_sent) send = true;
                else if (g->tries < DVB_MAX_RETRY && now - g->sent_ms >= DVB_RETRY_MS) { g->tries++; send = true; }
            }
        }
    }
    if (send) {
        if (!same_sent) g->tries = 0;
        g->table = buf[0];
        g->state = GATE_PENDING;
        memcpy(g->sent, buf, (size_t)len);
        g->sent_len = len;
        g->sent_ms = now;
        g->cand_cnt = 0;
        memcpy(s->job_ecm, buf, (size_t)len);
        s->job_len = len;
        s->job_entry = e;
        s->job_msgid = msgid;
        s->has_job = true;
        pthread_cond_signal(&s->jcv);
    }
    pthread_mutex_unlock(&s->jmtx);
}

/* worker side: record the card's answer for the ECM that was sent */
static void svc_gate_result(dvb_svc_t *s, int e, const uint8_t *ecm, bool ok)
{
    dvb_gate_t *g;
    pthread_mutex_lock(&s->jmtx);
    g = &s->gate[e];
    if (g->state == GATE_PENDING && g->table == ecm[0]) {
        if (ok) {
            g->state = GATE_DONE;
            g->good_len = g->sent_len;
            g->tries = 0;
            g->flt_req = FLT_REQ(0x80 | ((ecm[0] & 1) ^ 1), 0xFF);   /* only the opposite table */
        } else {
            g->state = GATE_FAILED;
            g->flt_req = FLT_REQ(0x80, 0xF0);                         /* both tables again */
        }
    }
    pthread_mutex_unlock(&s->jmtx);
}

/* manager thread: apply the hardware filter changes asked for by svc_gate_result() */
static void svc_apply_filters(dvb_svc_t *s)
{
    for (int e = 0; e < s->pmt.n_ecm; e++) {
        int req;
        pthread_mutex_lock(&s->jmtx);
        req = s->gate[e].flt_req;
        s->gate[e].flt_req = 0;
        pthread_mutex_unlock(&s->jmtx);
        if (!req || s->flt_fd[e] < 0) continue;
        int frc = conn_is_network(s->conn)
                     ? net_send_filter(s, e, (uint8_t)((req >> 8) & 0xFF), (uint8_t)(req & 0xFF))
                     : G.backend.demux_filter(s->flt_fd[e], s->pmt.ecm[e].pid,
                                               (uint8_t)((req >> 8) & 0xFF), (uint8_t)(req & 0xFF));
        if (frc < 0)
            tcmg_log_dbg(D_DVBAPI, "DMX_SET_FILTER update failed pid=%04X errno=%d (%s)",
                         s->pmt.ecm[e].pid, errno, strerror(errno));
        else
            tcmg_log_dbg(D_DVBAPI, "sid=%04X ecm pid=%04X filter table=%02X mask=%02X",
                         s->pmt.program, s->pmt.ecm[e].pid, (req >> 8) & 0xFF, req & 0xFF);
    }
}

/* ------------------------------------------------------------------ */
/* CA_PMT handling                                                     */
/* ------------------------------------------------------------------ */

static void conn_stop_services(int conn, int demux, bool only_stale)
{
    for (int i = 0; i < DVB_MAX_SVC; i++) {
        dvb_svc_t *s = &G.svc[i];
        if (atomic_load(&s->state) != SVC_ACTIVE || s->conn != conn) continue;
        if (only_stale && !s->stale) continue;
        if (demux >= 0 && demux != 0xFF) {
            int service_demux = conn_is_network(conn) ? s->idx : s->pmt.demux;
            if (service_demux != demux) continue;
        }
        svc_stop(s);
    }
}

static void handle_capmt(int conn, const S_DVBAPI_CAPMT *p, uint32_t net_msgid)
{
    dvb_svc_t *found = NULL;

    tcmg_log_dbg(D_DVBAPI, "CA_PMT mgmt=%d cmd=%d sid=%04X adapter=%d demux=%d ca_mask=%X ecm=%d streams=%d",
                 p->list_mgmt, p->cmd_id, p->program, p->adapter, p->demux, (unsigned)p->ca_mask, p->n_ecm, p->n_streams);

    if (p->list_mgmt == CAPMT_LIST_FIRST || p->list_mgmt == CAPMT_LIST_ONLY) {
        for (int i = 0; i < DVB_MAX_SVC; i++)
            if (atomic_load(&G.svc[i].state) == SVC_ACTIVE && G.svc[i].conn == conn) G.svc[i].stale = true;
    }
    for (int i = 0; i < DVB_MAX_SVC; i++) {
        dvb_svc_t *s = &G.svc[i];
        if (atomic_load(&s->state) == SVC_ACTIVE && s->conn == conn &&
            s->pmt.program == p->program && s->pmt.adapter == p->adapter &&
            s->pmt.demux == p->demux) { found = s; break; }
    }

    /* OSCam starts descrambling only for OK_DESCRAMBLING. QUERY is not
     * implemented by OSCam's DVBAPI either; NOT_SELECTED explicitly stops. */
    if (p->cmd_id != CAPMT_CMD_OK_DESCRAMBLING) {
        if (found) svc_stop(found);
        if (p->cmd_id != CAPMT_CMD_NOT_SELECTED)
            tcmg_log_dbg(D_DVBAPI, "sid=%04X CA_PMT cmd_id=%02X unsupported; descrambling stopped",
                         p->program, p->cmd_id);
    } else if (found) {
        if (pmt_same(&found->pmt, p)) {
            found->stale = false;
        } else {
            svc_stop(found);
            svc_start(conn, p, net_msgid);
        }
    } else {
        svc_start(conn, p, net_msgid);
    }

    if (p->list_mgmt == CAPMT_LIST_ONLY || p->list_mgmt == CAPMT_LIST_LAST)
        conn_stop_services(conn, -1, true);
}

static void conn_close(int c)
{
    int fd;
    if (c < 0 || c >= DVB_MAX_CONN || G.conn[c].fd < 0) return;
    conn_stop_services(c, -1, false);
    /* A service worker may finish a CA command while the manager is closing
     * the socket. Serialize close with all network writes to avoid using a
     * recycled descriptor. */
    pthread_mutex_lock(&G.conn[c].tx_mtx);
    fd = G.conn[c].fd;
    G.conn[c].fd = -1;
    G.conn[c].network = false;
    G.conn[c].proto_version = 0;
    G.conn[c].rlen = 0;
    G.conn[c].peer_name[0] = '\0';
    G.conn[c].peer_ip[0] = '\0';
    if (fd >= 0) {
        (void)shutdown(fd, SHUT_RDWR);
        close(fd);
    }
    pthread_mutex_unlock(&G.conn[c].tx_mtx);
    tcmg_log_dbg(D_CONN, "DVBAPI connection closed");
}

static int net_conn_read(int c);

static int conn_read(int c)
{
    dvb_conn_t *cn = &G.conn[c];
    if (cn->network) return net_conn_read(c);
    ssize_t n = read(cn->fd, cn->rbuf + cn->rlen, sizeof(cn->rbuf) - cn->rlen);
    if (n == 0) return -1;
    if (n < 0) return (errno == EAGAIN || errno == EINTR) ? 0 : -1;
    cn->rlen += (size_t)n;

    for (;;) {
        size_t used = 0, blen = 0;
        const uint8_t *body = NULL;
        E_DVBAPI_MSG type = DVBAPI_MSG_NONE;
        int rc = dvbapi_frame_next(cn->rbuf, cn->rlen, &used, &type, &body, &blen);
        if (rc == 0) break;
        if (rc < 0) {
            tcmg_log("protocol error on enigma connection -- closing");
            return -1;
        }
        if (type == DVBAPI_MSG_CAPMT) {
            S_DVBAPI_CAPMT p;
            if (dvbapi_capmt_parse(body, blen, &p) == 0) handle_capmt(c, &p, 0);
            else tcmg_log_dbg(D_DVBAPI, "invalid CA_PMT ignored (%zu bytes)", blen);
        } else if (type == DVBAPI_MSG_STOP) {
            int dmx = 0;
            if (dvbapi_stop_parse(body, blen, &dmx) == 0) {
                tcmg_log_dbg(D_DVBAPI, "stop request demux=%d", dmx);
                conn_stop_services(c, dmx, false);
            }
        }
        memmove(cn->rbuf, cn->rbuf + used, cn->rlen - used);
        cn->rlen -= used;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* manager thread                                                      */
/* ------------------------------------------------------------------ */

typedef struct { int kind; int a; int b; } poll_map_t;

static int listen_open(const char *path)
{
    struct sockaddr_un sa;
    int fd;
    if (strlen(path) >= sizeof(sa.sun_path)) {
        tcmg_log("socket path too long: %s", path);
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        tcmg_log("socket() failed errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    tcmg_strlcpy(sa.sun_path, path, sizeof(sa.sun_path));
    (void)unlink(path);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(fd, DVB_MAX_CONN) < 0) {
        tcmg_log("cannot listen on %s errno=%d (%s)", path, errno, strerror(errno));
        close(fd);
        return -1;
    }
    (void)chmod(path, 0666);
    (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

static int unix_connect_open(const char *path)
{
    struct sockaddr_un sa;
    int fd, flags;
    if (!path || !path[0] || strlen(path) >= sizeof(sa.sun_path)) return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    tcmg_strlcpy(sa.sun_path, path, sizeof(sa.sun_path));
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

static int net_listen_open(const char *address, int port)
{
    struct sockaddr_in sa;
    int fd, one = 1;
    const char *ip = (address && address[0]) ? address : "0.0.0.0";
    if (port < 1 || port > 65535) return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        tcmg_log("DVBAPI TCP socket() failed errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        tcmg_log("DVBAPI TCP bind address is invalid: %s", ip);
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(fd, DVB_MAX_CONN) < 0) {
        tcmg_log("DVBAPI TCP listen failed on %s:%d errno=%d (%s)", ip, port, errno, strerror(errno));
        close(fd);
        return -1;
    }
    (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

/* Decode OSCam's TCP DVBAPI socket stream. V3 packets begin with A5 + msgid;
 * the first CLIENT_INFO handshake is deliberately unframed. */
static int net_conn_read(int c)
{
    dvb_conn_t *cn = &G.conn[c];
    ssize_t n;
    if (cn->rlen >= sizeof(cn->rbuf)) return -1;
    n = read(cn->fd, cn->rbuf + cn->rlen, sizeof(cn->rbuf) - cn->rlen);
    if (n == 0) return -1;
    if (n < 0) return (errno == EAGAIN || errno == EINTR) ? 0 : -1;
    cn->rlen += (size_t)n;

    for (;;) {
        size_t off = 0, used = 0, body_len = 0;
        uint32_t msgid = 0, opcode;
        const uint8_t *body = NULL;
        E_DVBAPI_MSG type = DVBAPI_MSG_NONE;
        int rc;

        if (cn->proto_version == 0) {
            size_t total;
            uint16_t version;
            uint8_t name_len;
            if (cn->rlen < 7) break;
            if (net_get_u32(cn->rbuf) != DVB_NET_CLIENT_INFO) {
                tcmg_log("DVBAPI TCP: expected CLIENT_INFO handshake; closing peer");
                return -1;
            }
            version = net_get_u16(cn->rbuf + 4);
            name_len = cn->rbuf[6];
            total = 7u + (size_t)name_len;
            if (cn->rlen < total) break;
            if (version < 1) {
                tcmg_log("DVBAPI TCP: unsupported client protocol version %u", (unsigned)version);
                return -1;
            }
            if (version > DVB_NET_PROTO_VERSION) version = DVB_NET_PROTO_VERSION;
            cn->proto_version = version;
            size_t copy = name_len;
            if (copy >= sizeof(cn->peer_name)) copy = sizeof(cn->peer_name) - 1;
            if (copy) memcpy(cn->peer_name, cn->rbuf + 7, copy);
            cn->peer_name[copy] = '\0';
            if (net_send_server_info(c) < 0) return -1;
            tcmg_log_dbg(D_DVBAPI, "DVBAPI TCP client '%s' protocol=%u connected",
                         cn->peer_name, (unsigned)cn->proto_version);
            memmove(cn->rbuf, cn->rbuf + total, cn->rlen - total);
            cn->rlen -= total;
            continue;
        }

        if (cn->proto_version >= 3) {
            if (cn->rlen < 5) break;
            if (cn->rbuf[0] != 0xA5) {
                tcmg_log("DVBAPI TCP: malformed protocol-v3 packet (missing A5)");
                return -1;
            }
            msgid = net_get_u32(cn->rbuf + 1);
            off = 5;
        }
        if (cn->rlen < off + 4) break;
        opcode = net_get_u32(cn->rbuf + off);

        if (opcode == DVB_NET_FILTER_DATA) {
            size_t total, sec_len;
            int demux_id, filter_id;
            const uint8_t *section;
            dvb_svc_t *svc = NULL;
            if (cn->rlen < off + 9) break;
            sec_len = (size_t)(net_get_u16(cn->rbuf + off + 7) & 0x0FFFu);
            total = off + 9u + sec_len;
            if (total > sizeof(cn->rbuf)) return -1;
            if (cn->rlen < total) break;
            demux_id = cn->rbuf[off + 4];
            filter_id = cn->rbuf[off + 5];
            section = cn->rbuf + off + 6;
            if (demux_id >= 0 && demux_id < DVB_IDX_MAX &&
                filter_id >= 0 && filter_id < DVBAPI_MAX_ECM) {
                for (int i = 0; i < DVB_MAX_SVC; i++) {
                    dvb_svc_t *candidate = &G.svc[i];
                    if (atomic_load(&candidate->state) == SVC_ACTIVE && candidate->conn == c &&
                        candidate->idx == demux_id && filter_id < candidate->pmt.n_ecm &&
                        candidate->flt_fd[filter_id] >= 0) {
                        svc = candidate;
                        break;
                    }
                }
                if (svc) svc_on_section(svc, filter_id, section, (int)(sec_len + 3u), msgid);
                else tcmg_log_dbg(D_DVBAPI, "DVBAPI TCP: FILTER_DATA for unknown demux=%d filter=%d", demux_id, filter_id);
            }
            used = total;
        } else if (cn->rbuf[off] == 0x9F && cn->rbuf[off + 1] == 0x80 &&
                   (cn->rbuf[off + 2] == 0x32 || cn->rbuf[off + 2] == 0x3F)) {
            rc = dvbapi_frame_next(cn->rbuf + off, cn->rlen - off, &used, &type, &body, &body_len);
            if (rc == 0) break;
            if (rc < 0) {
                tcmg_log("DVBAPI TCP: malformed CA_PMT/CA_STOP packet");
                return -1;
            }
            if (type == DVBAPI_MSG_CAPMT) {
                S_DVBAPI_CAPMT pmt;
                if (dvbapi_capmt_parse(body, body_len, &pmt) == 0)
                    handle_capmt(c, &pmt, msgid);
                else
                    tcmg_log_dbg(D_DVBAPI, "DVBAPI TCP: invalid CA_PMT ignored (%zu bytes)", body_len);
            } else if (type == DVBAPI_MSG_STOP) {
                int demux = -1;
                if (dvbapi_stop_parse(body, body_len, &demux) == 0)
                    conn_stop_services(c, demux, false);
            }
            used += off;
        } else {
            tcmg_log("DVBAPI TCP: unsupported opcode %08X", opcode);
            return -1;
        }

        if (used == 0 || used > cn->rlen) return -1;
        memmove(cn->rbuf, cn->rbuf + used, cn->rlen - used);
        cn->rlen -= used;
    }
    return 0;
}

static void reap_services(void)
{
    for (int i = 0; i < DVB_MAX_SVC; i++) {
        dvb_svc_t *s = &G.svc[i];
        /* If worker initialization failed (e.g. missing/expired account), it
         * exits while the service is still ACTIVE. Ask the manager thread to
         * perform the same hardware/filter cleanup as a normal stop. */
        if (atomic_load(&s->state) == SVC_ACTIVE && atomic_load(&s->worker_done))
            svc_stop(s);
        if (atomic_load(&s->state) == SVC_STOPPING && atomic_load(&s->worker_done)) {
            s->conn = -1;
            atomic_store(&s->state, SVC_FREE);
        }
    }
}

static void *mgr_thread(void *arg)
{
    (void)arg;
    log_set_type(LOG_TYPE_CLIENT);

    while (atomic_load(&G.running) && g_running) {
        if (G.local_client_mode) {
            bool have_local_connection = false;
            int64_t now = tcmg_mono_ms();
            for (int c = 0; c < DVB_MAX_CONN; c++) {
                if (G.conn[c].fd >= 0 && !G.conn[c].network) {
                    have_local_connection = true;
                    break;
                }
            }
            if (!have_local_connection && now >= G.next_local_connect_ms) {
                int fd;
                G.next_local_connect_ms = now + 1000;
                fd = unix_connect_open(G.path);
                if (fd >= 0) {
                    int slot = -1;
                    for (int c = 0; c < DVB_MAX_CONN; c++) {
                        if (G.conn[c].fd < 0) { slot = c; break; }
                    }
                    if (slot >= 0) {
                        G.conn[slot].fd = fd;
                        G.conn[slot].rlen = 0;
                        G.conn[slot].network = false;
                        G.conn[slot].proto_version = 0;
                        G.conn[slot].peer_name[0] = '\0';
                        tcmg_strlcpy(G.conn[slot].peer_ip, "127.0.0.1", sizeof(G.conn[slot].peer_ip));
                        tcmg_log("DVBAPI: connected to Enigma2 CA_PMT socket %s", G.path);
                    } else {
                        close(fd);
                        tcmg_log("DVBAPI: no free connection slot for Enigma2 CA_PMT socket");
                    }
                } else {
                    tcmg_log_dbg(D_DVBAPI, "DVBAPI: waiting for Enigma2 CA_PMT socket %s", G.path);
                }
            }
        }
        struct pollfd fds[2 + DVB_MAX_CONN + DVB_MAX_SVC * DVBAPI_MAX_ECM];
        poll_map_t map[2 + DVB_MAX_CONN + DVB_MAX_SVC * DVBAPI_MAX_ECM];
        nfds_t n = 0;

        if (G.listen_fd >= 0) {
            fds[n].fd = G.listen_fd; fds[n].events = POLLIN; fds[n].revents = 0;
            map[n].kind = 0; map[n].a = 0; map[n].b = 0; n++;
        }
        if (G.net_listen_fd >= 0) {
            fds[n].fd = G.net_listen_fd; fds[n].events = POLLIN; fds[n].revents = 0;
            map[n].kind = 3; map[n].a = 0; map[n].b = 0; n++;
        }
        for (int c = 0; c < DVB_MAX_CONN; c++) {
            if (G.conn[c].fd < 0) continue;
            fds[n].fd = G.conn[c].fd; fds[n].events = POLLIN; fds[n].revents = 0;
            map[n].kind = 1; map[n].a = c; map[n].b = 0; n++;
        }
        for (int i = 0; i < DVB_MAX_SVC; i++) {
            dvb_svc_t *s = &G.svc[i];
            if (atomic_load(&s->state) != SVC_ACTIVE) continue;
            for (int e = 0; e < s->pmt.n_ecm; e++) {
                if (s->flt_fd[e] < 0 || conn_is_network(s->conn)) continue;
                fds[n].fd = s->flt_fd[e]; fds[n].events = POLLIN; fds[n].revents = 0;
                map[n].kind = 2; map[n].a = i; map[n].b = e; n++;
            }
        }

        if (poll(fds, n, 100) > 0) {
            for (nfds_t k = 0; k < n; k++) {
                if (!(fds[k].revents & (POLLIN | POLLHUP | POLLERR))) continue;
                if (map[k].kind == 0 || map[k].kind == 3) {
                    bool remote = map[k].kind == 3;
                    int lfd = remote ? G.net_listen_fd : G.listen_fd;
                    struct sockaddr_in peer_addr;
                    socklen_t peer_len = (socklen_t)sizeof(peer_addr);
                    int cfd = accept(lfd, remote ? (struct sockaddr *)&peer_addr : NULL,
                                     remote ? &peer_len : NULL);
                    if (cfd < 0) continue;
                    int slot = -1;
                    for (int c = 0; c < DVB_MAX_CONN; c++) if (G.conn[c].fd < 0) { slot = c; break; }
                    if (slot < 0) { close(cfd); tcmg_log("DVBAPI: too many connections -- rejected"); continue; }
                    (void)fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL, 0) | O_NONBLOCK);
                    (void)fcntl(cfd, F_SETFD, FD_CLOEXEC);
                    G.conn[slot].fd = cfd;
                    G.conn[slot].rlen = 0;
                    G.conn[slot].network = remote;
                    G.conn[slot].proto_version = 0;
                    G.conn[slot].peer_name[0] = '\0';
                    if (remote && peer_len >= (socklen_t)sizeof(peer_addr) &&
                        inet_ntop(AF_INET, &peer_addr.sin_addr, G.conn[slot].peer_ip,
                                  sizeof(G.conn[slot].peer_ip)) == NULL) {
                        G.conn[slot].peer_ip[0] = '\0';
                    } else if (!remote) {
                        tcmg_strlcpy(G.conn[slot].peer_ip, "127.0.0.1", sizeof(G.conn[slot].peer_ip));
                    }
                    tcmg_log_dbg(D_CONN, "%s DVBAPI connection accepted%s%s", remote ? "TCP" : "local",
                                 remote && G.conn[slot].peer_ip[0] ? " from " : "",
                                 remote ? G.conn[slot].peer_ip : "");
                } else if (map[k].kind == 1) {
                    if (conn_read(map[k].a) < 0) conn_close(map[k].a);
                } else {
                    dvb_svc_t *s = &G.svc[map[k].a];
                    uint8_t buf[4096];
                    int e = map[k].b, rn;
                    if (atomic_load(&s->state) != SVC_ACTIVE || s->flt_fd[e] != fds[k].fd) continue;
                    rn = G.backend.demux_read(fds[k].fd, buf, sizeof(buf));
                    if (rn > 0) svc_on_section(s, e, buf, rn, 0);
                }
            }
        }
        for (int i = 0; i < DVB_MAX_SVC; i++)
            if (atomic_load(&G.svc[i].state) == SVC_ACTIVE) { svc_apply_requests(&G.svc[i]); svc_apply_filters(&G.svc[i]); }
        reap_services();
    }

    for (int c = 0; c < DVB_MAX_CONN; c++) conn_close(c);
    for (int i = 0; i < DVB_MAX_SVC; i++) svc_stop(&G.svc[i]);
    for (int w = 0; w < 30; w++) {
        bool busy = false;
        reap_services();
        for (int i = 0; i < DVB_MAX_SVC; i++) if (atomic_load(&G.svc[i].state) != SVC_FREE) busy = true;
        if (!busy) break;
        tcmg_sleep_ms(100);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

void dvbapi_test_hooks(const S_DVBAPI_BACKEND *backend, T_DVBAPI_ECM_FN ecm_fn, int skip_account)
{
    if (backend) s_hook_backend = *backend;
    s_hook_ecm = ecm_fn;
    s_hook_skip = skip_account;
    s_hook_set = backend != NULL || ecm_fn != NULL;
}

int32_t dvbapi_start_with(const S_DVBAPI_SETTINGS *st)
{
    if (!st || !st->socket_path || !st->user) return -1;
    if (G.started) return 0;

    if (!G.inited) {
        pthread_mutex_init(&G.ca_mtx, NULL);
        for (int c = 0; c < DVB_MAX_CONN; c++) pthread_mutex_init(&G.conn[c].tx_mtx, NULL);
        for (int i = 0; i < DVB_MAX_SVC; i++) {
            pthread_mutex_init(&G.svc[i].mtx, NULL);
            pthread_mutex_init(&G.svc[i].jmtx, NULL);
            pthread_cond_init(&G.svc[i].jcv, NULL);
        }
        G.inited = true;
    }
    for (int i = 0; i < DVB_MAX_SVC; i++) {
        atomic_store(&G.svc[i].state, SVC_FREE);
        G.svc[i].conn = -1;
        G.ca[i].fd = -1;
        G.ca[i].refs = 0;
    }
    for (int c = 0; c < DVB_MAX_CONN; c++) {
        G.conn[c].fd = -1; G.conn[c].rlen = 0; G.conn[c].network = false;
        G.conn[c].proto_version = 0; G.conn[c].peer_name[0] = '\0';
        G.conn[c].peer_ip[0] = '\0';
    }

    G.ca_offset = st->ca_offset;
    G.delay_ms = st->delay_ms;
    G.max_services = st->max_services > 0 && st->max_services <= DVB_MAX_SVC ? st->max_services : 8;
    tcmg_strlcpy(G.path, st->socket_path, sizeof(G.path));
    tcmg_strlcpy(G.user, st->user, sizeof(G.user));
    G.backend = (s_hook_set && s_hook_backend.demux_open) ? s_hook_backend : k_real_backend;
    G.ecm_fn = (s_hook_set && s_hook_ecm) ? s_hook_ecm : ecm_process;
    G.skip_account = s_hook_set ? s_hook_skip : 0;

    G.listen_port = st->listen_port;
    G.local_client_mode = st->pmt_mode == 6;
    G.owns_socket_path = false;
    G.next_local_connect_ms = 0;
    tcmg_strlcpy(G.serverip, (st->serverip && st->serverip[0]) ? st->serverip : "127.0.0.1", sizeof(G.serverip));
    G.listen_fd = -1;
    if (!G.local_client_mode) {
        G.listen_fd = listen_open(G.path);
        if (G.listen_fd < 0) return -1;
        G.owns_socket_path = true;
    }
    G.net_listen_fd = -1;
    if (G.listen_port > 0) {
        G.net_listen_fd = net_listen_open(G.serverip, G.listen_port);
        if (G.net_listen_fd < 0) {
            if (G.listen_fd >= 0) close(G.listen_fd);
            G.listen_fd = -1;
            if (G.owns_socket_path) (void)unlink(G.path);
            G.owns_socket_path = false;
            return -1;
        }
    }

    atomic_store(&G.running, 1);
    int trc = pthread_create(&G.thread, NULL, mgr_thread, NULL);
    if (trc != 0) {
        tcmg_log("manager thread failed rc=%d (%s)", trc, strerror(trc));
        if (G.listen_fd >= 0) close(G.listen_fd);
        G.listen_fd = -1;
        if (G.net_listen_fd >= 0) close(G.net_listen_fd);
        G.net_listen_fd = -1;
        if (G.owns_socket_path) (void)unlink(G.path);
        G.owns_socket_path = false;
        atomic_store(&G.running, 0);
        return -1;
    }
    G.started = true;
    if (G.local_client_mode && G.net_listen_fd >= 0)
        tcmg_log("DVBAPI: Enigma2 CA_PMT client socket %s; OSCam-compatible TCP %s:%d user='%s' max_services=%d",
                 G.path, G.serverip, G.listen_port, G.user, G.max_services);
    else if (G.local_client_mode)
        tcmg_log("DVBAPI: connecting to Enigma2 CA_PMT socket %s user='%s' max_services=%d",
                 G.path, G.user, G.max_services);
    else if (G.net_listen_fd >= 0)
        tcmg_log("DVBAPI: local socket %s and OSCam-compatible TCP %s:%d user='%s' max_services=%d",
                 G.path, G.serverip, G.listen_port, G.user, G.max_services);
    else
        tcmg_log("listening on %s (enigma2 camd.socket) user='%s' max_services=%d",
                 G.path, G.user, G.max_services);
    return 0;
}

int32_t dvbapi_start(void)
{
    S_DVBAPI_SETTINGS st;
    S_CONFIG_DVBAPI_VIEW v;

    if (!cfg_runtime_dvbapi_snapshot(&v) || !v.enabled) return 0;
    G.cfg_enabled = true;
    st.socket_path = v.socket;
    st.user = v.user;
    st.ca_offset = (!strcmp(v.boxtype, "duckbox") || !strcmp(v.boxtype, "ufs910")) ? 1 : 0;
    st.delay_ms = v.delay_ms;
    st.max_services = v.max_services;
    st.pmt_mode = v.pmt_mode;
    st.listen_port = v.listen_port;
    st.serverip = v.serverip;
    return dvbapi_start_with(&st);
}

void dvbapi_stop(void)
{
    if (!G.started) return;
    atomic_store(&G.running, 0);
    pthread_join(G.thread, NULL);
    if (G.listen_fd >= 0) close(G.listen_fd);
    G.listen_fd = -1;
    if (G.net_listen_fd >= 0) close(G.net_listen_fd);
    G.net_listen_fd = -1;
    if (G.owns_socket_path) (void)unlink(G.path);
    G.owns_socket_path = false;
    G.started = false;
    tcmg_log("stopped");
}

void dvbapi_get_status(S_DVBAPI_STATUS *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->enabled = G.cfg_enabled;
    out->running = G.started;
    if (!G.started) return;
    for (int c = 0; c < DVB_MAX_CONN; c++) if (G.conn[c].fd >= 0) out->connections++;
    for (int i = 0; i < DVB_MAX_SVC; i++) if (atomic_load(&G.svc[i].state) == SVC_ACTIVE) out->services++;
}

#else

int32_t dvbapi_start(void)
{
    S_CONFIG_DVBAPI_VIEW v;
    if (cfg_runtime_dvbapi_snapshot(&v) && v.enabled)
        tcmg_log("dvbapi is only available on Linux receivers -- disabled");
    return 0;
}

void dvbapi_stop(void) {}

void dvbapi_get_status(S_DVBAPI_STATUS *out)
{
    if (out) memset(out, 0, sizeof(*out));
}

#endif
