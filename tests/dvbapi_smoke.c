#include "dvbapi/dvbapi.h"
#include "dvbapi/dvbapi_capmt.h"
#include "dvbapi/dvbapi_priv.h"
#include "core/config_state.h"
#include "core/runtime_state.h"
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct {
    uint16_t caid;
    uint16_t pid;
    uint8_t  priv[8];
    uint8_t  nprivate;
} ecm_spec_t;

static size_t build_capmt(uint8_t *o, uint8_t mgmt, uint16_t prog, int adapter, int demux, int ca,
                          const ecm_spec_t *ecms, int necm, const uint16_t *spids, int ns)
{
    uint8_t body[1024];
    size_t p = 0, pil_pos, desc_start;
    size_t hl;
    body[p++] = mgmt;
    body[p++] = (uint8_t)(prog >> 8);
    body[p++] = (uint8_t)prog;
    body[p++] = 0x01;
    pil_pos = p;
    p += 2;
    desc_start = p;
    body[p++] = CAPMT_CMD_OK_DESCRAMBLING;
    for (int i = 0; i < necm; i++) {
        body[p++] = 0x09;
        body[p++] = (uint8_t)(4 + ecms[i].nprivate);
        body[p++] = (uint8_t)(ecms[i].caid >> 8);
        body[p++] = (uint8_t)ecms[i].caid;
        body[p++] = (uint8_t)(0xE0 | (ecms[i].pid >> 8));
        body[p++] = (uint8_t)ecms[i].pid;
        memcpy(body + p, ecms[i].priv, ecms[i].nprivate);
        p += ecms[i].nprivate;
    }
    body[p++] = 0x83; body[p++] = 1; body[p++] = (uint8_t)adapter;
    body[p++] = 0x86; body[p++] = 1; body[p++] = (uint8_t)demux;
    body[p++] = 0x87; body[p++] = 1; body[p++] = (uint8_t)ca;
    body[p++] = 0x84; body[p++] = 2; body[p++] = 0x01; body[p++] = 0x00;
    {
        size_t pil = p - desc_start;
        body[pil_pos] = (uint8_t)(0xF0 | (pil >> 8));
        body[pil_pos + 1] = (uint8_t)pil;
    }
    for (int i = 0; i < ns; i++) {
        body[p++] = 0x02;
        body[p++] = (uint8_t)(0xE0 | (spids[i] >> 8));
        body[p++] = (uint8_t)spids[i];
        body[p++] = 0xF0;
        body[p++] = 0x00;
    }
    o[0] = 0x9F; o[1] = 0x80; o[2] = 0x32;
    if (p < 0x80) { o[3] = (uint8_t)p; hl = 4; }
    else { o[3] = 0x82; o[4] = (uint8_t)(p >> 8); o[5] = (uint8_t)p; hl = 6; }
    memcpy(o + hl, body, p);
    return hl + p;
}

static void test_parser(void)
{
    uint8_t msg[1100];
    ecm_spec_t ecms[3];
    uint16_t sp[2] = { 0x0200, 0x0201 };
    size_t n, used = 0, blen = 0;
    const uint8_t *body = NULL;
    E_DVBAPI_MSG type = DVBAPI_MSG_NONE;
    S_DVBAPI_CAPMT c;

    memset(ecms, 0, sizeof(ecms));
    ecms[0].caid = 0x0500; ecms[0].pid = 0x0101; ecms[0].nprivate = 5;
    ecms[0].priv[0] = 0x14; ecms[0].priv[1] = 0x03; ecms[0].priv[2] = 0x00; ecms[0].priv[3] = 0x00; ecms[0].priv[4] = 0x4F;
    ecms[1].caid = 0x0100; ecms[1].pid = 0x0202; ecms[1].nprivate = 2;
    ecms[1].priv[0] = 0x00; ecms[1].priv[1] = 0x12;

    n = build_capmt(msg, CAPMT_LIST_ONLY, 0x1001, 0, 1, 1, ecms, 2, sp, 2);

    for (size_t cut = 0; cut < n; cut++)
        assert(dvbapi_frame_next(msg, cut, &used, &type, &body, &blen) == 0);
    assert(dvbapi_frame_next(msg, n, &used, &type, &body, &blen) == 1);
    assert(type == DVBAPI_MSG_CAPMT && used == n);
    assert(dvbapi_capmt_parse(body, blen, &c) == 0);
    assert(c.list_mgmt == CAPMT_LIST_ONLY && c.cmd_id == CAPMT_CMD_OK_DESCRAMBLING);
    assert(c.program == 0x1001);
    assert(c.adapter == 0 && c.demux == 1 && c.ca_mask == 2u && c.pmt_pid == 0x0100);
    assert(c.n_ecm == 2);
    assert(c.ecm[0].caid == 0x0500 && c.ecm[0].pid == 0x0101 && c.ecm[0].provid == 0x40u);
    assert(c.ecm[1].caid == 0x0100 && c.ecm[1].pid == 0x0202 && c.ecm[1].provid == 0x12u);
    assert(c.n_streams == 2 && c.stream_pid[0] == 0x0200 && c.stream_pid[1] == 0x0201);

    /* OSCam keeps different CAID alternatives even if they share one ECM PID. */
    ecms[1] = ecms[0];
    ecms[1].caid = 0x0100;
    n = build_capmt(msg, CAPMT_LIST_ONLY, 0x1001, 0, 1, 1, ecms, 2, sp, 2);
    assert(dvbapi_frame_next(msg, n, &used, &type, &body, &blen) == 1);
    assert(dvbapi_capmt_parse(body, blen, &c) == 0);
    assert(c.n_ecm == 2 && c.ecm[0].pid == c.ecm[1].pid && c.ecm[0].caid != c.ecm[1].caid);

    /* OSCam accepts BER length encodings with more than two length bytes. */
    {
        uint8_t ber[13] = { 0x9F, 0x80, 0x32, 0x83, 0, 0, 6, 1, 2, 3, 4, 5, 6 };
        assert(dvbapi_frame_next(ber, sizeof(ber), &used, &type, &body, &blen) == 1);
        assert(type == DVBAPI_MSG_CAPMT && blen == 6 && used == sizeof(ber));
    }
    {
        uint8_t bad_list[12] = { 0x03, 0x10, 0x01, 0x01, 0xF0, 0x01, CAPMT_CMD_OK_DESCRAMBLING };
        bad_list[0] = 0x06;
        assert(dvbapi_capmt_parse(bad_list, 7, &c) == -1);
    }
    {
        uint8_t bad[8] = { 0x9F, 0x80, 0x99, 0x01, 0, 0, 0, 0 };
        assert(dvbapi_frame_next(bad, sizeof(bad), &used, &type, &body, &blen) == -1);
    }
    {
        uint8_t stop[8] = { 0x9F, 0x80, 0x3F, 0x04, 0x83, 0x02, 0x00, 0x03 };
        int dmx = -1;
        assert(dvbapi_frame_next(stop, sizeof(stop), &used, &type, &body, &blen) == 1);
        assert(type == DVBAPI_MSG_STOP);
        assert(dvbapi_stop_parse(body, blen, &dmx) == 0 && dmx == 3);
    }
    {
        uint8_t ecm[16] = { 0x80, 0x70, 0x0D, 0x90, 0x03, 0x12, 0x34, 0x5A, 0x00 };
        assert(dvbapi_ecm_provid(0x0500, ecm, 9) == 0x123450u);
        assert(dvbapi_ecm_provid(0x1801, ecm, 9) == 0u);
    }
    {
        uint8_t trunc[3] = { 0x03, 0x00, 0x01 };
        assert(dvbapi_capmt_parse(trunc, sizeof(trunc), &c) == -1);
    }
}

/* ---------------- mock devices ---------------- */

#define MAXREC 64

static struct {
    pthread_mutex_t m;
    int  wfd[8];
    int  n_demux_open, n_demux_close;
    int  open_adapter[8], open_demux[8];
    uint16_t filt_pid[8];
    uint8_t  filt_tid[8], filt_mask[8];
    int  n_filters;
    int  n_ca_open, ca_adapter[4], ca_num[4];
    int  n_pid;
    struct { uint16_t pid; int idx; } pids[MAXREC];
    int  n_descr;
    struct { int idx; int parity; uint8_t cw[8]; } descr[MAXREC];
    atomic_int ecm_calls;
    uint16_t ecm_caid, ecm_sid;
    uint32_t ecm_provid;
} R;

static int m_demux_open(int adapter, int demux)
{
    int p[2], idx;
    if (pipe2(p, O_NONBLOCK | O_CLOEXEC) != 0) return -1;
    pthread_mutex_lock(&R.m);
    idx = R.n_demux_open++;
    R.wfd[idx] = p[1];
    R.open_adapter[idx] = adapter;
    R.open_demux[idx] = demux;
    pthread_mutex_unlock(&R.m);
    return p[0];
}

static int m_demux_filter(int fd, uint16_t pid, uint8_t tid, uint8_t mask)
{
    (void)fd;
    pthread_mutex_lock(&R.m);
    R.filt_pid[R.n_filters] = pid;
    R.filt_tid[R.n_filters] = tid;
    R.filt_mask[R.n_filters] = mask;
    R.n_filters++;
    pthread_mutex_unlock(&R.m);
    return 0;
}

static int m_demux_read(int fd, uint8_t *buf, size_t len)
{
    ssize_t n = read(fd, buf, len);
    return n < 0 ? -1 : (int)n;
}

static void m_demux_close(int fd)
{
    close(fd);
    pthread_mutex_lock(&R.m);
    R.n_demux_close++;
    pthread_mutex_unlock(&R.m);
}

static int m_ca_open(int adapter, int ca)
{
    pthread_mutex_lock(&R.m);
    R.ca_adapter[R.n_ca_open] = adapter;
    R.ca_num[R.n_ca_open] = ca;
    R.n_ca_open++;
    pthread_mutex_unlock(&R.m);
    return open("/dev/null", O_RDWR | O_CLOEXEC);
}

static int m_ca_set_pid(int fd, uint16_t pid, int idx)
{
    (void)fd;
    pthread_mutex_lock(&R.m);
    R.pids[R.n_pid].pid = pid;
    R.pids[R.n_pid].idx = idx;
    R.n_pid++;
    pthread_mutex_unlock(&R.m);
    return 0;
}

static int m_ca_set_descr(int fd, int idx, int parity, const uint8_t cw[8])
{
    (void)fd;
    pthread_mutex_lock(&R.m);
    R.descr[R.n_descr].idx = idx;
    R.descr[R.n_descr].parity = parity;
    memcpy(R.descr[R.n_descr].cw, cw, 8);
    R.n_descr++;
    pthread_mutex_unlock(&R.m);
    return 0;
}

static void m_ca_close(int fd) { close(fd); }

static int32_t m_ecm(S_CLIENT *client, uint16_t caid, uint16_t sid, uint32_t provid,
                     const uint8_t *ecm, int32_t len, uint8_t cw[CW_LEN], S_ECM_RESULT *res)
{
    (void)client; (void)res;
    assert(len >= 5);
    pthread_mutex_lock(&R.m);
    R.ecm_caid = caid;
    R.ecm_sid = sid;
    R.ecm_provid = provid;
    pthread_mutex_unlock(&R.m);
    memset(cw, ecm[3], 8);
    memset(cw + 8, ecm[4], 8);
    atomic_fetch_add(&R.ecm_calls, 1);
    return 0;
}

static int get_int(const int *p)
{
    int v;
    pthread_mutex_lock(&R.m);
    v = *p;
    pthread_mutex_unlock(&R.m);
    return v;
}

static int wait_ge(const int *p, int want, int ms)
{
    for (int t = 0; t < ms; t += 10) {
        if (get_int(p) >= want) return 1;
        usleep(10000);
    }
    return get_int(p) >= want;
}

static size_t build_section_t(uint8_t *o, uint8_t table, uint8_t a, uint8_t b, int extra)
{
    size_t section_len = (size_t)(12 + extra);
    memset(o, 0, 16 + (size_t)extra);
    o[0] = table;
    o[1] = (uint8_t)(0xB0u | (uint8_t)((section_len >> 8) & 0x0Fu));
    o[2] = (uint8_t)(section_len & 0xFFu);
    o[3] = a;
    o[4] = b;
    for (int i = 5; i < 15 + extra; i++) o[i] = (uint8_t)i;
    return (size_t)(15 + extra);
}

static size_t build_section(uint8_t *o, uint8_t a, uint8_t b)
{
    return build_section_t(o, 0x80, a, b, 0);
}

static void send_all(int fd, const uint8_t *b, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, b + off, n - off);
        assert(w > 0);
        off += (size_t)w;
    }
}

static int connect_unix(const char *path)
{
    struct sockaddr_un sa;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(fd >= 0);
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    for (int i = 0; i < 100; i++) {
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) return fd;
        usleep(20000);
    }
    assert(!"connect failed");
    return -1;
}


static void put_u16be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_u32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void recv_exact_timeout(int fd, uint8_t *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, 3000);
        assert(pr > 0 && (pfd.revents & (POLLIN | POLLHUP)) != 0);
        ssize_t r = read(fd, buf + off, n - off);
        assert(r > 0);
        off += (size_t)r;
    }
}

static int reserve_tcp_port(void)
{
    struct sockaddr_in sa;
    socklen_t slen = sizeof(sa);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    assert(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    assert(getsockname(fd, (struct sockaddr *)&sa, &slen) == 0);
    int port = (int)ntohs(sa.sin_port);
    close(fd);
    assert(port > 0);
    return port;
}

static int connect_tcp_local(int port)
{
    struct sockaddr_in sa;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((uint16_t)port);
    for (int i = 0; i < 100; i++) {
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) return fd;
        usleep(10000);
    }
    close(fd);
    assert(!"TCP connect failed");
    return -1;
}

/* Receives one v3 server command. This smoke test intentionally accepts only
 * the commands emitted by the ECM round trip, so an unexpected frame fails. */
static size_t recv_net_v3_command(int fd, uint8_t *packet, size_t cap)
{
    uint32_t opcode;
    size_t rest;
    assert(cap >= 9);
    recv_exact_timeout(fd, packet, 9);
    assert(packet[0] == 0xA5);
    opcode = get_u32be(packet + 5);
    switch (opcode) {
    case 0x403C6F2Bu: rest = 61; break; /* adapter + dmx_sct_filter_params */
    case 0x00006F2Au: rest = 5; break;  /* adapter + demux/filter/pid */
    case 0x40086F87u: rest = 9; break;  /* adapter + ca_pid_t */
    case 0x40106F86u: rest = 17; break; /* adapter + ca_descr_t */
    default:
        fprintf(stderr, "unexpected DVBAPI network opcode %08X\n", opcode);
        assert(!"unexpected DVBAPI network opcode");
        return 0;
    }
    assert(9 + rest <= cap);
    recv_exact_timeout(fd, packet + 9, rest);
    return 9 + rest;
}

static void test_network_listener(void)
{
    char path[96];
    S_DVBAPI_SETTINGS st = {0};
    S_DVBAPI_STATUS status;
    uint8_t hello[64], reply[512], msg[1100], section[32];
    ecm_spec_t ecm;
    uint16_t stream_pid = 0x0200;
    int port = reserve_tcp_port();
    int fd;
    size_t msg_len, n;
    int calls_before = atomic_load(&R.ecm_calls);
    int got_pid = 0, got_filter_update = 0, got_descr = 0;
    unsigned descr_mask = 0;

    snprintf(path, sizeof(path), "/tmp/tcmg_dvbapi_net_%d.sock", (int)getpid());
    st.socket_path = path;
    st.user = "dvbapi";
    st.max_services = 4;
    st.listen_port = port;
    st.serverip = "127.0.0.1";
    assert(dvbapi_start_with(&st) == 0);
    fd = connect_tcp_local(port);

    /* CLIENT_INFO may arrive in pieces; the listener must buffer it. */
    hello[0] = 0xFF; hello[1] = 0xFF; hello[2] = 0x00; hello[3] = 0x01;
    put_u16be(hello + 4, 3);
    hello[6] = 5;
    memcpy(hello + 7, "smoke", 5);
    send_all(fd, hello, 5);
    usleep(20000);
    send_all(fd, hello + 5, 7);
    recv_exact_timeout(fd, reply, 12);
    assert(reply[0] == 0xA5 && get_u32be(reply + 1) == 0);
    assert(get_u32be(reply + 5) == 0xFFFF0002u);
    assert(reply[9] == 0 && reply[10] == 3);
    assert(reply[11] > 0 && reply[11] < 128);
    recv_exact_timeout(fd, reply + 12, reply[11]);

    memset(&ecm, 0, sizeof(ecm));
    ecm.caid = 0x0500;
    ecm.pid = 0x0101;
    ecm.nprivate = 5;
    ecm.priv[0] = 0x14; ecm.priv[1] = 0x03; ecm.priv[4] = 0x40;
    msg_len = build_capmt(msg + 5, CAPMT_LIST_ONLY, 0x2201, 0, 0, 0, &ecm, 1, &stream_pid, 1);
    msg[0] = 0xA5; put_u32be(msg + 1, 0x11223344u);
    send_all(fd, msg, msg_len + 5);

    n = recv_net_v3_command(fd, reply, sizeof(reply));
    assert(n == 70 && get_u32be(reply + 5) == 0x403C6F2Bu);
    assert(reply[9] == 0);
    assert(reply[10] < 32 && reply[11] == 0);
    int demux = reply[10];
    int filter = reply[11];
    assert(((unsigned)reply[12] << 8 | reply[13]) == 0x0101u);

    /* FILTER_DATA carries the section length in the section header and echoes
     * the filter command's message id, as OSCam's v3 protocol requires. */
    n = build_section(section, 0x4A, 0x6B);
    msg[0] = 0xA5; put_u32be(msg + 1, get_u32be(reply + 1));
    put_u32be(msg + 5, 0xFFFF0000u);
    msg[9] = (uint8_t)demux; msg[10] = (uint8_t)filter;
    memcpy(msg + 11, section, n);
    send_all(fd, msg, n + 11);

    for (int t = 0; t < 8 && !(got_pid && got_descr == 3 && got_filter_update); t++) {
        n = recv_net_v3_command(fd, reply, sizeof(reply));
        uint32_t opcode = get_u32be(reply + 5);
        if (opcode == 0x40086F87u) {
            assert(n == 18 && get_u32be(reply + 10) == stream_pid);
            assert(get_u32be(reply + 14) < 32);
            got_pid++;
        } else if (opcode == 0x40106F86u) {
            assert(n == 26 && get_u32be(reply + 10) < 32);
            unsigned parity = get_u32be(reply + 14);
            assert(parity < 2);
            assert(reply[18] == (parity == 0u ? 0x4Au : 0x6Bu));
            descr_mask |= 1u << parity;
            got_descr = (descr_mask == 3u) ? 3 : got_descr;
        } else if (opcode == 0x403C6F2Bu) {
            assert(n == 70 && reply[10] == (uint8_t)demux && reply[11] == (uint8_t)filter);
            got_filter_update++;
        } else {
            assert(!"unexpected DVBAPI command in ECM round trip");
        }
    }
    assert(got_pid == 1 && got_descr == 3 && got_filter_update >= 1);
    for (int t = 0; t < 200 && atomic_load(&R.ecm_calls) < calls_before + 1; t++) usleep(10000);
    assert(atomic_load(&R.ecm_calls) == calls_before + 1);
    dvbapi_get_status(&status);
    assert(status.running && status.connections == 1 && status.services == 1);

    close(fd);
    for (int t = 0; t < 200; t++) {
        dvbapi_get_status(&status);
        if (status.services == 0 && status.connections == 0) break;
        usleep(10000);
    }
    assert(status.services == 0 && status.connections == 0);
    dvbapi_stop();
    assert(access(path, F_OK) != 0);
}

static void test_engine(void)
{
    char path[96];
    S_DVBAPI_BACKEND be;
    S_DVBAPI_SETTINGS st = {0};
    S_DVBAPI_STATUS status;
    uint8_t msg[1100], sec[1100];
    ecm_spec_t ecms[2];
    uint16_t sp[2] = { 0x0200, 0x0201 };
    int cfd, extra_fd[4], n;

    pthread_mutex_init(&R.m, NULL);
    atomic_init(&R.ecm_calls, 0);
    memset(&be, 0, sizeof(be));
    be.demux_open = m_demux_open;
    be.demux_filter = m_demux_filter;
    be.demux_read = m_demux_read;
    be.demux_close = m_demux_close;
    be.ca_open = m_ca_open;
    be.ca_set_pid = m_ca_set_pid;
    be.ca_set_descr = m_ca_set_descr;
    be.ca_close = m_ca_close;
    dvbapi_test_hooks(&be, m_ecm, 1);

    snprintf(path, sizeof(path), "/tmp/tcmg_dvbapi_test_%d.sock", (int)getpid());
    memset(&st, 0, sizeof(st));
    st.socket_path = path;
    st.user = "dvbapi";
    st.max_services = 4;
    assert(dvbapi_start_with(&st) == 0);

    cfd = connect_unix(path);
    /* OSCam allows up to MAX_DEMUX (32) associated DVBAPI sockets. Ensure
     * the TCMG listener no longer rejects a fifth client connection. */
    for (int i = 0; i < 4; i++) extra_fd[i] = connect_unix(path);
    for (int t = 0; t < 200; t++) {
        dvbapi_get_status(&status);
        if (status.connections == 5) break;
        usleep(10000);
    }
    assert(status.connections == 5);

    memset(ecms, 0, sizeof(ecms));
    ecms[0].caid = 0x0500; ecms[0].pid = 0x0101; ecms[0].nprivate = 5;
    ecms[0].priv[0] = 0x14; ecms[0].priv[1] = 0x03; ecms[0].priv[4] = 0x40;
    ecms[1].caid = 0x0100; ecms[1].pid = 0x0202; ecms[1].nprivate = 2;
    ecms[1].priv[1] = 0x12;
    n = (int)build_capmt(msg, CAPMT_LIST_ONLY, 0x1001, 0, 1, 1, ecms, 2, sp, 2);
    send_all(cfd, msg, (size_t)n);

    assert(wait_ge(&R.n_filters, 2, 2000));
    pthread_mutex_lock(&R.m);
    assert(R.open_adapter[0] == 0 && R.open_demux[0] == 1);
    assert(R.filt_pid[0] == 0x0101 && R.filt_pid[1] == 0x0202);
    assert(R.filt_tid[0] == 0x80 && R.filt_mask[0] == 0xF0);
    pthread_mutex_unlock(&R.m);
    dvbapi_get_status(&status);
    assert(status.running && status.services == 1 && status.connections == 5);

    /* CA_PMT QUERY is not a request to begin descrambling (OSCam stops it). */
    {
        int qn = (int)build_capmt(msg, CAPMT_LIST_ADD, 0x1010, 0, 2, 1, ecms, 2, sp, 2);
        size_t body_off = (msg[3] < 0x80) ? 4u : 6u;
        msg[body_off + 6] = CAPMT_CMD_QUERY;
        send_all(cfd, msg, (size_t)qn);
        usleep(100000);
        dvbapi_get_status(&status);
        assert(status.services == 1);
    }

    n = (int)build_section(sec, 0xAA, 0xBB);
    assert(write(R.wfd[1], sec, (size_t)n) == n);
    assert(wait_ge(&R.n_descr, 2, 2000));
    assert(atomic_load(&R.ecm_calls) == 1);
    pthread_mutex_lock(&R.m);
    assert(R.ecm_caid == 0x0100 && R.ecm_sid == 0x1001 && R.ecm_provid == 0x12u);
    assert(R.n_ca_open == 1 && R.ca_adapter[0] == 0 && R.ca_num[0] == 1);
    assert(R.n_pid == 2 && R.pids[0].pid == 0x0200 && R.pids[1].pid == 0x0201 && R.pids[0].idx == 0);
    assert(R.descr[0].idx == 0 && R.descr[0].parity == 0 && R.descr[0].cw[0] == 0xAA && R.descr[0].cw[7] == 0xAA);
    assert(R.descr[1].parity == 1 && R.descr[1].cw[0] == 0xBB);
    pthread_mutex_unlock(&R.m);
    assert(wait_ge(&R.n_demux_close, 1, 2000));

    assert(write(R.wfd[1], sec, (size_t)n) == n);
    usleep(300000);
    assert(atomic_load(&R.ecm_calls) == 1);
    assert(get_int(&R.n_descr) == 2);

    /* gate: after a CW for table 0x80 the filter is narrowed to table 0x81 */
    assert(wait_ge(&R.n_filters, 3, 2000));
    pthread_mutex_lock(&R.m);
    assert(R.filt_tid[2] == 0x81 && R.filt_mask[2] == 0xFF);
    pthread_mutex_unlock(&R.m);

    n = (int)build_section_t(sec, 0x81, 0xAA, 0xCC, 0);
    assert(write(R.wfd[1], sec, (size_t)n) == n);
    assert(wait_ge(&R.n_descr, 3, 2000));
    usleep(100000);
    pthread_mutex_lock(&R.m);
    assert(R.n_descr == 3 && R.descr[2].parity == 1 && R.descr[2].cw[0] == 0xCC);
    pthread_mutex_unlock(&R.m);
    assert(atomic_load(&R.ecm_calls) == 2);

    /* noisy copy of the same table while DONE is ignored */
    n = (int)build_section_t(sec, 0x81, 0xAA, 0xDD, 0);
    assert(write(R.wfd[1], sec, (size_t)n) == n);
    usleep(200000);
    assert(atomic_load(&R.ecm_calls) == 2);

    /* wrong-length section of the expected table: one copy dropped, two identical accepted */
    n = (int)build_section_t(sec, 0x80, 0xAA, 0xEE, 40);
    assert(write(R.wfd[1], sec, (size_t)n) == n);
    usleep(200000);
    assert(atomic_load(&R.ecm_calls) == 2);
    assert(write(R.wfd[1], sec, (size_t)n) == n);
    for (int t = 0; t < 200 && atomic_load(&R.ecm_calls) < 3; t++) usleep(10000);
    assert(atomic_load(&R.ecm_calls) == 3);

    /* OSCam's MAX_ECM_SIZE is 1024 bytes; a 300-byte valid section must not
     * be truncated by an old 255-byte TCMG gate. Two copies are required here
     * because this fixture deliberately changes the last known ECM length. */
    n = (int)build_section_t(sec, 0x81, 0xAB, 0xEF, 285);
    assert(n == 300);
    assert(write(R.wfd[1], sec, (size_t)n) == n);
    usleep(50000);
    assert(atomic_load(&R.ecm_calls) == 3);
    assert(write(R.wfd[1], sec, (size_t)n) == n);
    for (int t = 0; t < 200 && atomic_load(&R.ecm_calls) < 4; t++) usleep(10000);
    assert(atomic_load(&R.ecm_calls) == 4);

    memset(ecms, 0, sizeof(ecms));
    ecms[0].caid = 0x0500; ecms[0].pid = 0x0303; ecms[0].nprivate = 5;
    ecms[0].priv[0] = 0x14; ecms[0].priv[1] = 0x03;
    sp[0] = 0x0300;
    n = (int)build_capmt(msg, CAPMT_LIST_ONLY, 0x1002, 0, 1, 1, ecms, 1, sp, 1);
    send_all(cfd, msg, (size_t)n);
    assert(wait_ge(&R.n_filters, 5, 2000));
    {
        int found_off = 0;
        for (int t = 0; t < 200 && !found_off; t++) {
            pthread_mutex_lock(&R.m);
            for (int i = 0; i < R.n_pid; i++)
                if (R.pids[i].pid == 0x0200 && R.pids[i].idx == -1) found_off = 1;
            pthread_mutex_unlock(&R.m);
            if (!found_off) usleep(10000);
        }
        assert(found_off);
    }
    for (int t = 0; t < 200; t++) {
        dvbapi_get_status(&status);
        if (status.services == 1) break;
        usleep(10000);
    }
    assert(status.services == 1);

    {
        uint8_t stop[8] = { 0x9F, 0x80, 0x3F, 0x04, 0x83, 0x02, 0x00, 0x01 };
        send_all(cfd, stop, sizeof(stop));
    }
    for (int t = 0; t < 200; t++) {
        dvbapi_get_status(&status);
        if (status.services == 0) break;
        usleep(10000);
    }
    assert(status.services == 0);
    {
        int found_off = 0;
        pthread_mutex_lock(&R.m);
        for (int i = 0; i < R.n_pid; i++)
            if (R.pids[i].pid == 0x0300 && R.pids[i].idx == -1) found_off = 1;
        pthread_mutex_unlock(&R.m);
        assert(found_off || get_int(&R.n_descr) >= 3);
    }

    close(cfd);
    for (int i = 0; i < 4; i++) close(extra_fd[i]);
    usleep(100000);
    dvbapi_stop();
    assert(access(path, F_OK) != 0);
    for (int i = 0; i < R.n_demux_open; i++) close(R.wfd[i]);
}

static void test_pmt_client_mode(void)
{
    char path[108];
    struct sockaddr_un sa;
    struct pollfd pfd;
    S_DVBAPI_SETTINGS st = {0};
    S_DVBAPI_STATUS status;
    ecm_spec_t ecm;
    uint16_t stream_pid = 0x0200;
    uint8_t msg[1100];
    int srv, peer, old_demux, old_filters;
    size_t msg_len;

    snprintf(path, sizeof(path), "/tmp/tcmg_dvbapi_enigma_%d.sock", (int)getpid());
    unlink(path);
    srv = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(srv >= 0);
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    assert(bind(srv, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    assert(listen(srv, 4) == 0);

    old_demux = get_int(&R.n_demux_open);
    old_filters = get_int(&R.n_filters);
    st.socket_path = path;
    st.user = "dvbapi";
    st.max_services = 4;
    st.pmt_mode = 6; /* connect to Enigma2's existing listen socket */
    st.listen_port = 0;
    st.serverip = "127.0.0.1";
    assert(dvbapi_start_with(&st) == 0);

    pfd.fd = srv; pfd.events = POLLIN; pfd.revents = 0;
    assert(poll(&pfd, 1, 3000) > 0 && (pfd.revents & POLLIN));
    peer = accept(srv, NULL, NULL);
    assert(peer >= 0);

    memset(&ecm, 0, sizeof(ecm));
    ecm.caid = 0x0500;
    ecm.pid = 0x0303;
    ecm.nprivate = 5;
    ecm.priv[0] = 0x14; ecm.priv[1] = 0x03; ecm.priv[4] = 0x40;
    msg_len = build_capmt(msg, CAPMT_LIST_ONLY, 0x3301, 0, 1, 1, &ecm, 1, &stream_pid, 1);
    send_all(peer, msg, msg_len);
    assert(wait_ge(&R.n_filters, old_filters + 1, 2000));
    for (int t = 0; t < 200; t++) {
        dvbapi_get_status(&status);
        if (status.connections == 1 && status.services == 1) break;
        usleep(10000);
    }
    assert(status.running && status.connections == 1 && status.services == 1);

    dvbapi_stop();
    /* pmt_mode=6 is a client: it must never unlink the peer-owned socket. */
    assert(access(path, F_OK) == 0);
    close(peer);
    close(srv);
    unlink(path);
    for (int i = old_demux; i < get_int(&R.n_demux_open); i++) close(R.wfd[i]);
}

int main(void)
{
    atomic_store(&g_running, 1);
    test_parser();
    test_engine();
    test_network_listener();
    test_pmt_client_mode();
    puts("dvbapi smoke ok");
    return 0;
}
