#define MODULE_LOG_PREFIX "net"
#include "net.h"
#include "../crypto/crypto.h"
#include "../core/utils.h"
#include "../log/log.h"
#include "../crypto/newcamd_des.h"
#include "../account/account.h"

int32_t net_recv_all(int fd, void *buf, int32_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t total = 0;
    if (len < 0) return -1;
    const size_t want = (size_t)len;
    while (total < want)
    {
        ssize_t n = recv(fd, RECV_CAST(p + total), want - total, 0);
        if (n == 0) return -1;
        if (n < 0) {
#ifdef TCMG_OS_WINDOWS
            int e = WSAGetLastError();
            if (e == WSAEINTR) continue;
            if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK)
                return total == 0 ? NET_RECV_TIMEOUT : -1;
#else
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT)
                return total == 0 ? NET_RECV_TIMEOUT : -1;
#endif
            return -1;
        }
        total += (size_t)n;
    }
    return (int32_t)total;
}

int32_t net_send_all(int fd, const void *buf, int32_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t total = 0;
    if (len < 0) return -1;
    const size_t want = (size_t)len;
    while (total < want)
    {
        ssize_t n = send(fd, SO_CAST(p + total), want - total, 0);
        if (n < 0) {
#ifdef TCMG_OS_WINDOWS
            int e = WSAGetLastError();
            if (e == WSAEINTR) continue;
#else
            if (errno == EINTR) continue;
#endif
            return -1;
        }
        if (n == 0) return -1;
        total += (size_t)n;
    }
    return (int32_t)total;
}

int net_parse_host_port(const char *device, char *host, size_t host_len, uint16_t *port)
{
    if (!device || !*device || !host || host_len < 2 || !port) return -1;

    const char *comma = strrchr(device, ',');
    if (!comma || comma == device || !comma[1]) return -1;

    size_t host_len_in = (size_t)(comma - device);
    if (host_len_in >= host_len) return -1;

    memcpy(host, device, host_len_in);
    host[host_len_in] = '\0';

    char *end = NULL;
    errno = 0;
    long value = strtol(comma + 1, &end, 10);
    if (errno == ERANGE || !end || *end != '\0' || value < 1 || value > 65535)
        return -1;

    *port = (uint16_t)value;
    return 0;
}

void net_set_timeout(int fd, int32_t seconds)
{
#ifdef TCMG_OS_WINDOWS
    DWORD ms = (DWORD)(seconds * 1000);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, SO_CAST(&ms), sizeof(ms));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, SO_CAST(&ms), sizeof(ms));
#else
    struct timeval tv = { seconds, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, SO_CAST(&tv), sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, SO_CAST(&tv), sizeof(tv));
#endif
}

void net_tune_socket(int fd)
{
    int one = 1;
#ifdef TCP_NODELAY
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, SO_CAST(&one), sizeof(one)) < 0)
        tcmg_log_dbg(D_WIRE, "setsockopt(TCP_NODELAY) failed");
#endif
#ifdef SO_KEEPALIVE
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, SO_CAST(&one), sizeof(one));
#endif
#ifdef TCP_KEEPIDLE
    { int idle = 60, intvl = 10, cnt = 3;
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  SO_CAST(&idle),  sizeof(idle));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, SO_CAST(&intvl), sizeof(intvl));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   SO_CAST(&cnt),   sizeof(cnt)); }
#endif
    (void)one;
}

#define NCD_PROTO_UNKNOWN 0
#define NCD_PROTO_524     524
#define NCD_PROTO_525     525

static int ncd_header_size(uint16_t proto)
{
    return proto == NCD_PROTO_524 ? 8 : 12;
}

static int ncd_cmd_offset(uint16_t proto)
{
    return proto == NCD_PROTO_524 ? 8 : 12;
}

static bool ncd_valid_command(uint8_t cmd)
{
    return ((cmd & 0xF0) == 0x80) || ((cmd & 0xF0) == 0xE0) ||
           cmd == MSG_GET_VERSION || cmd == MSG_ADDCARD || cmd == MSG_KEEPALIVE;
}

static int ncd_detect_proto(const uint8_t *buf, int total_len, uint16_t *proto_out)
{
    int off525 = ncd_cmd_offset(NCD_PROTO_525);
    int off524 = ncd_cmd_offset(NCD_PROTO_524);
    bool v525 = false, v524 = false;

    if (total_len >= off525 + 3) {
        uint32_t n = ((uint32_t)(buf[off525 + 1] & 0x0F) << 8) | buf[off525 + 2];
        n += 3;
        v525 = n <= (uint32_t)(total_len - off525) && ncd_valid_command(buf[off525]);
    }
    if (total_len >= off524 + 3) {
        uint32_t n = ((uint32_t)(buf[off524 + 1] & 0x0F) << 8) | buf[off524 + 2];
        n += 3;
        v524 = n <= (uint32_t)(total_len - off524) && ncd_valid_command(buf[off524]);
    }

    if (v525) { *proto_out = NCD_PROTO_525; return 0; }
    if (v524) { *proto_out = NCD_PROTO_524; return 0; }
    return -1;
}

static void ncd_build_header(uint8_t *buf, uint16_t proto, uint16_t sid,
                             uint16_t caid, uint32_t pid, bool mg_ack,
                             bool card_data, bool header_caid)
{
    if (proto == NCD_PROTO_524) {
        memset(buf + 4, 0, 4);
        if (sid)
            wr_be16(buf + 6, sid);
        return;
    }

    memset(buf + 4, 0, 8);

    if (mg_ack) {
        buf[4] = 0x6E;
        buf[5] = 0x73;
        buf[11] = 0x14;
        return;
    }

    if (sid)
        wr_be16(buf + 4, sid);

    if (card_data || header_caid) {
        buf[6]  = (uint8_t)(caid >> 8);
        buf[7]  = (uint8_t)caid;
        buf[8]  = (uint8_t)(pid >> 16);
        buf[9]  = (uint8_t)(pid >> 8);
        buf[10] = (uint8_t)pid;
    }

    if (card_data)
        buf[11] = 0x14;
}

static int32_t ncd_send_ex(S_CLIENT *cl, const uint8_t *data, int32_t dlen,
                           uint16_t sid, uint16_t mid, uint16_t caid,
                           uint32_t pid, bool header_caid,
                           bool mg_ack, bool card_data)
{
    uint8_t *buf;
    uint8_t key16[16];
    uint16_t proto;
    int head;
    int32_t total;
    int32_t enc_len;
    int32_t cmd_len;

    if (!cl || !data || dlen < 3 || dlen > NC_MSG_MAX - 32) return -1;
    if ((dlen - 3) > 0x0FFF) return -1;
    buf = cl->protocol.wire.newcamd.send_buf;
    proto = cl->protocol.wire.newcamd.proto ? cl->protocol.wire.newcamd.proto : NCD_PROTO_525;
    head = ncd_header_size(proto);

    memset(buf, 0, sizeof(cl->protocol.wire.newcamd.send_buf));
    cmd_len = dlen - 3;
    memcpy(buf + head, data, (size_t)dlen);
    buf[head + 1] = (uint8_t)((buf[head + 1] & 0xF0) | ((cmd_len >> 8) & 0x0F));
    buf[head + 2] = (uint8_t)cmd_len;

    wr_be16(buf + 2, mid);
    ncd_build_header(buf, proto, sid,
                     caid, pid, mg_ack, card_data, header_caid);

    if (!mg_ack && !card_data && cl->protocol.wire.newcamd.is_mgcamd && proto == NCD_PROTO_525 &&
        data[0] == MSG_CLIENT_LOGIN) {
        buf[4] = 0x6D;
        buf[5] = 0x67;
        buf[11] = 0x11;
    }

    total = head + dlen;
    if (total + 24 >= (int32_t)sizeof(cl->protocol.wire.newcamd.send_buf)) return -1;
    wr_be16(buf, (uint16_t)(total - 2));

    memcpy(key16, cl->protocol.wire.newcamd.key1, 8);
    memcpy(key16 + 8, cl->protocol.wire.newcamd.key2, 8);
    enc_len = tcmg_ncd_des_encrypt(buf, total, key16);
    secure_zero(key16, sizeof(key16));
    if (enc_len < 0 || enc_len > (int32_t)sizeof(cl->protocol.wire.newcamd.send_buf)) return -1;
    wr_be16(buf, (uint16_t)(enc_len - 2));

    tcmg_dump_dbg(D_WIRE, buf, enc_len,
                  "%s [newcamd/mgcamd] send encrypted proto=%u cmd=0x%02X sid=%04X mid=%04X",
                  cl->identity.ip, (unsigned)proto, data[0], sid, mid);
    return net_send_all(cl->session.fd, buf, enc_len);
}

void nc_init(S_CLIENT *cl, const uint8_t *des_key14, int32_t timeout)
{
    uint8_t rnd[14], key16[16];

    net_set_timeout(cl->session.fd, timeout);
    net_tune_socket(cl->session.fd);
    cl->protocol.wire.newcamd.proto = NCD_PROTO_UNKNOWN;
    cl->protocol.wire.newcamd.msgid = 0;

    csprng(rnd, sizeof(rnd));
    if (net_send_all(cl->session.fd, rnd, (int32_t)sizeof(rnd)) != (int32_t)sizeof(rnd)) {
        secure_zero(rnd, sizeof(rnd));
        return;
    }

    memcpy(cl->protocol.wire.newcamd.session_key, des_key14, 14);
    tcmg_ncd_des_login_key_get(rnd, des_key14, 14, key16);
    memcpy(cl->protocol.wire.newcamd.key1, key16, 8);
    memcpy(cl->protocol.wire.newcamd.key2, key16 + 8, 8);
    secure_zero(rnd, sizeof(rnd));
    secure_zero(key16, sizeof(key16));
}

int32_t nc_recv(S_CLIENT *cl, uint8_t *data,
                uint16_t *sid, uint16_t *mid,
                uint32_t *pid, uint16_t *caid_hdr)
{
    uint8_t lenbuf[2], key16[16];
    uint16_t proto;
    uint8_t *buf;
    int32_t wire_len, total, dec_len;
    int off;
    uint32_t rlen;

    if (!cl || !data || !sid || !mid || !pid || !caid_hdr) return -1;
    buf = cl->protocol.wire.newcamd.recv_buf;
    /* A timeout before consuming any frame-header byte is recoverable and
     * lets the caller emit a protocol keepalive. Once framing has started,
     * a short header/body is fatal because the stream cannot be resynchronized. */
    int32_t header_read = net_recv_all(cl->session.fd, lenbuf, 2);
    if (header_read == NET_RECV_TIMEOUT) return NET_RECV_TIMEOUT;
    if (header_read != 2) return -1;
    wire_len = (int32_t)be16(lenbuf);
    if (wire_len < 16 || wire_len > NC_MSG_MAX - 2) return -1;

    buf[0] = lenbuf[0]; buf[1] = lenbuf[1];
    if (net_recv_all(cl->session.fd, buf + 2, wire_len) != wire_len) return -1;
    total = wire_len + 2;

    memcpy(key16, cl->protocol.wire.newcamd.key1, 8);
    memcpy(key16 + 8, cl->protocol.wire.newcamd.key2, 8);
    dec_len = tcmg_ncd_des_decrypt(buf, total, key16);
    secure_zero(key16, sizeof(key16));
    if (dec_len < 0 || dec_len > NC_MSG_MAX) return -1;
    if (dec_len < 11) return -1;

    if (!cl->protocol.wire.newcamd.proto) {
        if (ncd_detect_proto(buf, dec_len, &proto) < 0) return -1;
        cl->protocol.wire.newcamd.proto = proto;
    }
    proto = cl->protocol.wire.newcamd.proto;
    if (proto != NCD_PROTO_524 && proto != NCD_PROTO_525) return -1;

    off = ncd_cmd_offset(proto);
    if (dec_len < off + 3) return -1;

    *mid = be16(buf + 2);
    *sid = proto == NCD_PROTO_525 ? be16(buf + 4) : be16(buf + 6);
    *caid_hdr = proto == NCD_PROTO_525 ? be16(buf + 6) : 0;
    *pid = proto == NCD_PROTO_525
             ? (((uint32_t)buf[8] << 16) | ((uint32_t)buf[9] << 8) | buf[10])
             : 0;
    cl->protocol.wire.newcamd.msgid = *mid;
    memcpy(cl->protocol.wire.newcamd.header, buf + 4, proto == NCD_PROTO_525 ? 8 : 4);

    rlen = (((uint32_t)(buf[off + 1] & 0x0F) << 8) | buf[off + 2]) + 3;
    if (rlen > (uint32_t)(dec_len - off) || rlen > NC_MSG_MAX) return -1;
    memcpy(data, buf + off, rlen);

    if (data[0] == MSG_CLIENT_LOGIN && proto == NCD_PROTO_525 &&
        buf[4] == 0x6D && buf[5] == 0x67 && buf[11] == 0x11) {
        cl->protocol.wire.newcamd.is_mgcamd = 1;
    }

    tcmg_dump_dbg(D_NEWCAMD, data, (int32_t)rlen,
                  "%s [newcamd/mgcamd] recv proto=%u cmd=0x%02X sid=%04X mid=%04X caid=%04X",
                  cl->identity.ip, (unsigned)proto, data[0], *sid, *mid, *caid_hdr);
    return (int32_t)rlen;
}

int32_t nc_send(S_CLIENT *cl, const uint8_t *data, int32_t dlen,
                uint16_t sid, uint16_t mid, uint32_t pid)
{
    if (!cl || !data || dlen < 3) return -1;
    S_ACCOUNT *account = account_session_acquire(cl);
    uint16_t caid = account ? account_default_caid(account) : cl->ecm.caid;
    if (!caid) caid = cl->ecm.caid;
    bool is_ecm = data[0] == MSG_ECM_0 || data[0] == MSG_ECM_1;
    bool custom = cl->protocol.wire.newcamd.client_mode && is_ecm;
    bool mg_ack = cl->protocol.wire.newcamd.is_mgcamd && data[0] == MSG_CLIENT_LOGIN_ACK;
    bool addcard = data[0] == MSG_ADDCARD;

    int rc = ncd_send_ex(cl, data, dlen, custom ? sid : (addcard ? 0 : 0), mid,
                         caid, pid, custom, mg_ack, addcard);
    if (account) account_release(account);
    return rc;
}

int32_t nc_send_addcard(S_CLIENT *cl, uint16_t caid,
                        uint32_t provid, uint16_t mid)
{
    static const uint8_t payload[3] = { MSG_ADDCARD, 0x00, 0x00 };
    return ncd_send_ex(cl, payload, sizeof(payload), 0, mid, caid, provid,
                       true, false, true);
}

int32_t nc_send_version(S_CLIENT *cl, uint16_t mid)
{
    static const char VER[] = "1.67";
    uint8_t buf[3 + sizeof(VER)];
    memset(buf, 0, sizeof(buf));
    buf[0] = MSG_GET_VERSION;
    buf[1] = 0;
    buf[2] = (uint8_t)(sizeof(VER) - 1);
    memcpy(buf + 3, VER, sizeof(VER) - 1);
    return nc_send(cl, buf, (int32_t)sizeof(buf), 0, mid, 0);
}
