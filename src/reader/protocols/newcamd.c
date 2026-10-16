#define MODULE_LOG_PREFIX "newcamd"
#include "net/net.h"
#include "crypto/crypto.h"
#include "crypto/newcamd_des.h"
#include "log/log.h"
#include "core/utils.h"
#include "newcamd.h"
#include "../reader_signature.h"
#include "proto/newcamd.h"

#define MG_READER_CLIENT_ID 0x7878

typedef struct {
    pthread_mutex_t mtx;
    int             fd;
    int8_t          connected;
    uint16_t        msg_id;
    S_CLIENT        nc;
    char            signature[CFGVAL_LEN + CFGKEY_LEN * 2];
} S_MG_READER_STATE;

static S_MG_READER_STATE s_mg[MAX_READERS];
static pthread_once_t s_mg_once = PTHREAD_ONCE_INIT;

static void mg_reader_init_once(void)
{
    for (int i = 0; i < MAX_READERS; i++) {
        pthread_mutex_init(&s_mg[i].mtx, NULL);
        s_mg[i].fd = -1;
    }
}



static void mg_close_locked(S_MG_READER_STATE *s)
{
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
    s->connected = 0;
    s->msg_id = 0;
    secure_zero(&s->nc, sizeof(s->nc));
    s->nc.session.fd = -1;
}

static int mg_tcp_connect(S_MG_READER_STATE *s, const char *host, uint16_t port, int timeout_s)
{
    char service[8];
    snprintf(service, sizeof(service), "%u", (unsigned)port);
    struct addrinfo hints, *ai = NULL, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, service, &hints, &ai) != 0) return -1;

    int fd = -1;
    for (p = ai; p; p = p->ai_next) {
        fd = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        net_set_timeout(fd, timeout_s);
        net_tune_socket(fd);
        if (connect(fd, p->ai_addr, (socklen_t)p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(ai);
    if (fd < 0) return -1;

    memset(&s->nc, 0, sizeof(s->nc));
    s->fd = fd;
    s->nc.session.fd = fd;
    s->nc.ecm.caid = 0;
    s->nc.identity.client_id = MG_READER_CLIENT_ID;
    tcmg_strlcpy(s->nc.identity.ip, host, sizeof(s->nc.identity.ip));
    return 0;
}

static int mg_login(S_MG_READER_STATE *s, const S_READER *r, uint16_t proto)
{
    uint8_t rnd[14], key16[16];
    uint8_t login[256], card_req[3] = { MSG_CARD_DATA_REQ, 0x00, 0x00 };
    uint8_t data[NC_MSG_MAX];
    uint16_t sid, mid, caid_hdr;
    uint32_t pid;
    int32_t dlen;
    int rc = -1;
    char passwdcrypt[64] = {0};
    size_t ulen, plen;

    if (net_recv_all(s->fd, rnd, 14) != 14) return -1;

    s->nc.protocol.wire.newcamd.is_mgcamd = (strcasecmp(r->protocol, "mgcamd") == 0) ? 1 : 0;
    s->nc.protocol.wire.newcamd.client_mode = 1;
    tcmg_ncd_des_login_key_get(rnd, r->newcamd_key, 14, key16);
    memcpy(s->nc.protocol.wire.newcamd.key1, key16, 8);
    memcpy(s->nc.protocol.wire.newcamd.key2, key16 + 8, 8);
    s->nc.protocol.wire.newcamd.proto = proto;
    s->nc.protocol.wire.newcamd.client_mode = 1;
    secure_zero(rnd, sizeof(rnd));
    secure_zero(key16, sizeof(key16));

    if (!crypt_md5_crypt(r->password, "$1$abcdefgh$", passwdcrypt, sizeof(passwdcrypt)))
        goto out;

    ulen = strlen(r->user) + 1;
    plen = strlen(passwdcrypt) + 1;
    if (3 + ulen + plen > sizeof(login)) goto out;

    login[0] = MSG_CLIENT_LOGIN;
    login[1] = 0;
    login[2] = (uint8_t)(ulen + plen);
    memcpy(login + 3, r->user, ulen);
    memcpy(login + 3 + ulen, passwdcrypt, plen);

    s->nc.ecm.caid = 0;
    s->msg_id = 0;
    uint16_t login_sid = s->nc.protocol.wire.newcamd.is_mgcamd ? 0x6D67 : 0x8888;
    uint16_t login_mid = ++s->msg_id;
    if (login_mid == 0) login_mid = ++s->msg_id;
    if (nc_send(&s->nc, login, (int32_t)(3 + ulen + plen), login_sid, login_mid, 0) <= 0) goto out;

    dlen = nc_recv(&s->nc, data, &sid, &mid, &pid, &caid_hdr);
    if (dlen != 3 || data[0] != MSG_CLIENT_LOGIN_ACK) goto out;

    tcmg_ncd_des_login_key_get(r->newcamd_key, (const uint8_t *)passwdcrypt,
                               (int)strlen(passwdcrypt), key16);
    memcpy(s->nc.protocol.wire.newcamd.key1, key16, 8);
    memcpy(s->nc.protocol.wire.newcamd.key2, key16 + 8, 8);
    secure_zero(key16, sizeof(key16));

    uint16_t card_mid = ++s->msg_id;
    if (card_mid == 0) card_mid = ++s->msg_id;
    if (nc_send(&s->nc, card_req, sizeof(card_req), 0, card_mid, 0) <= 0) goto out;

    dlen = nc_recv(&s->nc, data, &sid, &mid, &pid, &caid_hdr);
    if (mid != card_mid) goto out;
    if (dlen < 6 || data[0] != MSG_CARD_DATA) goto out;

    s->nc.ecm.caid = be16(data + 4);
    s->connected = 1;
    tcmg_log("mgcamd reader[%s] connected server=%s caid=%04X",
             r->label, r->device, s->nc.ecm.caid);
    rc = 0;

out:
    secure_zero(passwdcrypt, sizeof(passwdcrypt));
    secure_zero(key16, sizeof(key16));
    return rc;
}

static int mg_connect_locked(S_MG_READER_STATE *s, const S_READER *r)
{
    char sig[sizeof(s->signature)];
    reader_session_signature(r, sig, sizeof(sig));
    if (s->connected && s->fd >= 0 && strcmp(s->signature, sig) == 0) return 0;
    mg_close_locked(s);

    char host[CFGVAL_LEN];
    uint16_t port;
    if (net_parse_host_port(r->device, host, sizeof(host), &port) < 0) return -1;

    int timeout = r->inactivitytimeout > 0 ? r->inactivitytimeout : 5;
    const uint16_t protos[] = { NCD_PROTO_525, NCD_PROTO_524 };
    size_t proto_count = (strcasecmp(r->protocol, "newcamd") == 0) ? 2u : 1u;

    for (size_t i = 0; i < proto_count; i++) {
        mg_close_locked(s);
        if (mg_tcp_connect(s, host, port, timeout) < 0) continue;
        if (mg_login(s, r, protos[i]) == 0) {
            tcmg_strlcpy(s->signature, sig, sizeof(s->signature));
            return 0;
        }
    }

    tcmg_log("mgcamd reader[%s] login failed server=%s user='%s'",
             r->label, r->device, r->user);
    mg_close_locked(s);
    return -1;
}

int32_t newcamd_reader_do_ecm(int index, const S_READER *reader,
                             uint16_t caid, uint16_t sid, uint32_t provid,
                             const uint8_t *ecm, int32_t ecm_len,
                             uint8_t cw[CW_LEN])
{
    if (!reader || !ecm || !cw || index < 0 || index >= MAX_READERS ||
        ecm_len <= 0 || ecm_len > TCMG_MAX_ECM_SIZE)
        return -1;
    if (!reader->enabled ||
        (strcasecmp(reader->protocol, "mgcamd") != 0 &&
         strcasecmp(reader->protocol, "newcamd") != 0))
        return -2;

    pthread_once(&s_mg_once, mg_reader_init_once);
    S_MG_READER_STATE *s = &s_mg[index];
    int32_t rc = -1;

    pthread_mutex_lock(&s->mtx);

    if (mg_connect_locked(s, reader) < 0) {
        pthread_mutex_unlock(&s->mtx);
        return -3;
    }

    s->nc.ecm.caid = caid;
    uint16_t mid = ++s->msg_id;
    if (mid == 0) mid = ++s->msg_id;

    if (nc_send(&s->nc, ecm, ecm_len, sid, mid, provid) <= 0)
        goto reconnect;

    {
        uint8_t data[NC_MSG_MAX];
        uint16_t rsid, rmid, rcaid;
        uint32_t rpid;
        for (;;) {
            int32_t dlen = nc_recv(&s->nc, data, &rsid, &rmid, &rpid, &rcaid);
            if (dlen == 3 && data[0] == MSG_ADDCARD) {

                tcmg_log_dbg(D_NEWCAMD, "mgcamd reader[%d] consumed ADDCARD mid=%04X",
                             index, rmid);
                continue;
            }
            if (dlen == 19 && data[0] >= MSG_ECM_0 && data[0] <= MSG_ECM_1 && rmid == mid) {
                memcpy(cw, data + 3, CW_LEN);
                rc = 0;
                goto out;
            }
            if (dlen == 3 && data[0] >= MSG_ECM_0 && data[0] <= MSG_ECM_1 && rmid == mid) {
                rc = -4;
                goto out;
            }
            break;
        }
    }

reconnect:
    mg_close_locked(s);
    rc = -5;

out:
    pthread_mutex_unlock(&s->mtx);
    if (rc == 0)
        tcmg_log_dbg(D_ECM, "mgcamd reader[%d] ECM success label='%s' caid=%04X sid=%04X",
                     index, reader->label, caid, sid);
    else
        tcmg_log_dbg(D_ECM, "mgcamd reader[%d] ECM failed label='%s' caid=%04X sid=%04X rc=%d",
                     index, reader->label, caid, sid, rc);
    return rc;
}

void newcamd_reader_shutdown(void)
{
    pthread_once(&s_mg_once, mg_reader_init_once);
    for (int i = 0; i < MAX_READERS; i++) {
        pthread_mutex_lock(&s_mg[i].mtx);
        mg_close_locked(&s_mg[i]);
        pthread_mutex_unlock(&s_mg[i].mtx);
        pthread_mutex_destroy(&s_mg[i].mtx);
    }
}
