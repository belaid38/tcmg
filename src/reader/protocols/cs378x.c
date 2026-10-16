#define MODULE_LOG_PREFIX "cs378x"
#include "net/net.h"
#include "crypto/crypto.h"
#include "log/log.h"
#include "core/utils.h"
#include "cs378x.h"
#include "../reader_signature.h"
#include "proto/camd35.h"

#define CS378X_READER_MAX_FRAME (CS378X_UCRC_LEN + CS378X_MAX_CRYPT)

typedef struct {
    pthread_mutex_t mtx;
    int fd;
    int connected;
    uint16_t msg_id;
    uint8_t ucrc[4];
    uint8_t key[16];
    char signature[CFGVAL_LEN + CFGKEY_LEN * 2];
} S_CS378X_READER_STATE;

static S_CS378X_READER_STATE s_cs[MAX_READERS];
static pthread_once_t s_cs_once = PTHREAD_ONCE_INIT;

static void cs_reader_init_once(void)
{
    for (int i = 0; i < MAX_READERS; i++) {
        pthread_mutex_init(&s_cs[i].mtx, NULL);
        s_cs[i].fd = -1;
    }
}



static void cs_close_locked(S_CS378X_READER_STATE *s)
{
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
    s->connected = 0;
    s->msg_id = 0;
    secure_zero(s->ucrc, sizeof(s->ucrc));
    secure_zero(s->key, sizeof(s->key));
    s->signature[0] = '\0';
}

static int cs_connect_tcp(const char *host, uint16_t port, int timeout_s)
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
    return fd;
}

static int cs_connect_locked(S_CS378X_READER_STATE *s, const S_READER *r, int index)
{
    char sig[sizeof(s->signature)], host[CFGVAL_LEN];
    uint16_t port;
    reader_session_signature(r, sig, sizeof(sig));
    if (s->connected && s->fd >= 0 && strcmp(s->signature, sig) == 0) return 0;

    cs_close_locked(s);
    if (net_parse_host_port(r->device, host, sizeof(host), &port) < 0) return -1;
    int timeout = r->inactivitytimeout > 0 ? r->inactivitytimeout : 5;
    int fd = cs_connect_tcp(host, port, timeout);
    if (fd < 0) return -1;

    s->fd = fd;
    cs378x_user_crc(r->user, s->ucrc);
    cs378x_password_key(r->password, s->key);
    tcmg_strlcpy(s->signature, sig, sizeof(s->signature));
    s->connected = 1;
    s->msg_id = 0;
    tcmg_log_dbg(D_PROTOCOL, "reader[%d] connected label='%s' server=%s user='%s'",
                 index, r->label, r->device, r->user);
    return 0;
}

static int cs_send_keepalive(S_CS378X_READER_STATE *s)
{
    uint8_t plain[CS378X_HEADER_LEN + 1];
    memset(plain, 0, sizeof(plain));
    plain[0] = CS378X_CMD_KEEPALIVE;
    plain[1] = 1;
    plain[20] = 0;
    return cs378x_send_payload(s->fd, s->ucrc, s->key, plain, sizeof(plain));
}

int32_t cs378x_reader_do_ecm(int index, const S_READER *reader,
                             uint16_t caid, uint16_t sid, uint32_t provid,
                             const uint8_t *ecm, int32_t ecm_len,
                             uint8_t cw[CW_LEN])
{
    if (!reader || !ecm || !cw || index < 0 || index >= MAX_READERS ||
        ecm_len <= 0 || ecm_len > TCMG_MAX_ECM_SIZE) return -1;
    if (!reader->enabled || strcasecmp(reader->protocol, "cs378x") != 0) return -2;

    pthread_once(&s_cs_once, cs_reader_init_once);
    S_CS378X_READER_STATE *s = &s_cs[index];
    pthread_mutex_lock(&s->mtx);

    if (cs_connect_locked(s, reader, index) < 0) {
        pthread_mutex_unlock(&s->mtx);
        return -3;
    }

    uint8_t plain[CS378X_HEADER_LEN + TCMG_MAX_ECM_SIZE];
    memset(plain, 0, sizeof(plain));
    plain[0] = CS378X_CMD_ECM_REQ;
    plain[1] = (uint8_t)ecm_len;
    plain[8]  = (uint8_t)(sid >> 8);  plain[9]  = (uint8_t)sid;
    plain[10] = (uint8_t)(caid >> 8); plain[11] = (uint8_t)caid;
    plain[12] = (uint8_t)(provid >> 24); plain[13] = (uint8_t)(provid >> 16);
    plain[14] = (uint8_t)(provid >> 8);  plain[15] = (uint8_t)provid;
    plain[16] = (uint8_t)(++s->msg_id >> 8); plain[17] = (uint8_t)s->msg_id;
    plain[18] = 0xFF; plain[19] = 0xFF;
    memcpy(plain + CS378X_HEADER_LEN, ecm, (size_t)ecm_len);

    if (cs378x_send_payload(s->fd, s->ucrc, s->key, plain,
                            CS378X_HEADER_LEN + (size_t)ecm_len) < 0) {
        cs_close_locked(s);
        pthread_mutex_unlock(&s->mtx);
        return -4;
    }

    for (;;) {
        uint8_t ucrc[4], rsp[CS378X_MAX_CRYPT], cmd;
        size_t rlen = 0;
        int rc = cs378x_recv_ucrc(s->fd, ucrc);
        if (rc < 0 || memcmp(ucrc, s->ucrc, 4) != 0) {
            cs_close_locked(s);
            pthread_mutex_unlock(&s->mtx);
            return -5;
        }
        rc = cs378x_recv_payload(s->fd, s->key, rsp, sizeof(rsp), &rlen);
        if (rc == NET_RECV_TIMEOUT) {
            cs_close_locked(s);
            pthread_mutex_unlock(&s->mtx);
            return -6;
        }
        if (rc < 0) {
            cs_close_locked(s);
            pthread_mutex_unlock(&s->mtx);
            return -7;
        }
        cmd = rsp[0];
        if (cmd == CS378X_CMD_KEEPALIVE) {
            if (cs_send_keepalive(s) < 0) {
                cs_close_locked(s);
                pthread_mutex_unlock(&s->mtx);
                return -8;
            }
            continue;
        }
        if (cmd == CS378X_CMD_ECM_RSP && rlen >= CS378X_HEADER_LEN + CW_LEN && rsp[1] == CW_LEN) {
            uint16_t rmid = (uint16_t)(((uint16_t)rsp[16] << 8) | rsp[17]);
            uint16_t rsid = (uint16_t)(((uint16_t)rsp[8] << 8) | rsp[9]);
            uint16_t rcaid = (uint16_t)(((uint16_t)rsp[10] << 8) | rsp[11]);
            if (rmid != s->msg_id || rsid != sid || rcaid != caid) {
                cs_close_locked(s);
                pthread_mutex_unlock(&s->mtx);
                return -11;
            }
            memcpy(cw, rsp + CS378X_HEADER_LEN, CW_LEN);
            pthread_mutex_unlock(&s->mtx);
            tcmg_log_dbg(D_ECM, "reader[%d] ECM success label='%s' caid=%04X sid=%04X",
                         index, reader->label, caid, sid);
            return 0;
        }
        if (cmd == CS378X_CMD_ERROR) {
            pthread_mutex_unlock(&s->mtx);
            return -9;
        }
        pthread_mutex_unlock(&s->mtx);
        return -10;
    }
}

void cs378x_reader_shutdown(void)
{
    pthread_once(&s_cs_once, cs_reader_init_once);
    for (int i = 0; i < MAX_READERS; i++) {
        pthread_mutex_lock(&s_cs[i].mtx);
        cs_close_locked(&s_cs[i]);
        pthread_mutex_unlock(&s_cs[i].mtx);
        pthread_mutex_destroy(&s_cs[i].mtx);
    }
}
