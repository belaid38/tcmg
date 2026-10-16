#define MODULE_LOG_PREFIX "cccam"
#include "net/net.h"
#include "crypto/crypto.h"
#include "log/log.h"
#include "core/utils.h"
#include "cccam.h"
#include "proto/cccam.h"
#include "proto/cccam_crypto.h"

#define CC_READER_MAX_MSG 2048
#define CC_READER_CARD_MAX 64

typedef struct {
    pthread_mutex_t mtx;
    int fd;
    uint8_t g_flag;
    uint8_t node_id[8];
    uint8_t peer_node_id[8];
    uint32_t card_ids[CC_READER_CARD_MAX];
    uint16_t card_caids[CC_READER_CARD_MAX];
    int card_count;
    char signature[CFGVAL_LEN + CFGKEY_LEN * 2];
    S_CC_CRYPT send_block;
    S_CC_CRYPT recv_block;
} S_CC_READER_STATE;

static S_CC_READER_STATE s_cc[MAX_READERS];
static pthread_once_t s_cc_once = PTHREAD_ONCE_INIT;

static void cc_reader_init_once(void)
{
    for (int i = 0; i < MAX_READERS; i++) {
        pthread_mutex_init(&s_cc[i].mtx, NULL);
        s_cc[i].fd = -1;
    }
}

static void cc_close_locked(S_CC_READER_STATE *s)
{
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
    s->g_flag = 0;
    memset(s->node_id, 0, sizeof(s->node_id));
    memset(s->peer_node_id, 0, sizeof(s->peer_node_id));
    memset(s->card_ids, 0, sizeof(s->card_ids));
    memset(s->card_caids, 0, sizeof(s->card_caids));
    s->card_count = 0;
    s->signature[0] = '\0';
    secure_zero(&s->send_block, sizeof(s->send_block));
    secure_zero(&s->recv_block, sizeof(s->recv_block));
}

static void cc_signature(const S_READER *r, char *out, size_t out_len)
{
    if (!out || out_len == 0) return;
    out[0] = '\0';
    char blob[2048];
    int n = snprintf(blob, sizeof(blob), "%s\x1F%s\x1F%s\x1F%s\x1F%s\x1F%d",
                     r->device, r->user, r->password, r->label,
                     r->protocol, r->inactivitytimeout);
    if (n < 0 || (size_t)n >= sizeof(blob)) return;
    uint8_t h[20];
    sha1_hash((const uint8_t *)blob, (size_t)n, h);
    if (out_len >= 41) {
        static const char hex[] = "0123456789ABCDEF";
        for (size_t i = 0; i < sizeof(h); i++) {
            out[i * 2] = hex[h[i] >> 4];
            out[i * 2 + 1] = hex[h[i] & 0x0F];
        }
        out[40] = '\0';
    }
    secure_zero(h, sizeof(h));
    secure_zero(blob, sizeof(blob));
}

static int connect_host(const char *host, uint16_t port, int timeout_s)
{
    char service[8];
    snprintf(service, sizeof(service), "%u", (unsigned)port);
    struct addrinfo hints, *ai = NULL, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
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

static int cc_send_raw(S_CC_READER_STATE *s, const uint8_t *buf, int len)
{
    uint8_t tmp[CC_READER_MAX_MSG + 32];
    if (len < 0 || len > (int)sizeof(tmp)) return -1;
    memcpy(tmp, buf, (size_t)len);
    cccam_crypto_crypt(&s->send_block, tmp, (size_t)len, true);
    int rc = net_send_all(s->fd, tmp, len);
    secure_zero(tmp, sizeof(tmp));
    return rc == len ? 0 : -1;
}

static int cc_send_msg(S_CC_READER_STATE *s, uint8_t cmd, const uint8_t *payload, uint16_t plen)
{
    uint8_t buf[CC_READER_MAX_MSG + 4];
    if (plen > CC_READER_MAX_MSG) return -1;
    buf[0] = s->g_flag;
    buf[1] = cmd;
    buf[2] = (uint8_t)(plen >> 8);
    buf[3] = (uint8_t)plen;
    if (plen) memcpy(buf + 4, payload, plen);
    return cc_send_raw(s, buf, 4 + plen);
}

static int cc_recv_raw(S_CC_READER_STATE *s, uint8_t *buf, int len)
{
    if (len <= 0 || len > CC_READER_MAX_MSG + 32) return -1;
    if (net_recv_all(s->fd, buf, len) != len) return -1;
    cccam_crypto_crypt(&s->recv_block, buf, (size_t)len, false);
    return 0;
}

static int cc_recv_msg(S_CC_READER_STATE *s, uint8_t *cmd, uint8_t *buf, uint16_t *plen)
{
    uint8_t hdr[4];
    if (cc_recv_raw(s, hdr, 4) < 0) return -1;
    uint16_t len = (uint16_t)(((uint16_t)hdr[2] << 8) | hdr[3]);
    if (len > CC_READER_MAX_MSG) return -1;
    s->g_flag = hdr[0];
    *cmd = hdr[1];
    *plen = len;
    if (len && cc_recv_raw(s, buf, len) < 0) return -1;
    return 0;
}

static void cc_cw_crypt(S_CC_READER_STATE *s, uint8_t *cw, uint32_t card_id)
{
    cccam_crypto_cw(cw, card_id, s->node_id);
}

static void add_card(S_CC_READER_STATE *s, uint32_t card_id, uint16_t caid)
{
    for (int i = 0; i < s->card_count; i++) {
        if (s->card_ids[i] == card_id) {
            s->card_caids[i] = caid;
            return;
        }
    }
    if (s->card_count >= CC_READER_CARD_MAX) return;
    s->card_ids[s->card_count] = card_id;
    s->card_caids[s->card_count] = caid;
    s->card_count++;
}

static void consume_message(S_CC_READER_STATE *s, uint8_t cmd, const uint8_t *payload, uint16_t plen)
{
    if (cmd == CCCAM_CMD_NEW_CARD && plen >= 10) {
        uint32_t card_id = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                           ((uint32_t)payload[2] << 8) | payload[3];
        uint16_t caid = (uint16_t)(((uint16_t)payload[8] << 8) | payload[9]);
        add_card(s, card_id, caid);
    } else if (cmd == CCCAM_CMD_CARD_REM && plen >= 4) {
        uint32_t card_id = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                           ((uint32_t)payload[2] << 8) | payload[3];
        for (int i = 0; i < s->card_count; i++) if (s->card_ids[i] == card_id) {
            memmove(&s->card_ids[i], &s->card_ids[i + 1], (size_t)(s->card_count - i - 1) * sizeof(s->card_ids[0]));
            memmove(&s->card_caids[i], &s->card_caids[i + 1], (size_t)(s->card_count - i - 1) * sizeof(s->card_caids[0]));
            s->card_count--;
            break;
        }
    }
}

static int find_card(const S_CC_READER_STATE *s, uint16_t caid, uint32_t *card_id)
{
    for (int i = 0; i < s->card_count; i++) {
        if (s->card_caids[i] == caid) {
            *card_id = s->card_ids[i];
            return 0;
        }
    }
    return -1;
}

static int pump_cards(S_CC_READER_STATE *s, int wait_ms)
{
    int total = 0;
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s->fd, &rfds);
        struct timeval tv;
        tv.tv_sec = wait_ms / 1000;
        tv.tv_usec = (wait_ms % 1000) * 1000;
        int rc = select(s->fd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) break;
        uint8_t cmd, payload[CC_READER_MAX_MSG]; uint16_t plen;
        if (cc_recv_msg(s, &cmd, payload, &plen) < 0) return -1;
        if (cmd == CCCAM_CMD_KEEPALIVE) {
            if (cc_send_msg(s, CCCAM_CMD_KEEPALIVE, NULL, 0) < 0) return -1;
            continue;
        }
        consume_message(s, cmd, payload, plen);
        total++;
        wait_ms = 25;
    }
    return total;
}

static int cc_connect_locked(S_CC_READER_STATE *s, const S_READER *r, int index)
{
    char sig[sizeof(s->signature)];
    cc_signature(r, sig, sizeof(sig));
    if (s->fd >= 0 && strcmp(s->signature, sig) == 0) return 0;
    cc_close_locked(s);

    char host[CFGVAL_LEN]; uint16_t port;
    if (net_parse_host_port(r->device, host, sizeof(host), &port) < 0) return -1;
    int fd = connect_host(host, port, r->inactivitytimeout);
    if (fd < 0) return -1;
    s->fd = fd;

    uint8_t seed[16], xseed[16], hash[20], dec_seed[16], hash_buf[20];
    if (net_recv_all(s->fd, seed, sizeof(seed)) != (int)sizeof(seed)) goto fail;
    memcpy(xseed, seed, sizeof(xseed));
    cccam_crypto_seed_xor(xseed);
    sha1_hash(xseed, sizeof(xseed), hash);

    cccam_crypto_init(&s->recv_block, hash, 20);
    memcpy(dec_seed, xseed, sizeof(dec_seed));
    cccam_crypto_crypt(&s->recv_block, dec_seed, sizeof(dec_seed), false);
    cccam_crypto_init(&s->send_block, dec_seed, 16);

    memcpy(hash_buf, hash, sizeof(hash_buf));
    cccam_crypto_crypt(&s->send_block, hash_buf, sizeof(hash_buf), false);
    if (cc_send_raw(s, hash_buf, 20) < 0) goto fail;

    uint8_t user[20];
    memset(user, 0, sizeof(user));
    {
        size_t ulen = strlen(r->user);
        if (ulen > sizeof(user)) ulen = sizeof(user);
        memcpy(user, r->user, ulen);
    }
    if (cc_send_raw(s, user, sizeof(user)) < 0) goto fail;

    if (r->password[0]) {
        uint8_t pw[CFGKEY_LEN]; size_t pwlen = strlen(r->password);
        if (pwlen > sizeof(pw)) pwlen = sizeof(pw);
        memcpy(pw, r->password, pwlen);
        cccam_crypto_crypt(&s->send_block, pw, pwlen, true);
        secure_zero(pw, sizeof(pw));
    }

    uint8_t ccstr[6] = {'C','C','c','a','m',0};
    if (cc_send_raw(s, ccstr, 6) < 0) goto fail;

    uint8_t ack[20];
    if (net_recv_all(s->fd, ack, sizeof(ack)) != (int)sizeof(ack)) goto fail;
    cccam_crypto_crypt(&s->recv_block, ack, sizeof(ack), false);
    if (memcmp(ack, "CCcam", 5) != 0) goto fail;

    csprng(s->node_id, sizeof(s->node_id));
    uint8_t cli[93]; memset(cli, 0, sizeof(cli));
    memcpy(cli, user, 20);
    memcpy(cli + 20, s->node_id, 8);
    cli[28] = 0;
    memcpy(cli + 29, "2.3.0", 5);
    memcpy(cli + 61, "3367", 4);
    if (cc_send_msg(s, CCCAM_CMD_CLI_DATA, cli, sizeof(cli)) < 0) goto fail;

    for (int n = 0; n < 3; n++) {
        uint8_t cmd, payload[CC_READER_MAX_MSG]; uint16_t plen;
        if (cc_recv_msg(s, &cmd, payload, &plen) < 0) goto fail;
        if (cmd == CCCAM_CMD_SRV_DATA && plen >= 8) memcpy(s->peer_node_id, payload, 8);
        else consume_message(s, cmd, payload, plen);
        if (cmd == CCCAM_CMD_SRV_DATA) {
            if (cc_send_msg(s, CCCAM_CMD_CLI_DATA, NULL, 0) < 0) goto fail;
            break;
        }
    }

    (void)pump_cards(s, 150);
    tcmg_strlcpy(s->signature, sig, sizeof(s->signature));
    tcmg_dump_dbg(D_CCCAM, s->node_id, 8, "reader[%d] local node", index);
    tcmg_dump_dbg(D_CCCAM, s->peer_node_id, 8, "reader[%d] server node", index);
    tcmg_log_dbg(D_CCCAM, "reader[%d] connected label='%s' server=%s", index, r->label, r->device);
    secure_zero(seed, sizeof(seed)); secure_zero(xseed, sizeof(xseed)); secure_zero(hash, sizeof(hash));
    secure_zero(dec_seed, sizeof(dec_seed)); secure_zero(hash_buf, sizeof(hash_buf)); secure_zero(user, sizeof(user));
    secure_zero(ack, sizeof(ack)); secure_zero(cli, sizeof(cli));
    return 0;

fail:
    secure_zero(seed, sizeof(seed)); secure_zero(xseed, sizeof(xseed)); secure_zero(hash, sizeof(hash));
    secure_zero(dec_seed, sizeof(dec_seed)); secure_zero(hash_buf, sizeof(hash_buf)); secure_zero(user, sizeof(user));
    secure_zero(ack, sizeof(ack));
    cc_close_locked(s);
    return -1;
}

int32_t cccam_reader_do_ecm(int index, const S_READER *reader,
                            uint16_t caid, uint16_t sid, uint32_t provid,
                            const uint8_t *ecm, int32_t ecm_len,
                            uint8_t cw[CW_LEN])
{
    if (!reader || !ecm || !cw || index < 0 || index >= MAX_READERS || ecm_len <= 0 || ecm_len > TCMG_MAX_ECM_SIZE)
        return -1;
    if (!reader->enabled || strcasecmp(reader->protocol, "cccam") != 0) return -2;

    pthread_once(&s_cc_once, cc_reader_init_once);
    S_CC_READER_STATE *s = &s_cc[index];
    pthread_mutex_lock(&s->mtx);
    if (cc_connect_locked(s, reader, index) < 0) {
        pthread_mutex_unlock(&s->mtx);
        return -3;
    }

    uint32_t card_id = 0;
    if (find_card(s, caid, &card_id) < 0) (void)pump_cards(s, 100);
    if (find_card(s, caid, &card_id) < 0) {
        pthread_mutex_unlock(&s->mtx);
        return -4;
    }

    uint8_t payload[13 + TCMG_MAX_ECM_SIZE];
    payload[0] = (uint8_t)(caid >> 8); payload[1] = (uint8_t)caid;
    payload[2] = (uint8_t)(provid >> 24); payload[3] = (uint8_t)(provid >> 16);
    payload[4] = (uint8_t)(provid >> 8); payload[5] = (uint8_t)provid;
    payload[6] = (uint8_t)(card_id >> 24); payload[7] = (uint8_t)(card_id >> 16);
    payload[8] = (uint8_t)(card_id >> 8); payload[9] = (uint8_t)card_id;
    payload[10] = (uint8_t)(sid >> 8); payload[11] = (uint8_t)sid;
    payload[12] = (uint8_t)ecm_len;
    memcpy(payload + 13, ecm, (size_t)ecm_len);

    if (cc_send_msg(s, CCCAM_CMD_ECM_REQ, payload, (uint16_t)(13 + ecm_len)) < 0) {
        cc_close_locked(s);
        pthread_mutex_unlock(&s->mtx);
        return -5;
    }

    uint8_t cmd, rsp[CC_READER_MAX_MSG]; uint16_t plen;
    for (;;) {
        if (cc_recv_msg(s, &cmd, rsp, &plen) < 0) {
            cc_close_locked(s);
            pthread_mutex_unlock(&s->mtx);
            return -6;
        }
        if (cmd == CCCAM_CMD_KEEPALIVE) {
            if (cc_send_msg(s, CCCAM_CMD_KEEPALIVE, NULL, 0) < 0) { cc_close_locked(s); pthread_mutex_unlock(&s->mtx); return -7; }
            continue;
        }
        if (cmd == CCCAM_CMD_NEW_CARD || cmd == CCCAM_CMD_CARD_REM) {
            consume_message(s, cmd, rsp, plen);
            continue;
        }
        break;
    }

    if (cmd == CCCAM_CMD_ECM_NOK1 || cmd == CCCAM_CMD_ECM_NOK2) {

        pthread_mutex_unlock(&s->mtx);
        return -9;
    }
    if (cmd != CCCAM_CMD_ECM_REQ || plen < CW_LEN) {
        pthread_mutex_unlock(&s->mtx);
        return -8;
    }
    tcmg_dump_dbg(D_CCCAM, rsp, CW_LEN, "reader[%d] wire-decoded CW card=%08X", index, card_id);
    memcpy(cw, rsp, CW_LEN);
    cc_cw_crypt(s, cw, card_id);
    tcmg_dump_dbg(D_CCCAM, cw, CW_LEN, "reader[%d] after cw_crypt card=%08X", index, card_id);

    uint8_t state_step[CW_LEN];
    memcpy(state_step, cw, CW_LEN);
    cccam_crypto_crypt(&s->recv_block, state_step, CW_LEN, true);
    secure_zero(state_step, sizeof(state_step));
    pthread_mutex_unlock(&s->mtx);
    tcmg_log_dbg(D_ECM, "reader[%d] ECM success label='%s' caid=%04X sid=%04X", index, reader->label, caid, sid);
    return 0;
}

void cccam_reader_shutdown(void)
{
    pthread_once(&s_cc_once, cc_reader_init_once);
    for (int i = 0; i < MAX_READERS; i++) {
        pthread_mutex_lock(&s_cc[i].mtx);
        cc_close_locked(&s_cc[i]);
        pthread_mutex_unlock(&s_cc[i].mtx);
        pthread_mutex_destroy(&s_cc[i].mtx);
    }
}
