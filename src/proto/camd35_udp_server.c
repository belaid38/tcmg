#define MODULE_LOG_PREFIX "camd35"
#include "camd35_udp_server.h"
#include "camd35.h"
#include "core/config_state.h"
#include "core/runtime_state.h"
#include "core/constants.h"
#include "core/utils.h"
#include "platform/platform.h"
#include "log/log.h"
#include "crypto/crypto.h"
#include "crypto/aes128.h"
#include "security/failban.h"
#include "account/account.h"
#include "account/account_state.h"
#include "ecm/ecm.h"
#include "session/session.h"
#include "server.h"

#define CAMD35_UDP_IDLE_SECS 300
#define CAMD35_UDP_PACKET_MAX (CS378X_UCRC_LEN + CS378X_MAX_CRYPT)

typedef struct {
    bool in_use;
    struct sockaddr_in peer;
    uint8_t ucrc[CS378X_UCRC_LEN];
    uint8_t key[16];
    time_t last_activity;
    S_CLIENT client;
} S_CAMD35_UDP_CLIENT;

typedef struct {
    int fd;
    pthread_t thread;
    _Atomic int32_t running;
} S_CAMD35_UDP_SERVER;

static S_CAMD35_UDP_SERVER s_udp = { .fd = -1 };
static S_CAMD35_UDP_CLIENT s_clients[MAX_CONNS];

static bool peer_equal(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_family == b->sin_family && a->sin_addr.s_addr == b->sin_addr.s_addr &&
           a->sin_port == b->sin_port;
}

static void peer_ip(const struct sockaddr_in *peer, char ip[MAXIPLEN])
{
    if (!inet_ntop(AF_INET, &peer->sin_addr, ip, MAXIPLEN)) ip[0] = '\0';
    ip[MAXIPLEN - 1] = '\0';
}

static S_ACCOUNT *find_account_by_ucrc(const uint8_t ucrc[CS378X_UCRC_LEN])
{
    S_ACCOUNT *found = NULL;
    account_state_read_lock();
    for (S_ACCOUNT *a = account_state_list_locked(); a; a = a->next) {
        uint8_t check[CS378X_UCRC_LEN];
        cs378x_user_crc(a->user, check);
        if (memcmp(check, ucrc, CS378X_UCRC_LEN) == 0) {
            account_retain(a);
            found = a;
            break;
        }
    }
    account_state_read_unlock();
    return found;
}

static void client_dispose(S_CAMD35_UDP_CLIENT *entry)
{
    if (!entry || !entry->in_use) return;
    session_cleanup(&entry->client);
    secure_zero(entry->key, sizeof(entry->key));
    secure_zero(entry->ucrc, sizeof(entry->ucrc));
    memset(&entry->peer, 0, sizeof(entry->peer));
    entry->last_activity = 0;
    entry->in_use = false;
}

static S_CAMD35_UDP_CLIENT *client_find(const struct sockaddr_in *peer,
                                         const uint8_t ucrc[CS378X_UCRC_LEN])
{
    for (size_t i = 0; i < MAX_CONNS; ++i) {
        S_CAMD35_UDP_CLIENT *entry = &s_clients[i];
        if (entry->in_use && peer_equal(&entry->peer, peer) &&
            memcmp(entry->ucrc, ucrc, CS378X_UCRC_LEN) == 0)
            return entry;
    }
    return NULL;
}

static S_CAMD35_UDP_CLIENT *client_create(const struct sockaddr_in *peer,
                                           const uint8_t ucrc[CS378X_UCRC_LEN])
{
    char ip[MAXIPLEN];
    S_ACCOUNT *account;
    S_CAMD35_UDP_CLIENT *entry = NULL;
    int active;

    peer_ip(peer, ip);
    if (ban_is_banned(ip)) return NULL;
    account = find_account_by_ucrc(ucrc);
    if (!account) {
        bool banned = ban_record_fail(ip);
        tcmg_log_dbg(D_CONN, "%s CAMD35-UDP AUTH failed: unknown_account%s", ip,
                     banned ? " failban=triggered" : "");
        return NULL;
    }
    T_ACCOUNT_STATUS status = account_validate(account, ip);
    if (status != ACCOUNT_OK) {
        tcmg_log_dbg(D_CONN, "%s CAMD35-UDP AUTH rejected: user='%s' status=%d",
                     ip, account->user, status);
        account_release(account);
        return NULL;
    }

    for (size_t i = 0; i < MAX_CONNS; ++i) {
        if (!s_clients[i].in_use) { entry = &s_clients[i]; break; }
    }
    if (!entry) {
        account_release(account);
        return NULL;
    }

    active = atomic_fetch_add(&g_active_conns, 1);
    if (active >= MAX_CONNS) {
        atomic_fetch_sub(&g_active_conns, 1);
        account_release(account);
        return NULL;
    }

    memset(entry, 0, sizeof(*entry));
    T_SESSION_INPUT input = { -1, ip };
    session_init(&entry->client, &input, "camd35");
    if (account_session_open(&entry->client, account) < 0) {
        account_release(account);
        session_cleanup(&entry->client);
        return NULL;
    }

    entry->peer = *peer;
    memcpy(entry->ucrc, ucrc, CS378X_UCRC_LEN);
    cs378x_password_key(account->pass, entry->key);
    memcpy(entry->client.protocol.wire.cs378x.ucrc, ucrc, CS378X_UCRC_LEN);
    memcpy(entry->client.protocol.wire.cs378x.key, entry->key, sizeof(entry->key));
    pthread_mutex_lock(&entry->client.state_mtx);
    entry->client.ecm.caid = account_default_caid(account);
    tcmg_strlcpy(entry->client.identity.user, account->user,
                 sizeof(entry->client.identity.user));
    tcmg_strlcpy(entry->client.identity.client_name, "CAMD35-UDP",
                 sizeof(entry->client.identity.client_name));
    pthread_mutex_unlock(&entry->client.state_mtx);
    account_mark_login(account, ip);
    ban_record_ok(ip);
    entry->last_activity = time(NULL);
    entry->in_use = true;
    tcmg_log_dbg(D_CONN, "%s CAMD35-UDP AUTH success user='%s'", ip,
                 entry->client.identity.user);
    return entry;
}

static int udp_send_plain(S_CAMD35_UDP_CLIENT *entry,
                          const struct sockaddr_in *peer,
                          const uint8_t *plain, size_t plain_len)
{
    uint8_t frame[CAMD35_UDP_PACKET_MAX];
    size_t frame_len = 0;
    if (cs378x_build_frame(entry->ucrc, entry->key, plain, plain_len,
                           frame, sizeof(frame), &frame_len) < 0) return -1;
    ssize_t sent = sendto(s_udp.fd, frame, frame_len, 0,
                          (const struct sockaddr *)peer, sizeof(*peer));
    return sent == (ssize_t)frame_len ? 0 : -1;
}

static void udp_send_error(S_CAMD35_UDP_CLIENT *entry,
                           const struct sockaddr_in *peer)
{
    uint8_t response[CS378X_HEADER_LEN] = {0};
    response[0] = CS378X_CMD_ERROR;
    (void)udp_send_plain(entry, peer, response, sizeof(response));
}

static void udp_process_ecm(S_CAMD35_UDP_CLIENT *entry,
                            const struct sockaddr_in *peer,
                            const uint8_t *plain, size_t plain_len,
                            size_t ecm_len)
{
    uint16_t sid = (uint16_t)(((uint16_t)plain[8] << 8) | plain[9]);
    uint16_t caid = (uint16_t)(((uint16_t)plain[10] << 8) | plain[11]);
    uint32_t provid = ((uint32_t)plain[12] << 24) | ((uint32_t)plain[13] << 16) |
                      ((uint32_t)plain[14] << 8) | plain[15];
    uint8_t cw[CW_LEN] = {0};
    S_ECM_RESULT result;
    T_ECM_ACCESS_STATUS access;
    uint8_t response[CS378X_HEADER_LEN + CW_LEN] = {0};

    if (plain_len != CS378X_HEADER_LEN + ecm_len || ecm_len > TCMG_MAX_ECM_SIZE) {
        udp_send_error(entry, peer);
        return;
    }
    int32_t normalized_len = (int32_t)ecm_len;
    if (!ecm_prepare_input(caid, &provid, plain + CS378X_HEADER_LEN, &normalized_len)) {
        udp_send_error(entry, peer);
        return;
    }
    ecm_len = (size_t)normalized_len;

    access = ecm_access(&entry->client, caid, sid, provid);
    if (access != ECM_ACCESS_OK) {
        tcmg_log_dbg(D_ECM, "%s CAMD35-UDP ECM denied user='%s' caid=%04X sid=%04X reason=%d",
                     entry->client.identity.ip, entry->client.identity.user,
                     caid, sid, access);
        udp_send_error(entry, peer);
        return;
    }

    if (ecm_process(&entry->client, caid, sid, provid,
                    plain + CS378X_HEADER_LEN, (int32_t)ecm_len, cw, &result) < 0) {
        udp_send_error(entry, peer);
        secure_zero(cw, sizeof(cw));
        return;
    }

    response[0] = CS378X_CMD_ECM_RSP;
    response[1] = CW_LEN;
    memcpy(response + 2, plain + 2, 18);
    memcpy(response + CS378X_HEADER_LEN, cw, CW_LEN);
    (void)udp_send_plain(entry, peer, response, sizeof(response));
    secure_zero(cw, sizeof(cw));
}

static void udp_handle_packet(const uint8_t *packet, size_t packet_len,
                              const struct sockaddr_in *peer)
{
    char ip[MAXIPLEN];
    S_CAMD35_UDP_CLIENT *entry;
    uint8_t plain[CS378X_MAX_CRYPT];
    size_t crypt_len, data_len = 0, plain_len = 0;
    uint32_t expected_crc, actual_crc;

    if (packet_len < CS378X_UCRC_LEN + CS378X_BLOCK_LEN ||
        packet_len > CAMD35_UDP_PACKET_MAX) return;
    crypt_len = packet_len - CS378X_UCRC_LEN;
    if ((crypt_len % CS378X_BLOCK_LEN) != 0 || crypt_len > sizeof(plain)) return;

    entry = client_find(peer, packet);
    if (!entry) entry = client_create(peer, packet);
    if (!entry) return;

    memcpy(plain, packet + CS378X_UCRC_LEN, crypt_len);
    aes128_ecb_decrypt(entry->key, plain, crypt_len);
    if (cs378x_payload_info(plain, crypt_len, &data_len, &plain_len) < 0 ||
        plain_len > crypt_len || ((plain_len + 15U) & ~((size_t)15U)) != crypt_len) {
        udp_send_error(entry, peer);
        return;
    }

    expected_crc = ((uint32_t)plain[4] << 24) | ((uint32_t)plain[5] << 16) |
                   ((uint32_t)plain[6] << 8) | plain[7];
    actual_crc = cs378x_crc32(plain + CS378X_HEADER_LEN, data_len);
    if (expected_crc != actual_crc) {
        peer_ip(peer, ip);
        tcmg_log_dbg(D_WIRE, "%s CAMD35-UDP CRC mismatch", ip);
        return;
    }

    entry->last_activity = time(NULL);
    entry->client.session.last_activity = entry->last_activity;
    if (plain[0] == CS378X_CMD_ECM_REQ) {
        if (plain_len < CS378X_HEADER_LEN + 3 || data_len < 3 ||
            data_len > TCMG_MAX_ECM_SIZE) {
            udp_send_error(entry, peer);
            return;
        }
        udp_process_ecm(entry, peer, plain, plain_len, data_len);
    } else if (plain[0] == CS378X_CMD_KEEPALIVE) {
        uint8_t response[CS378X_HEADER_LEN + 1] = {0};
        response[0] = CS378X_CMD_KEEPALIVE;
        response[1] = 1;
        (void)udp_send_plain(entry, peer, response, sizeof(response));
    } else if (plain[0] == CS378X_CMD_STOP) {
        client_dispose(entry);
    } else {
        /* Commands that OSCam handles through other CAMD35 paths (EMM/cascade)
         * are not silently misinterpreted as ECM requests. */
        udp_send_error(entry, peer);
    }
}

static void *camd35_udp_thread(void *arg)
{
    (void)arg;
    log_set_type(LOG_TYPE_CLIENT);
    while (atomic_load(&s_udp.running) && g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s_udp.fd, &rfds);
        struct timeval tv = {0, 200000};
        int rc = select(s_udp.fd + 1, &rfds, NULL, NULL, &tv);
        if (rc > 0 && FD_ISSET(s_udp.fd, &rfds)) {
            uint8_t packet[CAMD35_UDP_PACKET_MAX + 1];
            struct sockaddr_in peer;
            socklen_t peer_len = sizeof(peer);
            ssize_t n = recvfrom(s_udp.fd, packet, sizeof(packet), 0,
                                 (struct sockaddr *)&peer, &peer_len);
            if (n > 0 && (size_t)n <= CAMD35_UDP_PACKET_MAX)
                udp_handle_packet(packet, (size_t)n, &peer);
        }
        time_t now = time(NULL);
        for (size_t i = 0; i < MAX_CONNS; ++i) {
            S_CAMD35_UDP_CLIENT *entry = &s_clients[i];
            if (entry->in_use &&
                (now - entry->last_activity > CAMD35_UDP_IDLE_SECS ||
                 session_idle_expired(&entry->client, now)))
                client_dispose(entry);
        }
    }
    for (size_t i = 0; i < MAX_CONNS; ++i) client_dispose(&s_clients[i]);
    return NULL;
}

int32_t camd35_udp_start(void)
{
    struct sockaddr_in sa;
    if (g_cfg.camd35_port <= 0) {
        tcmg_log_dbg(D_CONN, "[camd35-udp] disabled (port=0)");
        return -1;
    }
    if (s_udp.fd >= 0 || atomic_load(&s_udp.running)) return -1;

    s_udp.fd = (int)socket(AF_INET, SOCK_DGRAM, 0);
    if (s_udp.fd < 0) {
        tcmg_log("[camd35-udp] socket() failed errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    int one = 1;
    (void)setsockopt(s_udp.fd, SOL_SOCKET, SO_REUSEADDR, SO_CAST(&one), sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (g_cfg.camd35_bindaddr[0]) {
        if (inet_pton(AF_INET, g_cfg.camd35_bindaddr, &sa.sin_addr) != 1) {
            tcmg_log("[camd35-udp] invalid bind address '%s'", g_cfg.camd35_bindaddr);
            close(s_udp.fd); s_udp.fd = -1; return -1;
        }
    } else sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)g_cfg.camd35_port);
    if (bind(s_udp.fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        tcmg_log("[camd35-udp] bind() failed port=%d errno=%d (%s)",
                 g_cfg.camd35_port, errno, strerror(errno));
        close(s_udp.fd); s_udp.fd = -1; return -1;
    }
    atomic_store(&s_udp.running, 1);
    int trc = pthread_create(&s_udp.thread, NULL, camd35_udp_thread, NULL);
    if (trc != 0) {
        atomic_store(&s_udp.running, 0);
        close(s_udp.fd); s_udp.fd = -1;
        tcmg_log("[camd35-udp] failed to start listener rc=%d (%s)", trc, strerror(trc));
        return -1;
    }
    tcmg_log("[camd35-udp] listening on %s:%d",
             g_cfg.camd35_bindaddr[0] ? g_cfg.camd35_bindaddr : "*", g_cfg.camd35_port);
    return 0;
}

void camd35_udp_stop(void)
{
    if (!atomic_load(&s_udp.running)) return;
    /* The worker owns reads from fd until it exits. Join before close so the
     * descriptor cannot be reused while select()/recvfrom() still references it. */
    atomic_store(&s_udp.running, 0);
    pthread_join(s_udp.thread, NULL);
    if (s_udp.fd >= 0) close(s_udp.fd);
    s_udp.fd = -1;
    tcmg_log("[camd35-udp] stopped");
}
