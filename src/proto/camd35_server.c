#define MODULE_LOG_PREFIX "cs378x"
#include "../core/config_state.h"
#include "../config/runtime_access.h"
#include "../core/runtime_state.h"
#include "../core/utils.h"
#include "../platform/platform.h"
#include "../log/log.h"
#include "../net/net.h"
#include "../crypto/crypto.h"
#include "../security/failban.h"
#include "reader/reader.h"
#include "account/account.h"
#include "account/account_state.h"
#include "ecm/ecm.h"
#include "session/session.h"
#include "camd35.h"
#include "camd35_server.h"
#include "server.h"

static S_PROTO_SERVER s_server;

static void cs378x_send_error(S_CLIENT *cl)
{
    uint8_t plain[CS378X_HEADER_LEN];
    memset(plain, 0, sizeof(plain));
    plain[0] = CS378X_CMD_ERROR;
    (void)cs378x_send_payload(cl->session.fd, cl->protocol.wire.cs378x.ucrc, cl->protocol.wire.cs378x.key, plain, sizeof(plain));
}

static int cs378x_send_cw(S_CLIENT *cl, const uint8_t req[CS378X_HEADER_LEN], const uint8_t cw[CW_LEN])
{
    uint8_t plain[CS378X_HEADER_LEN + CW_LEN];
    memset(plain, 0, sizeof(plain));
    memcpy(plain + 2, req + 2, 18);
    plain[0] = CS378X_CMD_ECM_RSP;
    plain[1] = CW_LEN;
    memcpy(plain + CS378X_HEADER_LEN, cw, CW_LEN);
    return cs378x_send_payload(cl->session.fd, cl->protocol.wire.cs378x.ucrc, cl->protocol.wire.cs378x.key, plain, sizeof(plain));
}

static int cs378x_handle_ecm(S_CLIENT *cl, const uint8_t *plain, size_t plain_len)
{
    uint16_t sid, caid;
    uint32_t provid;
    size_t ecm_len;
    uint8_t cw[CW_LEN] = {0};
    T_ECM_ACCESS_STATUS access;
    S_ECM_RESULT result;

    if (!cl || plain_len < CS378X_HEADER_LEN + 3) return -1;
    sid = (uint16_t)(((uint16_t)plain[8] << 8) | plain[9]);
    caid = (uint16_t)(((uint16_t)plain[10] << 8) | plain[11]);
    provid = ((uint32_t)plain[12] << 24) | ((uint32_t)plain[13] << 16) |
             ((uint32_t)plain[14] << 8) | plain[15];
    ecm_len = (((size_t)plain[21] & 0x0F) << 8) | plain[22];
    ecm_len += 3;
    if (ecm_len == 0 || ecm_len > TCMG_MAX_ECM_SIZE || plain_len != CS378X_HEADER_LEN + ecm_len) return -1;
    int32_t normalized_len = (int32_t)ecm_len;
    if (!ecm_prepare_input(caid, &provid, plain + CS378X_HEADER_LEN, &normalized_len)) {
        cs378x_send_error(cl);
        return 1;
    }
    ecm_len = (size_t)normalized_len;

    access = ecm_access(cl, caid, sid, provid);
    if (access != ECM_ACCESS_OK) {
        if (access == ECM_ACCESS_CAID_DENIED)
            tcmg_log_dbg(D_ECM, "%s ECM denied: CAID %04X not allowed user='%s'",
                         cl->identity.ip, caid, cl->identity.user);
        else if (access == ECM_ACCESS_ANTISHARE)
            tcmg_log_dbg(D_ECM, "%s ECM denied: anti-share user='%s' sid=%04X",
                         cl->identity.ip, cl->identity.user, sid);
        return 1;
    }

    if (ecm_process(cl, caid, sid, provid, plain + CS378X_HEADER_LEN,
                          (int32_t)ecm_len, cw, &result) < 0) {
        cs378x_send_error(cl);
        secure_zero(cw, sizeof(cw));
        return 1;
    }

    if (cs378x_send_cw(cl, plain, cw) < 0) {
        secure_zero(cw, sizeof(cw));
        return -1;
    }
    secure_zero(cw, sizeof(cw));
    return 0;
}

static S_ACCOUNT *find_account_by_ucrc(const uint8_t ucrc[4])
{
    S_ACCOUNT *found = NULL;
    account_state_read_lock();
    for (S_ACCOUNT *a = account_state_list_locked(); a; a = a->next) {
        uint8_t u[4];
        cs378x_user_crc(a->user, u);
        if (memcmp(u, ucrc, 4) == 0) {
            account_retain(a);
            found = a;
            break;
        }
    }
    account_state_read_unlock();
    return found;
}

void *handle_cs378x_client(void *arg)
{
    S_CONN_ARGS *args = (S_CONN_ARGS *)arg;
    S_CLIENT cl;
    S_ACCOUNT *acc = NULL;
    uint8_t ucrc[4];
    {
        T_SESSION_INPUT input = { args->fd, args->ip };
        session_init(&cl, &input, "cs378x");
    }
    free(args);
    S_CONFIG_NETWORK_VIEW netcfg;
    if (!cfg_runtime_network_snapshot(&netcfg)) {
        session_cleanup(&cl);
        return NULL;
    }
    net_tune_socket(cl.session.fd);
    {
        int timeout = netcfg.sock_timeout;
        if (netcfg.server_keepalive > 0 && netcfg.server_keepalive < timeout) timeout = netcfg.server_keepalive;
        net_set_timeout(cl.session.fd, timeout);
    }

    if (ban_is_banned(cl.identity.ip)) {
        tcmg_log("%s AUTH blocked: failban", cl.identity.ip);
        goto cleanup;
    }
    int urc = cs378x_recv_ucrc(cl.session.fd, ucrc);
    if (urc != 0) goto cleanup;
    acc = find_account_by_ucrc(ucrc);
    if (!acc) {
        int banned_now = ban_record_fail(cl.identity.ip);
        tcmg_log("%s AUTH failed: unknown_account%s",
                 cl.identity.ip, banned_now ? " failban=triggered" : "");
        goto cleanup;
    }
    {
        T_ACCOUNT_STATUS status = account_validate(acc, cl.identity.ip);
        if (status != ACCOUNT_OK) {
            tcmg_log("%s AUTH rejected: account_access user='%s' status=%d",
                     cl.identity.ip, acc->user, status);
            account_release(acc);
            goto cleanup;
        }
    }
    if (account_session_open(&cl, acc) < 0) {
        tcmg_log("%s AUTH rejected: max_connections user='%s' active=%d max=%d",
                 cl.identity.ip, acc->user, (int)acc->active, acc->max_connections);
        account_release(acc);
        goto cleanup;
    }

    memcpy(cl.protocol.wire.cs378x.ucrc, ucrc, 4);
    cs378x_password_key(acc->pass, cl.protocol.wire.cs378x.key);
    pthread_mutex_lock(&cl.state_mtx);
    cl.ecm.caid = account_default_caid(acc);
    tcmg_strlcpy(cl.identity.user, acc->user, sizeof(cl.identity.user));
    tcmg_strlcpy(cl.identity.client_name, "CS378X", sizeof(cl.identity.client_name));
    pthread_mutex_unlock(&cl.state_mtx);
    account_mark_login(acc, cl.identity.ip);
    ban_record_ok(cl.identity.ip);
    tcmg_log("%s AUTH success user='%s'", cl.identity.ip, cl.identity.user);

    int ka_misses = 0;
    bool first_frame = true;
    while (g_running && !cl.session.kill_flag) {
        uint8_t frame_ucrc[CS378X_UCRC_LEN];
        int urc_frame = 0;

        if (!first_frame) urc_frame = cs378x_recv_ucrc(cl.session.fd, frame_ucrc);
        else memcpy(frame_ucrc, cl.protocol.wire.cs378x.ucrc, CS378X_UCRC_LEN);
        if (urc_frame == NET_RECV_TIMEOUT) {
            if (netcfg.server_keepalive > 0) {
                uint8_t ka[CS378X_HEADER_LEN + 1] = {0};
                ka[0] = CS378X_CMD_KEEPALIVE; ka[1] = 1;
                if (cs378x_send_payload(cl.session.fd, cl.protocol.wire.cs378x.ucrc, cl.protocol.wire.cs378x.key, ka, sizeof(ka)) < 0) break;
                if (++ka_misses >= netcfg.server_keepalive_misses) break;
                continue;
            }
            break;
        }
        if (urc_frame < 0) {
            tcmg_log_dbg(D_CONN, "%s client disconnected/read error", cl.identity.ip);
            break;
        }
        if (memcmp(frame_ucrc, cl.protocol.wire.cs378x.ucrc, CS378X_UCRC_LEN) != 0) {
            tcmg_log_dbg(D_WIRE, "%s invalid per-frame UCRC", cl.identity.ip);
            break;
        }
        first_frame = false;
        uint8_t plain[CS378X_MAX_CRYPT];
        size_t plain_len = 0;
        int rc = cs378x_recv_payload(cl.session.fd, cl.protocol.wire.cs378x.key, plain, sizeof(plain), &plain_len);
        if (rc < 0) break;
        ka_misses = 0;
        cl.session.last_activity = time(NULL);
        if (plain_len < CS378X_HEADER_LEN) break;

        switch (plain[0]) {
        case CS378X_CMD_ECM_REQ:
            if (cs378x_handle_ecm(&cl, plain, plain_len) < 0) { cs378x_send_error(&cl); goto done; }
            break;
        case CS378X_CMD_KEEPALIVE: {
            uint8_t ka[CS378X_HEADER_LEN + 1] = {0};
            ka[0] = CS378X_CMD_KEEPALIVE; ka[1] = 1;
            if (cs378x_send_payload(cl.session.fd, cl.protocol.wire.cs378x.ucrc, cl.protocol.wire.cs378x.key, ka, sizeof(ka)) < 0) goto done;
            break;
        }
        case CS378X_CMD_EMM_REQ:
        case CS378X_CMD_EMM_DATA:

            cs378x_send_error(&cl);
            break;
        case CS378X_CMD_STOP:
            break;
        default:
            cs378x_send_error(&cl);
            break;
        }
    }

done:
cleanup:
    session_cleanup(&cl);
    return NULL;
}

int32_t cs378x_start(void)
{
    return proto_server_start(&s_server, "cs378x", g_cfg.cs378x_port,
                               g_cfg.cs378x_bindaddr,
                               handle_cs378x_client);
}

void cs378x_stop(void)
{
    proto_server_stop(&s_server);
}
