#include "stats/account_stats.h"
#define MODULE_LOG_PREFIX "cccam"
#include "../core/config_state.h"
#include "../config/runtime_access.h"
#include "../core/runtime_state.h"
#include "../core/utils.h"
#include "../platform/platform.h"
#include "../security/failban.h"
#include "../log/log.h"
#include "../net/net.h"
#include "../crypto/crypto.h"
#include "reader/reader.h"
#include "account/account.h"
#include "account/account_state.h"
#include "ecm/ecm.h"
#include "session/session.h"
#include "cccam.h"
#include "cccam_crypto.h"
#include "server.h"

static S_PROTO_SERVER s_server;

static void cc_derive_keys(S_CCCAM_CLIENT *cc, const uint8_t *seed)
{
    uint8_t xseed[CCCAM_SEED_LEN], hash[CCCAM_HASH_LEN], dec_seed[CCCAM_SEED_LEN], hash_buf[CCCAM_HASH_LEN];
    memcpy(xseed, seed, sizeof(xseed));
    cccam_crypto_seed_xor(xseed);
    sha1_hash(xseed, sizeof(xseed), hash);
    cccam_crypto_init(&cc->send_block, hash, sizeof(hash));
    memcpy(dec_seed, xseed, sizeof(dec_seed));
    cccam_crypto_crypt(&cc->send_block, dec_seed, sizeof(dec_seed), false);
    cccam_crypto_init(&cc->recv_block, dec_seed, sizeof(dec_seed));
    memcpy(hash_buf, hash, sizeof(hash_buf));
    cccam_crypto_crypt(&cc->recv_block, hash_buf, sizeof(hash_buf), false);
    secure_zero(xseed, sizeof(xseed));
    secure_zero(hash, sizeof(hash));
    secure_zero(hash_buf, sizeof(hash_buf));
    secure_zero(dec_seed, sizeof(dec_seed));
}

static int cc_send_msg(S_CCCAM_CLIENT *cc, uint8_t cmd, const uint8_t *payload, uint16_t plen)
{
    uint8_t buf[CCCAM_MSG_MAX + 4];
    if (plen > CCCAM_MSG_MAX) return -1;
    buf[0] = cc->g_flag;
    buf[1] = cmd;
    buf[2] = (uint8_t)(plen >> 8);
    buf[3] = (uint8_t)plen;
    if (plen) memcpy(buf + 4, payload, plen);
    cccam_crypto_crypt(&cc->send_block, buf, 4u + plen, true);
    return net_send_all(cc->fd, buf, 4 + (int)plen);
}

static int cc_recv_msg(S_CCCAM_CLIENT *cc, uint8_t *seq_out, uint8_t *cmd, uint8_t *buf, uint16_t *plen)
{
    uint8_t hdr[4];
    int rr = net_recv_all(cc->fd, hdr, sizeof(hdr));
    if (rr == NET_RECV_TIMEOUT) return NET_RECV_TIMEOUT;
    if (rr != (int)sizeof(hdr)) return -1;
    cccam_crypto_crypt(&cc->recv_block, hdr, sizeof(hdr), false);
    *seq_out = hdr[0];
    cc->g_flag = hdr[0];
    *cmd = hdr[1];
    const uint16_t len = (uint16_t)(((uint16_t)hdr[2] << 8) | hdr[3]);
    if (len > CCCAM_MSG_MAX) return -1;
    *plen = len;
    if (!len) return 0;
    rr = net_recv_all(cc->fd, buf, len);
    if (rr == NET_RECV_TIMEOUT) return NET_RECV_TIMEOUT;
    if (rr != (int)len) return -1;
    cccam_crypto_crypt(&cc->recv_block, buf, len, false);
    return 0;
}

static void cc_cw_crypt(S_CCCAM_CLIENT *cc, uint8_t *cw, uint32_t card_id)
{
    const uint8_t *nid = (cc->peer_node_id[0] || cc->peer_node_id[1] || cc->peer_node_id[2] ||
                          cc->peer_node_id[3] || cc->peer_node_id[4] || cc->peer_node_id[5] ||
                          cc->peer_node_id[6] || cc->peer_node_id[7]) ? cc->peer_node_id : cc->node_id;
    cccam_crypto_cw(cw, card_id, nid);
}

static int cc_send_srv_data(S_CCCAM_CLIENT *cc)
{
    uint8_t buf[0x48];
    memset(buf,0,sizeof(buf));
    csprng(cc->node_id,8);
    memcpy(buf,cc->node_id,8);
    snprintf((char*)buf+8,32,"CCcam 2.3.0");
    snprintf((char*)buf+40,7,"3291");
    return cc_send_msg(cc,CCCAM_CMD_SRV_DATA,buf,sizeof(buf));
}

static void cc_send_new_card(S_CCCAM_CLIENT *cc, uint32_t card_id, uint16_t caid,
                              const uint32_t *provids, int nprov)
{
    uint8_t  buf[21 + 7 * 32];
    int      i, n;
    uint16_t total;

    n = (nprov < 32) ? nprov : 32;
    total = (uint16_t)(21 + 7 * n);
    memset(buf, 0, total);

    buf[0]  = (uint8_t)(card_id >> 24);
    buf[1]  = (uint8_t)(card_id >> 16);
    buf[2]  = (uint8_t)(card_id >>  8);
    buf[3]  = (uint8_t)(card_id & 0xFF);
    buf[8]  = (uint8_t)(caid >> 8);
    buf[9]  = (uint8_t)(caid & 0xFF);
    buf[20] = (uint8_t)n;

    for (i = 0; i < n; i++) {
        buf[21 + i*7]     = (uint8_t)(provids[i] >> 16);
        buf[21 + i*7 + 1] = (uint8_t)(provids[i] >>  8);
        buf[21 + i*7 + 2] = (uint8_t)(provids[i] & 0xFF);
    }
    cc_send_msg(cc, CCCAM_CMD_NEW_CARD, buf, total);
}

static void cc_send_cards(S_CCCAM_CLIENT *cc, const S_ACCOUNT *acc)
{
    uint16_t caids[MAX_CAIDS_PER_ACC + (MAX_READERS * MAX_CAIDS_PER_READER)];
    uint32_t zero = 0;
    uint32_t card_id = 1;
    int32_t ncaids;
    int32_t total = 0;

    ncaids = account_collect_caids(acc, caids,
                                    (int32_t)(sizeof(caids) / sizeof(caids[0])));
    for (int32_t i = 0; i < ncaids; i++) {
        /* announce the account idents of this CAID: OSCam and CCcam only send an ECM
         * to a card whose provider list contains the provider of the request */
        uint32_t provs[32];
        int nprov = 0;
        for (int32_t k = 0; k < acc->nidents && nprov < 32; k++) {
            bool dup = false;
            if (acc->idents[k].caid != caids[i]) continue;
            for (int m = 0; m < nprov; m++) if (provs[m] == acc->idents[k].provid) dup = true;
            if (!dup) provs[nprov++] = acc->idents[k].provid;
        }
        if (nprov == 0) cc_send_new_card(cc, card_id++, caids[i], &zero, 1);
        else cc_send_new_card(cc, card_id++, caids[i], provs, nprov);
        total++;
    }

    tcmg_log_dbg(D_CCCAM, "sent %d card(s) to user='%s'", total, acc->user);
}

static S_ACCOUNT *cc_authenticate_account(S_CCCAM_CLIENT *cc,
                                          const uint8_t username[20],
                                          const uint8_t encrypted_cccam[6])
{
    if (!cc || !username || !encrypted_cccam) return NULL;

    const S_CC_CRYPT base = cc->recv_block;
    S_CC_CRYPT accepted_state;
    S_ACCOUNT *accepted = NULL;

    account_state_read_lock();
    for (S_ACCOUNT *acc = account_state_list_locked(); acc; acc = acc->next)
    {
        uint8_t acc_user[20];
        uint8_t pwd[CFGKEY_LEN];
        uint8_t check[6];
        memset(acc_user, 0, sizeof(acc_user));
        {
            size_t ulen = strlen(acc->user);
            if (ulen > sizeof(acc_user)) ulen = sizeof(acc_user);
            memcpy(acc_user, acc->user, ulen);
        }
        if (memcmp(username, acc_user, sizeof(acc_user)) != 0)
            continue;

        size_t pwlen = strlen(acc->pass);
        if (pwlen > sizeof(pwd))
            continue;
        memset(pwd, 0, sizeof(pwd));
        memcpy(pwd, acc->pass, pwlen);

        S_CC_CRYPT trial = base;
        cccam_crypto_crypt(&trial, pwd, pwlen, true);
        memcpy(check, encrypted_cccam, sizeof(check));
        cccam_crypto_crypt(&trial, check, sizeof(check), false);

        bool match = memcmp(check, "CCcam\0", sizeof(check)) == 0;
        secure_zero(check, sizeof(check));
        secure_zero(pwd, sizeof(pwd));
        secure_zero(acc_user, sizeof(acc_user));
        if (!match)
            continue;

        account_retain(acc);
        accepted = acc;
        accepted_state = trial;
        break;
    }
    account_state_read_unlock();

    if (accepted)
        cc->recv_block = accepted_state;
    return accepted;
}

static void cc_handle_ecm(S_CCCAM_CLIENT *cc, S_CLIENT *cl,
                           uint8_t req_seq, const uint8_t *p, uint16_t plen)
{
    uint8_t resp[16] = {0};
    uint8_t cw[CW_LEN] = {0};
    uint16_t caid, sid;
    uint32_t provid, card_id;
    uint16_t ecm_len;
    uint8_t declared_ecm_len;
    T_ECM_ACCESS_STATUS access;
    S_ECM_RESULT result;

    (void)req_seq;
    if (!cl || plen < 13) {
        if (cl) cc_send_msg(cc, CCCAM_CMD_ECM_NOK1, NULL, 0);
        return;
    }

    caid = (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
    provid = ((uint32_t)p[2] << 24) | ((uint32_t)p[3] << 16) |
             ((uint32_t)p[4] << 8) | p[5];
    card_id = ((uint32_t)p[6] << 24) | ((uint32_t)p[7] << 16) |
              ((uint32_t)p[8] << 8) | p[9];
    sid = (uint16_t)(((uint16_t)p[10] << 8) | p[11]);
    declared_ecm_len = p[12];
    /* OSCam derives the ECM byte count from the frame length, not p[12]. */
    ecm_len = (uint16_t)(plen - 13);
    if (ecm_len == 0 || ecm_len > TCMG_MAX_ECM_SIZE) {
        tcmg_log_dbg(D_CCCAM, "%s ECM bad frame_ecm_len=%u declared=%u plen=%u",
                     cl->identity.ip, ecm_len, declared_ecm_len, plen);
        cc_send_msg(cc, CCCAM_CMD_ECM_NOK1, NULL, 0);
        return;
    }
    if (declared_ecm_len != (uint8_t)ecm_len) {
        tcmg_log_dbg(D_CCCAM, "%s ECM length field differs: declared=%u frame=%u; using frame length",
                     cl->identity.ip, declared_ecm_len, ecm_len);
    }

    int32_t normalized_len = (int32_t)ecm_len;
    if (!ecm_prepare_input(caid, &provid, p + 13, &normalized_len)) {
        cc_send_msg(cc, CCCAM_CMD_ECM_NOK1, NULL, 0);
        secure_zero(cw, sizeof(cw));
        return;
    }
    ecm_len = (uint16_t)normalized_len;

    access = ecm_access(cl, caid, sid, provid);
    if (access != ECM_ACCESS_OK) {
        switch (access) {
        case ECM_ACCESS_CAID_DENIED:
            tcmg_log("%s ECM denied: caid=%04X not permitted for user='%s'",
                     cl->identity.ip, caid, cl->identity.user);
            break;
        case ECM_ACCESS_ANTISHARE:
            tcmg_log("%s ECM denied: anti-sharing limit triggered for user='%s' sid=%04X",
                     cl->identity.ip, cl->identity.user, sid);
            break;
        case ECM_ACCESS_DISABLED:
            tcmg_log("%s ECM denied: account disabled mid-session user='%s'",
                     cl->identity.ip, cl->identity.user);
            break;
        case ECM_ACCESS_EXPIRED: {
            S_ACCOUNT *ea = account_session_acquire(cl);
            long exp = ea ? (long)ea->expirationdate : 0L;
            tcmg_log("%s ECM denied: account expired mid-session user='%s' expired=%ld",
                     cl->identity.ip, cl->identity.user, exp);
            if (ea) account_release(ea);
            break;
        }
        default:
            break;
        }
        cc_send_msg(cc, CCCAM_CMD_ECM_NOK1, NULL, 0);
        return;
    }

    tcmg_log_dbg(D_CCCAM,
                 "%s ECM request user='%s' caid=%04X sid=%04X provid=%06X card_id=%08X ecm_len=%u channel='%s'",
                 cl->identity.ip, cl->identity.user, caid, sid, provid, card_id, ecm_len,
                 cl->ecm.last_channel[0] ? cl->ecm.last_channel : "unknown");

    if (ecm_process(cl, caid, sid, provid, p + 13, ecm_len, cw, &result) < 0) {
        cc_send_msg(cc, CCCAM_CMD_ECM_NOK1, NULL, 0);
        secure_zero(cw, sizeof(cw));
        return;
    }

    memcpy(resp, cw, CW_LEN);
    cc_cw_crypt(cc, resp, card_id);
    cc_send_msg(cc, CCCAM_CMD_ECM_REQ, resp, CW_LEN);
    tcmg_dump_dbg(D_CCCAM, cc->peer_node_id, 8,
                  "%s cw peer node card_id=%08X node", cl->identity.ip, card_id);
    tcmg_dump_dbg(D_CCCAM, cw, CW_LEN,
                  "%s CW sent to user='%s' caid=%04X sid=%04X",
                  cl->identity.ip, cl->identity.user, caid, sid);
    tcmg_log_dbg(D_CCCAM,
                 "%s ECM result=FOUND user='%s' caid=%04X sid=%04X time=%ldms cache=%d",
                 cl->identity.ip, cl->identity.user, caid, sid, (long)result.elapsed_ms,
                 result.cache_hit ? 1 : 0);
    secure_zero(cw, sizeof(cw));
    (void)result;
}

void *handle_cccam_client(void *arg)
{
    S_CONN_ARGS    *args=(S_CONN_ARGS*)arg;
    S_CCCAM_CLIENT  cc;
    S_CLIENT        cl;
    uint8_t         seed[CCCAM_SEED_LEN];
    uint8_t         cli_hash[CCCAM_HASH_LEN];
    uint8_t         username[20];
    uint8_t         ccstr_recv[6];
    uint8_t         ack[20];
    S_ACCOUNT      *acc;
    S_CONFIG_NETWORK_VIEW netcfg;
    char            user[CFGKEY_LEN];
    uint8_t         cmd,req_seq;
    uint8_t         payload[CCCAM_MSG_MAX];
    uint16_t        plen;

    memset(&cc, 0, sizeof(cc));
    {
        T_SESSION_INPUT input = { args->fd, args->ip };
        session_init(&cl, &input, "cccam");
    }
    cc.fd = cl.session.fd;
    free(args);
    if (!cfg_runtime_network_snapshot(&netcfg)) {
        session_cleanup(&cl);
        return NULL;
    }
    tcmg_log_dbg(D_CONN,"%s new connection fd=%d tid=%u",
                 cl.identity.ip, cl.session.fd, cl.identity.thread_id);

    {
        int recv_timeout = netcfg.sock_timeout;
        if (netcfg.server_keepalive > 0 && netcfg.server_keepalive < recv_timeout)
            recv_timeout = netcfg.server_keepalive;
        net_set_timeout(cc.fd, recv_timeout);
    }
    net_tune_socket(cc.fd);

    if(ban_is_banned(cl.identity.ip)){
        tcmg_log("%s AUTH blocked: failban", cl.identity.ip);
        goto cleanup;
    }

    csprng(seed,CCCAM_SEED_LEN);
    tcmg_log_dbg(D_CCCAM, "%s sending %d-byte seed", cl.identity.ip, CCCAM_SEED_LEN);
    if(net_send_all(cc.fd,seed,CCCAM_SEED_LEN)!=CCCAM_SEED_LEN) goto cleanup;

    cc_derive_keys(&cc,seed);
    secure_zero(seed,sizeof(seed));
    tcmg_log_dbg(D_CCCAM, "%s session keys derived", cl.identity.ip);

    if(net_recv_all(cc.fd,cli_hash,CCCAM_HASH_LEN)!=CCCAM_HASH_LEN) {
        tcmg_log_dbg(D_CCCAM, "%s failed to receive client hash", cl.identity.ip);
        goto cleanup;
    }
    cccam_crypto_crypt(&cc.recv_block, cli_hash, CCCAM_HASH_LEN, false);
    secure_zero(cli_hash,sizeof(cli_hash));

    if(net_recv_all(cc.fd,username,20)!=20) {
        tcmg_log_dbg(D_CCCAM, "%s failed to receive username", cl.identity.ip);
        goto cleanup;
    }
    cccam_crypto_crypt(&cc.recv_block, username, 20, false);
    memset(user,0,sizeof(user));
    memcpy(user, username, sizeof(username));
    user[sizeof(user) - 1] = '\0';

    tcmg_log_dbg(D_CCCAM, "%s LOGIN attempt user='%s'", cl.identity.ip, user);

    if(net_recv_all(cc.fd,ccstr_recv,6)!=6) {
        tcmg_log_dbg(D_CCCAM, "%s failed to receive password proof user='%s'",
                     cl.identity.ip, user);
        goto cleanup;
    }

    acc=cc_authenticate_account(&cc,username,ccstr_recv);
    secure_zero(ccstr_recv,sizeof(ccstr_recv));
    secure_zero(username,sizeof(username));

    if(!acc){
        int banned_now = ban_record_fail(cl.identity.ip);
        tcmg_log("%s AUTH failed: invalid_credentials user='%s'%s",
                 cl.identity.ip, user, banned_now ? " failban=triggered" : "");
        goto cleanup;
    }

    {
        T_ACCOUNT_STATUS status = account_validate(acc, cl.identity.ip);
        if (status != ACCOUNT_OK) {
            if (status == ACCOUNT_DISABLED)
                tcmg_log("%s AUTH rejected: account_disabled user='%s'", cl.identity.ip, acc->user);
            else if (status == ACCOUNT_EXPIRED)
                tcmg_log("%s AUTH rejected: account_expired user='%s' expired=%ld",
                         cl.identity.ip, acc->user, (long)acc->expirationdate);
            else if (status == ACCOUNT_IP_DENIED)
                tcmg_log("%s AUTH rejected: ip_not_whitelisted user='%s'", cl.identity.ip, acc->user);
            account_release(acc);
            goto cleanup;
        }
    }

    memset(ack,0,sizeof(ack));
    memcpy(ack,"CCcam",5);
    cccam_crypto_crypt(&cc.send_block, ack, 20, true);
    if(net_send_all(cc.fd,ack,20)!=20) goto cleanup;
    secure_zero(ack,sizeof(ack));

    if (account_session_open(&cl, acc) < 0) {
        tcmg_log("%s AUTH rejected: max_connections user='%s' active=%d max=%d",
                 cl.identity.ip, acc->user, (int)acc->active, acc->max_connections);
        account_release(acc);
        goto cleanup;
    }

    pthread_mutex_lock(&cl.state_mtx);
    tcmg_strlcpy(cl.identity.user, acc->user, sizeof(cl.identity.user));
    cl.ecm.caid = account_default_caid(acc);
    cl.session.last_activity = time(NULL);
    pthread_mutex_unlock(&cl.state_mtx);

    account_mark_login(acc, cl.identity.ip);
    ban_record_ok(cl.identity.ip);

    {
        uint16_t login_caids[MAX_CAIDS_PER_ACC + (MAX_READERS * MAX_CAIDS_PER_READER)];
        int32_t card_count = account_collect_caids(acc, login_caids,
                                                    (int32_t)(sizeof(login_caids) / sizeof(login_caids[0])));
        tcmg_log("%s AUTH success user='%s' cards=%d max_conn=%d",
                 cl.identity.ip, acc->user, card_count, acc->max_connections);
    }

    if (cc_send_msg(&cc,CCCAM_CMD_CLI_DATA,NULL,0) < 0) goto done;
    tcmg_log_dbg(D_CCCAM, "%s CLI_DATA ack sent to user='%s'", cl.identity.ip, acc->user);
    if (cc_send_srv_data(&cc) < 0) goto done;
    tcmg_log_dbg(D_CCCAM, "%s SRV_DATA sent to user='%s'", cl.identity.ip, acc->user);

    {
        int ready = 0;
        for (int n = 0; n < 4 && !ready; n++) {
            uint8_t rcmd, rseq; uint16_t rplen;
            int rr = cc_recv_msg(&cc, &rseq, &rcmd, payload, &rplen);
            if (rr == NET_RECV_TIMEOUT) {
                if (netcfg.server_keepalive > 0) {
                    if (cc_send_msg(&cc, CCCAM_CMD_KEEPALIVE, NULL, 0) < 0) goto done;
                    continue;
                }
                goto done;
            }
            if (rr < 0) goto done;
            if (rcmd == CCCAM_CMD_CLI_DATA) {
                if (rplen >= 28) memcpy(cc.peer_node_id, payload + 20, 8);
                ready = 1;
            } else if (rcmd == CCCAM_CMD_KEEPALIVE) {
                if (cc_send_msg(&cc, CCCAM_CMD_KEEPALIVE, NULL, 0) < 0) goto done;
            }
        }
        if (!ready) goto done;
    }
    cc_send_cards(&cc,acc);

    int ka_misses = 0;
    while(g_running&&!cl.session.kill_flag){
        if (session_idle_expired(&cl, time(NULL))) {
            time_t idle = time(NULL) - (cl.session.last_activity ? cl.session.last_activity : cl.ecm.last_ecm_time);
            S_ACCOUNT *ia = account_session_acquire(&cl);
            int max_idle = ia ? ia->max_idle : 0;
            tcmg_log("%s idle timeout %lds >= max_idle=%ds disconnecting user='%s'",
                     cl.identity.ip, (long)idle, max_idle, cl.identity.user);
            if (ia) account_release(ia);
            break;
        }

        int rr = cc_recv_msg(&cc,&req_seq,&cmd,payload,&plen);
        if(rr == NET_RECV_TIMEOUT){
            if(netcfg.server_keepalive > 0){
                if(cc_send_msg(&cc,CCCAM_CMD_KEEPALIVE,NULL,0)<0) break;
                ka_misses++;
                tcmg_log_dbg(D_CCCAM, "%s SERVER_KEEPALIVE user='%s' miss=%d/%d",
                             cl.identity.ip, cl.identity.user, ka_misses, netcfg.server_keepalive_misses);
                if(ka_misses >= netcfg.server_keepalive_misses) break;
                continue;
            }
            break;
        }
        if(rr<0){
            if (cl.identity.user[0]) {
                S_ACCOUNT_STATS_SNAPSHOT stats = {0};
                S_ACCOUNT *sa = account_session_acquire(&cl);
                bool have_stats = sa != NULL;
                if (sa) {
                    account_stats_snapshot(sa, &stats);
                    account_release(sa);
                }
                if (have_stats) {
                    tcmg_log("%s disconnected user='%s' ecm_total=%llu cw_found=%lld",
                             cl.identity.ip, cl.identity.user,
                             (unsigned long long)stats.ecm_total,
                             (long long)stats.cw_found);
                } else {
                    tcmg_log("%s disconnected user='%s' account stats unavailable",
                             cl.identity.ip, cl.identity.user);
                }
            }
            else
                tcmg_log_dbg(D_CONN, "%s disconnected (no user)", cl.identity.ip);
            break;
        }

        ka_misses = 0;
        cl.session.last_activity = time(NULL);
        tcmg_log_dbg(D_CCCAM, "%s recv cmd=0x%02X plen=%u seq=%u",
                     cl.identity.ip, cmd, plen, req_seq);

        if(cmd==CCCAM_CMD_ECM_REQ){
            cc_handle_ecm(&cc,&cl,req_seq,payload,plen);
        } else if(cmd==CCCAM_CMD_KEEPALIVE){
            tcmg_log_dbg(D_CCCAM, "%s KEEPALIVE user='%s'", cl.identity.ip, cl.identity.user);
            cc_send_msg(&cc,CCCAM_CMD_KEEPALIVE,NULL,0);
        } else if(cmd==CCCAM_CMD_CLI_DATA){
            tcmg_log_dbg(D_CCCAM, "%s CLI_DATA user='%s' plen=%u", cl.identity.ip, cl.identity.user, plen);
            if(plen>=28) memcpy(cc.peer_node_id, payload+20, 8);
            cc_send_msg(&cc,CCCAM_CMD_CLI_DATA,NULL,0);
        } else if(cmd==CCCAM_CMD_EMM_REQ){
            tcmg_log_dbg(D_CCCAM, "%s EMM_REQ user='%s' plen=%u (ignored)", cl.identity.ip, cl.identity.user, plen);
            cc_send_msg(&cc,CCCAM_CMD_EMM_REQ,NULL,0);
        } else if(cmd==0x0C||cmd==0x0D||cmd==0x0E){
            tcmg_log_dbg(D_CCCAM, "%s cmd=0x%02X user='%s' plen=%u (echo)", cl.identity.ip, cmd, cl.identity.user, plen);
            cc_send_msg(&cc,cmd,NULL,0);
        } else {
            tcmg_log_dbg(D_CCCAM, "%s unknown cmd=0x%02X plen=%u -- ignored",
                         cl.identity.ip, cmd, plen);
        }
    }

done:
cleanup:
    tcmg_log_dbg(D_CONN, "%s connection closed fd=%d tid=%u", cl.identity.ip, cl.session.fd, cl.identity.thread_id);
    session_cleanup(&cl);
    return NULL;
}

int32_t cccam_start(void)
{
    return proto_server_start(&s_server, "cccam", g_cfg.cccam_port,
                               g_cfg.cccam_bindaddr,
                               handle_cccam_client);
}

void cccam_stop(void)
{
    proto_server_stop(&s_server);
}
