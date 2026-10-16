#define MODULE_LOG_PREFIX "conf"
#include "config.h"
#include "../security/antishare.h"
#include "../core/config_state.h"
#include "../core/client_state.h"
#include "../core/utils.h"
#include "account/account.h"
#include "stats/account_stats.h"
#include "../log/log.h"
#include "config_internal.h"

static bool cfg_load_file(const char *global_file, S_CONFIG *cfg, char *err, size_t errsz)
{
    char user_file[CFGPATH_LEN];
    char reader_file[CFGPATH_LEN];

    if (!global_file || !*global_file) {
        snprintf(err, errsz, "missing configuration path");
        return false;
    }

    if (access(global_file, F_OK) != 0) {
        snprintf(err, errsz, "%s: %s", global_file, strerror(errno));
        return false;
    }

    cfg_default_runtime(cfg);
    tcmg_strlcpy(cfg->config_file, global_file, sizeof(cfg->config_file));
    cfg_path_sibling(user_file, sizeof(user_file), global_file, TCMG_USER_FILE);
    cfg_path_sibling(reader_file, sizeof(reader_file), global_file, TCMG_SERVER_FILE);
    tcmg_strlcpy(cfg->user_file, user_file, sizeof(cfg->user_file));
    tcmg_strlcpy(cfg->server_file, reader_file, sizeof(cfg->server_file));

    if (!cfg_parse_file(global_file, cfg_global_cb, cfg, err, errsz)) return false;
    if (!cfg_parse_users(user_file, cfg, err, errsz)) return false;
    if (!cfg_parse_readers(reader_file, cfg, err, errsz)) return false;
    if (!cfg_validate(cfg, err, errsz)) return false;

    return true;
}

bool cfg_load(const char *file, S_CONFIG *cfg)
{
    char err[256] = "";

    if (!file || !cfg) return false;

    if (!cfg_load_file(file, cfg, err, sizeof(err))) {
        tcmg_log("error: %s", err);
        return false;
    }
    return true;
}

bool cfg_reload(const char *file, char *err, size_t esz)
{
    S_CONFIG next;
    S_ACCOUNT *old_accounts;

    if (!file || !*file || !err || esz == 0) return false;
    err[0] = '\0';
    pthread_mutex_lock(&g_cfg_transition_mtx);

    memset(&next, 0, sizeof(next));
    if (pthread_rwlock_init(&next.acc_lock, NULL) != 0) {
        snprintf(err, esz, "cannot initialize temporary account lock");
        pthread_mutex_unlock(&g_cfg_transition_mtx);
        return false;
    }
    if (pthread_mutex_init(&next.ban_lock, NULL) != 0) {
        pthread_rwlock_destroy(&next.acc_lock);
        snprintf(err, esz, "cannot initialize temporary ban lock");
        pthread_mutex_unlock(&g_cfg_transition_mtx);
        return false;
    }

    if (!cfg_load_file(file, &next, err, esz)) {
        cfg_accounts_free(&next);
        pthread_rwlock_destroy(&next.acc_lock);
        pthread_mutex_destroy(&next.ban_lock);
        pthread_mutex_unlock(&g_cfg_transition_mtx);
        return false;
    }

    if (cfg_listener_settings_changed(&g_cfg, &next, err, esz)) {
        cfg_accounts_free(&next);
        pthread_rwlock_destroy(&next.acc_lock);
        pthread_mutex_destroy(&next.ban_lock);
        pthread_mutex_unlock(&g_cfg_transition_mtx);
        return false;
    }

    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    for (S_ACCOUNT *new_acc = next.accounts; new_acc; new_acc = new_acc->next) {
        for (S_ACCOUNT *old_acc = g_cfg.accounts; old_acc; old_acc = old_acc->next) {
            if (strcmp(new_acc->user, old_acc->user) != 0) continue;

            account_stats_copy_runtime(new_acc, old_acc);
            antishare_copy_runtime(new_acc, old_acc);
            break;
        }
    }
    pthread_rwlock_unlock(&g_cfg.acc_lock);

    pthread_mutex_lock(&g_clients_mtx);
    pthread_rwlock_wrlock(&g_cfg.acc_lock);

    old_accounts = g_cfg.accounts;
    g_cfg.accounts = next.accounts;
    next.accounts = NULL;
    g_cfg.naccounts = next.naccounts;

    g_cfg.sock_timeout = next.sock_timeout;
    g_cfg.server_keepalive = next.server_keepalive;
    g_cfg.server_keepalive_misses = next.server_keepalive_misses;
    g_cfg.ecm_log = next.ecm_log;
    g_cfg.cccam_port = next.cccam_port;
    tcmg_strlcpy(g_cfg.cccam_bindaddr, next.cccam_bindaddr, sizeof(g_cfg.cccam_bindaddr));
    g_cfg.cs378x_port = next.cs378x_port;
    tcmg_strlcpy(g_cfg.cs378x_bindaddr, next.cs378x_bindaddr, sizeof(g_cfg.cs378x_bindaddr));
    g_cfg.camd35_port = next.camd35_port;
    tcmg_strlcpy(g_cfg.camd35_bindaddr, next.camd35_bindaddr, sizeof(g_cfg.camd35_bindaddr));
    g_cfg.newcamd_port = next.newcamd_port;
    tcmg_strlcpy(g_cfg.newcamd_bindaddr, next.newcamd_bindaddr, sizeof(g_cfg.newcamd_bindaddr));
    memcpy(g_cfg.newcamd_key, next.newcamd_key, sizeof(g_cfg.newcamd_key));
    g_cfg.newcamd_keepalive = next.newcamd_keepalive;
    g_cfg.newcamd_mgclient = next.newcamd_mgclient;
    g_cfg.webif_enabled = next.webif_enabled;
    g_cfg.webif_port = next.webif_port;
    g_cfg.webif_refresh = next.webif_refresh;
    tcmg_strlcpy(g_cfg.webif_user, next.webif_user, sizeof(g_cfg.webif_user));
    tcmg_strlcpy(g_cfg.webif_pass, next.webif_pass, sizeof(g_cfg.webif_pass));
    tcmg_strlcpy(g_cfg.webif_bindaddr, next.webif_bindaddr, sizeof(g_cfg.webif_bindaddr));
    g_cfg.failban_enabled = next.failban_enabled;
    tcmg_strlcpy(g_cfg.failban_allowlist, next.failban_allowlist, sizeof(g_cfg.failban_allowlist));
    g_cfg.failban_max_fails = next.failban_max_fails;
    g_cfg.failban_ban_secs = next.failban_ban_secs;
    tcmg_strlcpy(g_cfg.logfile, next.logfile, sizeof(g_cfg.logfile));
    tcmg_strlcpy(g_cfg.usrfile, next.usrfile, sizeof(g_cfg.usrfile));
    memcpy(g_cfg.readers, next.readers, sizeof(g_cfg.readers));
    g_cfg.nreaders = next.nreaders;
    tcmg_strlcpy(g_cfg.config_file, next.config_file, sizeof(g_cfg.config_file));
    tcmg_strlcpy(g_cfg.user_file, next.user_file, sizeof(g_cfg.user_file));
    tcmg_strlcpy(g_cfg.server_file, next.server_file, sizeof(g_cfg.server_file));

    for (int i = 0; i < MAX_ACTIVE_CLIENTS; i++) {
        S_CLIENT *client = g_clients[i];
        S_ACCOUNT *replacement = NULL;

        if (!client) continue;
        char client_user[CFGKEY_LEN];
        pthread_mutex_lock(&client->state_mtx);
        tcmg_strlcpy(client_user, client->identity.user, sizeof(client_user));
        pthread_mutex_unlock(&client->state_mtx);
        if (!client_user[0]) continue;
        for (S_ACCOUNT *a = g_cfg.accounts; a; a = a->next) {
            if (strcmp(client_user, a->user) == 0) {
                replacement = a;
                break;
            }
        }
        if (replacement) {
            account_session_rebind(client, replacement);
        } else {
            client->session.kill_flag = 1;
        }
    }

    pthread_rwlock_unlock(&g_cfg.acc_lock);
    pthread_mutex_unlock(&g_clients_mtx);

    while (old_accounts) {
        S_ACCOUNT *next_old = old_accounts->next;
        old_accounts->next = NULL;
        account_retire(old_accounts);
        old_accounts = next_old;
    }

    pthread_rwlock_destroy(&next.acc_lock);
    pthread_mutex_destroy(&next.ban_lock);

    log_ecm_set(g_cfg.ecm_log);
    log_set_file(g_cfg.logfile[0] ? g_cfg.logfile : NULL);
    log_set_usrfile(g_cfg.usrfile[0] ? g_cfg.usrfile : NULL);
    account_reap_retired();

    tcmg_log("reload: accounts=%d readers=%d", g_cfg.naccounts, g_cfg.nreaders);
    pthread_mutex_unlock(&g_cfg_transition_mtx);
    return true;
}

void cfg_print(const S_CONFIG *c)
{
    int disabled = 0;

    if (!c) return;
    for (const S_ACCOUNT *a = c->accounts; a; a = a->next) {
        if (!a->enabled) disabled++;
    }

    tcmg_log("files: global=%s users=%s readers=%s",
             c->config_file, c->user_file, c->server_file);
    tcmg_log("readers=%d accounts=%d disabled=%d",
             c->nreaders, c->naccounts, disabled);
    tcmg_log("network: newcamd=%d cccam=%d cs378x=%d camd35-udp=%d webif=%d",
             c->newcamd_port, c->cccam_port, c->cs378x_port, c->camd35_port,
             c->webif_enabled ? c->webif_port : 0);
    if (c->dvbapi_enabled)
        tcmg_log("dvbapi: enabled socket=%s user=%s boxtype=%s",
                 c->dvbapi_socket, c->dvbapi_user, c->dvbapi_boxtype);
}

const char *cfg_client_name(uint16_t id)
{
    static const struct {
        uint16_t id;
        const char *name;
    } table[] = {
        {0x0665, "rq-sssp-CS"},
        {0x0666, "rqcamd"},
        {0x414C, "AlexCS"},
        {0x4333, "camd3"},
        {0x4343, "CCcam"},
        {0x4453, "DiabloCam"},
        {0x4543, "eyetvCamd"},
        {0x4765, "Octagon"},
        {0x6502, "Tvheadend"},
        {0x6576, "evocamd"},
        {0x6D63, "mpcs"},
        {0x6D67, "mgcamd"},
        {0x6E73, "NewCS"},
        {0x7264, "radegast"},
        {0x7363, "Scam"},
        {0x7878, "tsdecrypt"},
        {0x8888, "oscam"},
        {0x9911, "ACamd"},
        {0, NULL}
    };

    for (int i = 0; table[i].name; i++) {
        if (table[i].id == id) return table[i].name;
    }
    return "unknown";
}
