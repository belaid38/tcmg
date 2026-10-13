#define MODULE_LOG_PREFIX "webif"
#include "service.h"
#include "../../src/config/config.h"
#include "../../src/config/config_internal.h"
#include "../../src/core/config_state.h"
#include "../../src/core/runtime_state.h"
#include "../../src/reader/protocol.h"
#include <ctype.h>
#include "../../src/core/utils.h"
#include "../../src/platform/platform.h"
#include "../../src/srvid/srvid.h"
#include "../internal/proto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static pthread_mutex_t s_file_save_mtx = PTHREAD_MUTEX_INITIALIZER;
bool webif_config_snapshot(S_WEBIF_CONFIG_VIEW *out)
{
    if (!out) return false;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    memset(out, 0, sizeof(*out));
    out->webif_enabled = g_cfg.webif_enabled;
    out->newcamd_port = g_cfg.newcamd_port;
    tcmg_strlcpy(out->newcamd_bindaddr, g_cfg.newcamd_bindaddr, sizeof(out->newcamd_bindaddr));
    memcpy(out->newcamd_key, g_cfg.newcamd_key, sizeof(out->newcamd_key));
    out->newcamd_keepalive = g_cfg.newcamd_keepalive;
    out->newcamd_mgclient = g_cfg.newcamd_mgclient;
    out->cccam_port = g_cfg.cccam_port;
    out->cs378x_port = g_cfg.cs378x_port;
    tcmg_strlcpy(out->cs378x_bindaddr, g_cfg.cs378x_bindaddr, sizeof(out->cs378x_bindaddr));
    out->sock_timeout = g_cfg.sock_timeout;
    out->server_keepalive = g_cfg.server_keepalive;
    out->server_keepalive_misses = g_cfg.server_keepalive_misses;
    out->ecm_log = g_cfg.ecm_log;
    out->scheduled_restart_enabled = g_cfg.scheduled_restart_enabled;
    unsigned restart_minutes = (g_cfg.scheduled_restart_minutes >= 0 && g_cfg.scheduled_restart_minutes < 1440)
        ? (unsigned)g_cfg.scheduled_restart_minutes : 240u;
    unsigned restart_hour = restart_minutes / 60u;
    unsigned restart_minute = restart_minutes % 60u;
    out->scheduled_restart_time[0] = (char)('0' + (restart_hour / 10u));
    out->scheduled_restart_time[1] = (char)('0' + (restart_hour % 10u));
    out->scheduled_restart_time[2] = ':';
    out->scheduled_restart_time[3] = (char)('0' + (restart_minute / 10u));
    out->scheduled_restart_time[4] = (char)('0' + (restart_minute % 10u));
    out->scheduled_restart_time[5] = '\0';
    tcmg_strlcpy(out->logfile, g_cfg.logfile, sizeof(out->logfile));
    out->webif_port = g_cfg.webif_port;
    out->webif_refresh = g_cfg.webif_refresh;
    tcmg_strlcpy(out->webif_user, g_cfg.webif_user, sizeof(out->webif_user));
    tcmg_strlcpy(out->webif_pass, g_cfg.webif_pass, sizeof(out->webif_pass));
    tcmg_strlcpy(out->webif_bindaddr, g_cfg.webif_bindaddr, sizeof(out->webif_bindaddr));
    out->failban_enabled = g_cfg.failban_enabled;
    tcmg_strlcpy(out->failban_allowlist, g_cfg.failban_allowlist, sizeof(out->failban_allowlist));
    out->failban_max_fails = g_cfg.failban_max_fails;
    out->failban_ban_secs = g_cfg.failban_ban_secs;
    tcmg_strlcpy(out->seller_name, g_cfg.seller_name, sizeof(out->seller_name));
    tcmg_strlcpy(out->seller_type, g_cfg.seller_type, sizeof(out->seller_type));
    tcmg_strlcpy(out->seller_host, g_cfg.seller_host, sizeof(out->seller_host));
    out->seller_port = g_cfg.seller_port;
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return true;
}

bool webif_config_apply(const S_WEBIF_CONFIG_PATCH *p, bool *restart_required)
{
    if (!p) return false;
    if (restart_required) *restart_required = false;

    pthread_mutex_lock(&g_cfg_transition_mtx);
    pthread_rwlock_wrlock(&g_cfg.acc_lock);
    int old_webif_enabled = g_cfg.webif_enabled;
    int old_webif_port = g_cfg.webif_port;
    char old_webif_bindaddr[MAXIPLEN];
    char old_newcamd_bindaddr[MAXIPLEN];
    char old_cccam_bindaddr[MAXIPLEN];
    char old_cs378x_bindaddr[MAXIPLEN];
    tcmg_strlcpy(old_webif_bindaddr, g_cfg.webif_bindaddr, sizeof(old_webif_bindaddr));
    tcmg_strlcpy(old_newcamd_bindaddr, g_cfg.newcamd_bindaddr, sizeof(old_newcamd_bindaddr));
    tcmg_strlcpy(old_cccam_bindaddr, g_cfg.cccam_bindaddr, sizeof(old_cccam_bindaddr));
    tcmg_strlcpy(old_cs378x_bindaddr, g_cfg.cs378x_bindaddr, sizeof(old_cs378x_bindaddr));
    int old_newcamd_port = g_cfg.newcamd_port;
    int old_newcamd_keepalive = g_cfg.newcamd_keepalive;
    int old_newcamd_mgclient = g_cfg.newcamd_mgclient;
    int old_cccam_port = g_cfg.cccam_port;
    int old_cs378x_port = g_cfg.cs378x_port;
    int old_sock_timeout = g_cfg.sock_timeout;
    int old_server_keepalive = g_cfg.server_keepalive;
    int old_server_keepalive_misses = g_cfg.server_keepalive_misses;
    int old_ecm_log = g_cfg.ecm_log;
    int old_sched_enabled = g_cfg.scheduled_restart_enabled;
    int old_sched_minutes = g_cfg.scheduled_restart_minutes;
    int old_webif_refresh = g_cfg.webif_refresh;
    char old_webif_user[CFGKEY_LEN], old_webif_pass[CFGKEY_LEN], old_logfile[CFGPATH_LEN];
    char old_usrfile[CFGPATH_LEN], old_failban_allowlist[CFGKEY_LEN];
    uint8_t old_newcamd_key[14];
    tcmg_strlcpy(old_webif_user, g_cfg.webif_user, sizeof(old_webif_user));
    tcmg_strlcpy(old_webif_pass, g_cfg.webif_pass, sizeof(old_webif_pass));
    tcmg_strlcpy(old_logfile, g_cfg.logfile, sizeof(old_logfile));
    tcmg_strlcpy(old_usrfile, g_cfg.usrfile, sizeof(old_usrfile));
    tcmg_strlcpy(old_failban_allowlist, g_cfg.failban_allowlist, sizeof(old_failban_allowlist));
    memcpy(old_newcamd_key, g_cfg.newcamd_key, sizeof(old_newcamd_key));
    int old_failban_enabled = g_cfg.failban_enabled;
    int old_failban_max_fails = g_cfg.failban_max_fails;
    int old_failban_ban_secs = g_cfg.failban_ban_secs;
    char old_seller_name[CFGVAL_LEN], old_seller_type[16], old_seller_host[CFGKEY_LEN];
    int old_seller_port = g_cfg.seller_port;
    tcmg_strlcpy(old_seller_name, g_cfg.seller_name, sizeof(old_seller_name));
    tcmg_strlcpy(old_seller_type, g_cfg.seller_type, sizeof(old_seller_type));
    tcmg_strlcpy(old_seller_host, g_cfg.seller_host, sizeof(old_seller_host));

    if (p->has_newcamd_port) g_cfg.newcamd_port = p->newcamd_port;
    if (p->has_newcamd_bindaddr) tcmg_strlcpy(g_cfg.newcamd_bindaddr, p->newcamd_bindaddr, sizeof(g_cfg.newcamd_bindaddr));
    if (p->has_newcamd_key) memcpy(g_cfg.newcamd_key, p->newcamd_key, 14);
    if (p->has_newcamd_keepalive) g_cfg.newcamd_keepalive = p->newcamd_keepalive;
    if (p->has_newcamd_mgclient) g_cfg.newcamd_mgclient = p->newcamd_mgclient;
    if (p->has_cccam_port) g_cfg.cccam_port = p->cccam_port;
    if (p->has_cs378x_port) g_cfg.cs378x_port = p->cs378x_port;
    if (p->has_cs378x_bindaddr) tcmg_strlcpy(g_cfg.cs378x_bindaddr, p->cs378x_bindaddr, sizeof(g_cfg.cs378x_bindaddr));
    if (p->has_sock_timeout) g_cfg.sock_timeout = p->sock_timeout;
    if (p->has_server_keepalive) g_cfg.server_keepalive = p->server_keepalive;
    if (p->has_server_keepalive_misses) g_cfg.server_keepalive_misses = p->server_keepalive_misses;
    if (p->has_ecm_log) g_cfg.ecm_log = p->ecm_log;
    if (p->has_scheduled_restart) g_cfg.scheduled_restart_enabled = p->scheduled_restart_enabled;
    if (p->has_scheduled_restart_time) { int hh = (p->scheduled_restart_time[0]-'0')*10 + (p->scheduled_restart_time[1]-'0'); int mm = (p->scheduled_restart_time[3]-'0')*10 + (p->scheduled_restart_time[4]-'0'); g_cfg.scheduled_restart_minutes = (int16_t)(hh*60 + mm); }
    if (p->has_logfile) tcmg_strlcpy(g_cfg.logfile, p->logfile, sizeof(g_cfg.logfile));
    if (p->has_webif_port) g_cfg.webif_port = p->webif_port;
    if (p->has_webif_refresh) g_cfg.webif_refresh = p->webif_refresh;
    if (p->has_webif_user) tcmg_strlcpy(g_cfg.webif_user, p->webif_user, sizeof(g_cfg.webif_user));
    if (p->has_webif_pass) tcmg_strlcpy(g_cfg.webif_pass, p->webif_pass, sizeof(g_cfg.webif_pass));
    if (p->has_webif_bindaddr) tcmg_strlcpy(g_cfg.webif_bindaddr, p->webif_bindaddr, sizeof(g_cfg.webif_bindaddr));
    if (p->has_failban_enabled) g_cfg.failban_enabled = p->failban_enabled;
    if (p->has_failban_allowlist) tcmg_strlcpy(g_cfg.failban_allowlist, p->failban_allowlist, sizeof(g_cfg.failban_allowlist));
    if (p->has_failban_max_fails) g_cfg.failban_max_fails = p->failban_max_fails;
    if (p->has_failban_ban_secs) g_cfg.failban_ban_secs = p->failban_ban_secs;
    if (p->has_seller_name) tcmg_strlcpy(g_cfg.seller_name, p->seller_name, sizeof(g_cfg.seller_name));
    if (p->has_seller_type) tcmg_strlcpy(g_cfg.seller_type, p->seller_type, sizeof(g_cfg.seller_type));
    if (p->has_seller_host) tcmg_strlcpy(g_cfg.seller_host, p->seller_host, sizeof(g_cfg.seller_host));
    if (p->has_seller_port) g_cfg.seller_port = p->seller_port;

    bool restart =
        old_webif_enabled != g_cfg.webif_enabled || old_webif_port != g_cfg.webif_port || strcmp(old_webif_bindaddr, g_cfg.webif_bindaddr) != 0 ||
        old_newcamd_port != g_cfg.newcamd_port || strcmp(old_newcamd_bindaddr, g_cfg.newcamd_bindaddr) != 0 ||
        old_cccam_port != g_cfg.cccam_port || strcmp(old_cccam_bindaddr, g_cfg.cccam_bindaddr) != 0 ||
        old_cs378x_port != g_cfg.cs378x_port || strcmp(old_cs378x_bindaddr, g_cfg.cs378x_bindaddr) != 0;

    pthread_rwlock_unlock(&g_cfg.acc_lock);

    bool ok = cfg_save(&g_cfg);
    if (!ok) {
        pthread_rwlock_wrlock(&g_cfg.acc_lock);
        g_cfg.webif_enabled = old_webif_enabled;
        g_cfg.webif_port = old_webif_port;
        tcmg_strlcpy(g_cfg.webif_bindaddr, old_webif_bindaddr, sizeof(g_cfg.webif_bindaddr));
        g_cfg.newcamd_port = old_newcamd_port;
        tcmg_strlcpy(g_cfg.newcamd_bindaddr, old_newcamd_bindaddr, sizeof(g_cfg.newcamd_bindaddr));
        memcpy(g_cfg.newcamd_key, old_newcamd_key, sizeof(g_cfg.newcamd_key));
        g_cfg.newcamd_keepalive = old_newcamd_keepalive;
        g_cfg.newcamd_mgclient = old_newcamd_mgclient;
        g_cfg.cccam_port = old_cccam_port;
        tcmg_strlcpy(g_cfg.cccam_bindaddr, old_cccam_bindaddr, sizeof(g_cfg.cccam_bindaddr));
        g_cfg.cs378x_port = old_cs378x_port;
        tcmg_strlcpy(g_cfg.cs378x_bindaddr, old_cs378x_bindaddr, sizeof(g_cfg.cs378x_bindaddr));
        g_cfg.sock_timeout = old_sock_timeout;
        g_cfg.server_keepalive = old_server_keepalive;
        g_cfg.server_keepalive_misses = old_server_keepalive_misses;
        g_cfg.ecm_log = old_ecm_log;
        g_cfg.scheduled_restart_enabled = old_sched_enabled;
        g_cfg.scheduled_restart_minutes = (int16_t)old_sched_minutes;
        g_cfg.webif_refresh = old_webif_refresh;
        tcmg_strlcpy(g_cfg.webif_user, old_webif_user, sizeof(g_cfg.webif_user));
        tcmg_strlcpy(g_cfg.webif_pass, old_webif_pass, sizeof(g_cfg.webif_pass));
        tcmg_strlcpy(g_cfg.logfile, old_logfile, sizeof(g_cfg.logfile));
        tcmg_strlcpy(g_cfg.usrfile, old_usrfile, sizeof(g_cfg.usrfile));
        g_cfg.failban_enabled = old_failban_enabled;
        tcmg_strlcpy(g_cfg.failban_allowlist, old_failban_allowlist, sizeof(g_cfg.failban_allowlist));
        g_cfg.failban_max_fails = old_failban_max_fails;
        g_cfg.failban_ban_secs = old_failban_ban_secs;
        tcmg_strlcpy(g_cfg.seller_name, old_seller_name, sizeof(g_cfg.seller_name));
        tcmg_strlcpy(g_cfg.seller_type, old_seller_type, sizeof(g_cfg.seller_type));
        tcmg_strlcpy(g_cfg.seller_host, old_seller_host, sizeof(g_cfg.seller_host));
        g_cfg.seller_port = old_seller_port;
        pthread_rwlock_unlock(&g_cfg.acc_lock);
    } else {
        if (restart_required) *restart_required = restart;
        if (!restart) g_reload_cfg = 1;
        else tcmg_log("listener settings saved; restart required to apply them");
    }

    pthread_mutex_unlock(&g_cfg_transition_mtx);
    return ok;
}

bool webif_save_config_file(const char *content, size_t len)
{
    char path[CFGPATH_LEN], tmp[CFGPATH_LEN + 8];
    if (!content || !len) return false;

    bool ok = false;
    S_CONFIG *parsed = NULL;
    tcmg_build_path(path, sizeof(path), g_cfgdir, TCMG_CFG_FILE);
    tcmg_build_path(tmp, sizeof(tmp), g_cfgdir, TCMG_CFG_FILE ".chk");

    pthread_mutex_lock(&s_file_save_mtx);

    FILE *fp = fopen(tmp, "wb");
    if (!fp || fwrite(content, 1, len, fp) != len) {
        if (fp) fclose(fp);
        remove(tmp);
        goto done;
    }
    if (fclose(fp) != 0) {
        remove(tmp);
        goto done;
    }

    parsed = calloc(1, sizeof(*parsed));
    if (!parsed) {
        remove(tmp);
        goto done;
    }
    if (pthread_rwlock_init(&parsed->acc_lock, NULL) != 0) {
        free(parsed);
        parsed = NULL;
        remove(tmp);
        goto done;
    }
    if (pthread_mutex_init(&parsed->ban_lock, NULL) != 0) {
        pthread_rwlock_destroy(&parsed->acc_lock);
        free(parsed);
        parsed = NULL;
        remove(tmp);
        goto done;
    }

    ok = cfg_load(tmp, parsed);
    remove(tmp);
    cfg_accounts_free(parsed);
    pthread_rwlock_destroy(&parsed->acc_lock);
    pthread_mutex_destroy(&parsed->ban_lock);
    free(parsed);
    parsed = NULL;

    if (ok) ok = write_file_atomic(path, content, len);
    if (ok) g_reload_cfg = 1;

done:
    pthread_mutex_unlock(&s_file_save_mtx);
    return ok;
}

static bool validate_reader_editor_text(const char *content, char *err, size_t errsz)
{
    /* old_ecm_trigger / old_ecm_interval are legacy keys: still accepted, ignored by the loader. */
    static const char *const keys[] = {
        "label", "protocol", "enabled", "device", "user", "password", "group", "caid", "ident",
        "sid_whitelist", "ecmwhitelist", "inactivitytimeout", "do_ecm", "fast_reset", "fast_reset_idle",
        "maintenance_mode", "old_ecm_source", "old_ecm_trigger", "old_ecm_interval", "old_ecm_successes",
        "old_ecm", "poll_ms", "key", "ecmkey"
    };
    char *buf = strdup(content ? content : "");
    if (!buf) { snprintf(err, errsz, "out of memory"); return false; }
    int section = 0, label_seen = 0, protocol_seen = 0, line_no = 0;
    bool ok = true;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        line_no++;
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\r' || isspace((unsigned char)line[n - 1]))) line[--n] = '\0';
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') continue;
        if (*p == '[') {
            if (!section) {
                if (strcmp(p, "[reader]") != 0) { snprintf(err, errsz, "line %d: only [reader] sections are allowed", line_no); ok = false; break; }
            } else {
                if (!label_seen || !protocol_seen) { snprintf(err, errsz, "line %d: reader requires label and protocol", line_no); ok = false; break; }
                if (strcmp(p, "[reader]") != 0) { snprintf(err, errsz, "line %d: only [reader] sections are allowed", line_no); ok = false; break; }
            }
            section = 1; label_seen = 0; protocol_seen = 0;
            continue;
        }
        if (!section) { snprintf(err, errsz, "line %d: setting outside [reader] section", line_no); ok = false; break; }
        char *eq = strchr(p, '=');
        if (!eq) { snprintf(err, errsz, "line %d: invalid reader setting", line_no); ok = false; break; }
        *eq++ = '\0';
        while (*eq && isspace((unsigned char)*eq)) eq++;
        char *ke = p + strlen(p);
        while (ke > p && isspace((unsigned char)ke[-1])) *--ke = '\0';
        bool known = false;
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) if (!strcasecmp(p, keys[i])) { known = true; break; }
        if (!known) { snprintf(err, errsz, "line %d: unknown reader setting '%s'", line_no, p); ok = false; break; }
        if (!strcasecmp(p, "label")) {
            if (!*eq) { snprintf(err, errsz, "line %d: label is required", line_no); ok = false; break; }
            label_seen = 1;
        } else if (!strcasecmp(p, "protocol")) {
            if (!*eq || !reader_protocol_find(eq)) { snprintf(err, errsz, "line %d: invalid reader protocol", line_no); ok = false; break; }
            protocol_seen = 1;
        }
    }
    if (ok && section && (!label_seen || !protocol_seen)) { snprintf(err, errsz, "reader requires label and protocol"); ok = false; }
    free(buf);
    return ok;
}

static bool validate_split_file(const char *tmp_path, const char *content, bool users, char *err, size_t errsz)
{
    S_CONFIG parsed;
    memset(&parsed, 0, sizeof(parsed));
    cfg_default_runtime(&parsed);
    err[0] = '\0';

    bool ok = true;
    if (!users) ok = validate_reader_editor_text(content, err, errsz);
    if (ok) ok = users ? cfg_parse_users(tmp_path, &parsed, err, errsz)
                       : cfg_parse_readers(tmp_path, &parsed, err, errsz);
    if (ok && !cfg_validate(&parsed, err, errsz)) ok = false;
    cfg_accounts_free(&parsed);
    return ok;
}

static bool save_validated_split_file(const char *content, size_t len,
                                      const char *path, const char *tmp_path,
                                      bool users, char *err, size_t errsz)
{
    if (err && errsz) err[0] = '\0';
    if (!content || !path || !tmp_path) {
        if (err && errsz) snprintf(err, errsz, "missing content");
        return false;
    }

    pthread_mutex_lock(&s_file_save_mtx);
    FILE *fp = fopen(tmp_path, "wb");
    if (!fp || fwrite(content, 1, len, fp) != len) {
        if (fp) fclose(fp);
        remove(tmp_path);
        pthread_mutex_unlock(&s_file_save_mtx);
        if (err && errsz) snprintf(err, errsz, "cannot write validation file");
        return false;
    }
    if (fclose(fp) != 0) {
        remove(tmp_path);
        pthread_mutex_unlock(&s_file_save_mtx);
        if (err && errsz) snprintf(err, errsz, "cannot close validation file");
        return false;
    }

    bool ok = validate_split_file(tmp_path, content, users, err, errsz);
    remove(tmp_path);
    if (ok && !write_file_atomic(path, content, len)) {
        ok = false;
        if (err && errsz) snprintf(err, errsz, "cannot write target file");
    }
    if (ok) g_reload_cfg = 1;
    pthread_mutex_unlock(&s_file_save_mtx);
    return ok;
}

bool webif_save_srvid_file(const char *content, size_t len, int *loaded)
{
    char path[CFGPATH_LEN];
    if (!content || !len) return false;
    pthread_mutex_lock(&s_file_save_mtx);
    tcmg_build_path(path, sizeof(path), g_cfgdir, TCMG_SRVID_FILE);
    bool ok = write_file_atomic(path, content, len);
    int n = ok ? srvid_load(path) : 0;
    if (loaded) *loaded = n;
    pthread_mutex_unlock(&s_file_save_mtx);
    return ok;
}

bool webif_save_users_file(const char *content, size_t len, char *err, size_t errsz)
{
    char path[CFGPATH_LEN], tmp[CFGPATH_LEN];
    tcmg_build_path(path, sizeof(path), g_cfgdir, TCMG_USER_FILE);
    tcmg_build_path(tmp, sizeof(tmp), g_cfgdir, ".tcmg.users.webif.chk");
    return save_validated_split_file(content, len, path, tmp, true, err, errsz);
}

bool webif_save_readers_file(const char *content, size_t len, char *err, size_t errsz)
{
    char path[CFGPATH_LEN], tmp[CFGPATH_LEN];
    tcmg_build_path(path, sizeof(path), g_cfgdir, TCMG_SERVER_FILE);
    tcmg_build_path(tmp, sizeof(tmp), g_cfgdir, ".tcmg.readers.webif.chk");
    return save_validated_split_file(content, len, path, tmp, false, err, errsz);
}
