#define MODULE_LOG_PREFIX "conf"
#include "config_internal.h"
#include "../reader/protocol.h"

#ifndef TCMG_OS_WINDOWS
#include <unistd.h>
#endif

static pthread_mutex_t s_save_mtx = PTHREAD_MUTEX_INITIALIZER;

bool cfg_appendf(char *buf, size_t cap, size_t *pos, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (!buf || !pos || !fmt || *pos >= cap) return false;

    va_start(ap, fmt);
    n = vsnprintf(buf + *pos, cap - *pos, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= cap - *pos) return false;
    *pos += (size_t)n;
    return true;
}

bool cfg_write_atomic(const char *path, const char *data)
{
    char tmp[CFGPATH_LEN + 32];
    FILE *f;
    size_t len;

    if (!path || !data || !path[0]) return false;
    if (snprintf(tmp, sizeof(tmp), "%s.new", path) <= 0 || strlen(tmp) >= sizeof(tmp)) return false;

    f = fopen(tmp, "wb");
    if (!f) return false;

    len = strlen(data);
    if (fwrite(data, 1, len, f) != len || fflush(f) != 0) {
        fclose(f);
        remove(tmp);
        return false;
    }
#ifndef TCMG_OS_WINDOWS
    if (fsync(fileno(f)) != 0) {
        fclose(f);
        remove(tmp);
        return false;
    }
#endif
    if (fclose(f) != 0) {
        remove(tmp);
        return false;
    }

#ifdef TCMG_OS_WINDOWS
    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        remove(tmp);
        return false;
    }
#else
    if (rename(tmp, path) != 0) {
        remove(tmp);
        return false;
    }
#endif
    return true;
}

bool cfg_build_global_text(const S_CONFIG*c,char*buf,size_t cap)
{
    size_t p=0;bool ok=cfg_appendf(buf,cap,&p,"# TCMG global configuration\n\n[global]\nsocket_timeout = %d\nserver_keepalive = %d\nserver_keepalive_misses = %d\necm_log = %d\nscheduled_restart = %d\nscheduled_restart_time = %02d:%02d\nlogfile = %s\nusrfile = %s\n\n[webif]\nenabled = %d\nport = %d\nrefresh = %d\nuser = %s\npassword = %s\nbindaddr = %s\n\n[newcamd]\nport = %d\nbindaddr = %s\nkey = ",c->sock_timeout,c->server_keepalive,c->server_keepalive_misses,c->ecm_log,c->scheduled_restart_enabled,c->scheduled_restart_minutes/60,c->scheduled_restart_minutes%60,c->logfile,c->usrfile,c->webif_enabled,c->webif_port,c->webif_refresh,c->webif_user,c->webif_pass,c->webif_bindaddr,c->newcamd_port,c->newcamd_bindaddr);
    for(int i=0;i<14&&ok;i++)ok=cfg_appendf(buf,cap,&p,"%02X",c->newcamd_key[i]);
    ok=ok&&cfg_appendf(buf,cap,&p,"\nkeepalive = %d\nmode = %s\n\n[cccam]\nport = %d\nbindaddr = %s\n\n[cs378x]\nport = %d\nbindaddr = %s\n\n[failban]\nenabled = %d\nallowlist = %s\nmax_fails = %d\nban_secs = %d\n\n[seller]\nname = %s\ntype = %s\nhost = %s\nport = %d\n",c->newcamd_keepalive,c->newcamd_mgclient?"mgcamd":"auto",c->cccam_port,c->cccam_bindaddr,c->cs378x_port,c->cs378x_bindaddr,c->failban_enabled,c->failban_allowlist,c->failban_max_fails,c->failban_ban_secs,c->seller_name,c->seller_type,c->seller_host,c->seller_port);return ok;
}

bool cfg_build_user_text(const S_CONFIG *c, char *buf, size_t cap)
{
    size_t p = 0;
    bool ok = true;
    for(const S_ACCOUNT*a=c->accounts;a&&ok;a=a->next){ok=cfg_appendf(buf,cap,&p,"[account]\nuser = %s\npassword = %s\nenabled = %d\ngroup = ",a->user,a->pass,a->enabled);for(int i=0;i<a->ngroups&&ok;i++)ok=cfg_appendf(buf,cap,&p,"%s%d",i?",":"",a->groups[i]);if((a->caid||a->ncaids)&&ok){ok=cfg_appendf(buf,cap,&p,"\ncaid = %04X",a->caid);for(int i=0;i<a->ncaids&&ok;i++)ok=cfg_appendf(buf,cap,&p,",%04X",a->caids[i]);}if(a->nidents&&ok){ok=cfg_appendf(buf,cap,&p,"\nident = ");for(int i=0;i<a->nidents&&ok;i++)ok=cfg_appendf(buf,cap,&p,"%s%04X:%08X",i?",":"",a->idents[i].caid,a->idents[i].provid);}ok=ok&&cfg_appendf(buf,cap,&p,"\nmax_connections = %d\nmax_idle = %d\nexpiration = ",a->max_connections,a->max_idle);if(a->expirationdate){struct tm t;localtime_r(&a->expirationdate,&t);ok=cfg_appendf(buf,cap,&p,"%04d-%02d-%02d",t.tm_year+1900,t.tm_mon+1,t.tm_mday);}else ok=ok&&cfg_appendf(buf,cap,&p,"0");ok=ok&&cfg_appendf(buf,cap,&p,"\nschedule = %s\nanti_share = %d\nas_max_sids = %d\nas_max_ecm = %d\nas_ecm_window_s = %d\nas_channel_timeout_s = %d\nas_switch_delay_s = %d\n",a->schedule,a->anti_share,a->as_max_sids,a->as_max_ecm,a->as_ecm_window_s,a->as_channel_timeout_s,a->as_switch_delay_s);if(a->nwhitelist&&ok){ok=cfg_appendf(buf,cap,&p,"ip_whitelist = ");for(int i=0;i<a->nwhitelist&&ok;i++)ok=cfg_appendf(buf,cap,&p,"%s%s",i?",":"",a->ip_whitelist[i]);ok=ok&&cfg_appendf(buf,cap,&p,"\n");}if(a->nsid_whitelist&&ok){ok=cfg_appendf(buf,cap,&p,"sid_whitelist = ");for(int i=0;i<a->nsid_whitelist&&ok;i++)ok=cfg_appendf(buf,cap,&p,"%s%04X",i?",":"",a->sid_whitelist[i]);ok=ok&&cfg_appendf(buf,cap,&p,"\n");}for(int i=0;i<a->nkeys&&ok;i++){ok=cfg_appendf(buf,cap,&p,"ecmkey = %04X=",a->keys[i].caid);for(int j=0;j<16&&ok;j++)ok=cfg_appendf(buf,cap,&p,"%02X",a->keys[i].key0[j]);for(int j=0;j<16&&ok;j++)ok=cfg_appendf(buf,cap,&p,"%02X",a->keys[i].key1[j]);ok=ok&&cfg_appendf(buf,cap,&p,"\n");}ok=ok&&cfg_appendf(buf,cap,&p,"\n");}
    return ok;
}

bool cfg_build_server_text(const S_CONFIG *c, char *buf, size_t cap)
{
    size_t pos = 0;
    bool ok = true;

    for (int i = 0; i < MAX_READERS && ok; i++) {
        const S_READER *r = &c->readers[i];
        if (!r->in_use) continue;

        ok = cfg_appendf(buf, cap, &pos, "[reader]\n");
        ok = ok && cfg_appendf(buf, cap, &pos,
                           "label = %s\nprotocol = %s\nenabled = %d\n",
                           r->label, r->protocol, r->enabled);

        ok = ok && cfg_appendf(buf, cap, &pos, "group = ");
        for (int j = 0; j < r->ngroups && ok; j++)
            ok = cfg_appendf(buf, cap, &pos, "%s%d", j ? "," : "", r->groups[j]);
        if ((r->ncaids > 0) && ok) {
            ok = cfg_appendf(buf, cap, &pos, "\ncaid = ");
            for (int j = 0; j < r->ncaids && ok; j++)
                ok = cfg_appendf(buf, cap, &pos, "%s%04X", j ? "," : "", r->caids[j]);
        }
        if (r->nidents > 0 && ok) {
            ok = cfg_appendf(buf, cap, &pos, "\nident = ");
            for (int j = 0; j < r->nidents && ok; j++)
                ok = cfg_appendf(buf, cap, &pos, "%s%04X:%08X", j ? "," : "", r->idents[j].caid, r->idents[j].provid);
        }

        ok = ok && cfg_appendf(buf, cap, &pos,
                           "\necmwhitelist = %02X\ninactivitytimeout = %d\n",
                           (unsigned)(r->ecm_whitelist & 0xFF), r->inactivitytimeout);

        if (reader_protocol_kind(r->protocol) == READER_PROTOCOL_NETWORK) {
            ok = ok && cfg_appendf(buf, cap, &pos,
                               "device = %s\nuser = %s\npassword = %s\n",
                               r->device, r->user, r->password);
        }

        if (!strcasecmp(r->protocol, "newcamd") || !strcasecmp(r->protocol, "mgcamd")) {
            ok = ok && cfg_appendf(buf, cap, &pos, "key = ");
            for (int j = 0; j < 14 && ok; j++)
                ok = cfg_appendf(buf, cap, &pos, "%02X", r->newcamd_key[j]);
            ok = ok && cfg_appendf(buf, cap, &pos, "\n");
        }

        if (reader_protocol_kind(r->protocol) == READER_PROTOCOL_CARD) {
            const char *maintenance = r->maintenance_mode == TCMG_READER_MAINT_OLD_ECM ? "old_ecm" : "fast_reset";
            const char *source = r->old_ecm_source == TCMG_OLD_ECM_SOURCE_MANUAL ? "manual" : "auto";
            ok = ok && cfg_appendf(buf, cap, &pos,
                               "device = %s\nmaintenance_mode = %s\nfast_reset = %d\nfast_reset_idle = %d\nold_ecm_source = %s\nold_ecm_successes = %d\nold_ecm = %s\n",
                               r->device, maintenance, r->fast_reset, r->fast_reset_idle, source,
                               r->old_ecm_successes, r->old_ecm);
            if (strcasecmp(r->protocol, "pcsc") == 0 ||
                strcasecmp(r->protocol, "serial") == 0) {
                ok = ok && cfg_appendf(buf, cap, &pos, "poll_ms = %d\n", r->poll_ms);
            }
        }

        if (!strcasecmp(r->protocol, "emu")) {
            for (int j = 0; j < r->nkeys && ok; j++) {
                ok = cfg_appendf(buf, cap, &pos, "ecmkey = %04X=", r->keys[j].caid);
                for (int z = 0; z < 16 && ok; z++)
                    ok = cfg_appendf(buf, cap, &pos, "%02X", r->keys[j].key0[z]);
                for (int z = 0; z < 16 && ok; z++)
                    ok = cfg_appendf(buf, cap, &pos, "%02X", r->keys[j].key1[z]);
                ok = ok && cfg_appendf(buf, cap, &pos, "\n");
            }
        }

        if (r->nsid_whitelist > 0) {
            ok = cfg_appendf(buf, cap, &pos, "sid_whitelist = ");
            for (int j = 0; j < r->nsid_whitelist && ok; j++)
                ok = cfg_appendf(buf, cap, &pos, "%s%04X", j ? "," : "", r->sid_whitelist[j]);
            ok = ok && cfg_appendf(buf, cap, &pos, "\n");
        }

        ok = ok && cfg_appendf(buf, cap, &pos, "\n");
    }

    return ok;
}

typedef bool (*cfg_builder_fn)(const S_CONFIG *c, char *buf, size_t cap);

static char *cfg_build_grow(const S_CONFIG *c, cfg_builder_fn fn,
                            size_t start_cap, size_t max_cap)
{
    size_t cap = start_cap;
    while (cap <= max_cap) {
        char *buf = (char *)calloc(1, cap);
        if (!buf) return NULL;
        if (fn(c, buf, cap)) return buf;
        free(buf);
        cap *= 2;
    }
    return NULL;
}

bool cfg_save(S_CONFIG *c)
{
    enum { GLOBAL_START = 2048, GLOBAL_MAX = 32768,
           TEXT_START = 8192, TEXT_MAX = 262144 };
    char *global_text = NULL;
    char *user_text = NULL;
    char *reader_text = NULL;
    bool ok;

    if (!c || !c->config_file[0] || !c->user_file[0] || !c->server_file[0]) return false;

    pthread_mutex_lock(&s_save_mtx);

    pthread_rwlock_rdlock(&c->acc_lock);
    global_text = cfg_build_grow(c, cfg_build_global_text, GLOBAL_START, GLOBAL_MAX);
    user_text   = cfg_build_grow(c, cfg_build_user_text,   TEXT_START,   TEXT_MAX);
    reader_text = cfg_build_grow(c, cfg_build_server_text, TEXT_START,   TEXT_MAX);
    pthread_rwlock_unlock(&c->acc_lock);

    ok = global_text && user_text && reader_text;

    if (ok) ok = cfg_write_atomic(c->config_file, global_text);
    if (ok) ok = cfg_write_atomic(c->user_file, user_text);
    if (ok) ok = cfg_write_atomic(c->server_file, reader_text);

    if (ok)
        tcmg_log("saved");

    if (user_text)   secure_zero(user_text, strlen(user_text));
    if (global_text) secure_zero(global_text, strlen(global_text));
    if (reader_text) secure_zero(reader_text, strlen(reader_text));
    free(global_text);
    free(user_text);
    free(reader_text);
    pthread_mutex_unlock(&s_save_mtx);
    return ok;
}

bool cfg_write_default_if_missing(const char *path, const char *text)
{
    if (!path || !text) return false;
    if (access(path, F_OK) == 0) return true;
    return cfg_write_atomic(path, text);
}

bool cfg_write_default(const char *path)
{
    char user_file[CFGPATH_LEN];
    char reader_file[CFGPATH_LEN];

    static const char global_text[] =
        "# TCMG global configuration\n"
        "# First run intentionally starts with no accounts or readers.\n"
        "# Configure the services you need before enabling them.\n\n"
        "[webif]\n"
        "enabled = 1\n"
        "port = 8585\n"
        "bindaddr = 0.0.0.0\n";

    static const char user_text[] =
        "# TCMG accounts\n"
        "# Add one [account] block per user.\n";

    static const char reader_text[] =
        "# TCMG readers\n"
        "# Add one [reader] block per reader.\n";

    if (!path || !*path) return false;

    cfg_path_sibling(user_file, sizeof(user_file), path, TCMG_USER_FILE);
    cfg_path_sibling(reader_file, sizeof(reader_file), path, TCMG_SERVER_FILE);

    if (!cfg_write_default_if_missing(path, global_text)) return false;
    if (!cfg_write_default_if_missing(user_file, user_text)) return false;
    if (!cfg_write_default_if_missing(reader_file, reader_text)) return false;

    tcmg_log("initial configuration created: webif=0.0.0.0:8585, accounts=0, readers=0");
    return true;
}
