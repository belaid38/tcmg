#define MODULE_LOG_PREFIX "webif"
#include "service.h"
#include "../../src/config/config.h"
#include "../../src/core/config_state.h"
#include "../../src/core/runtime_state.h"
#include "../../src/core/constants.h"
#include "../../src/core/utils.h"
#include "../../src/reader/protocol.h"
#include "../../src/reader/rules.h"
#include "../../src/reader/stats.h"
#include "../../src/internal/internal.h"
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void trim_field(char *s)
{
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
}

static bool parse_ident_field(const char *s, S_IDENT_FILTER *out, int32_t *n)
{
    char buf[WEBIF_IDENT_LIST_LEN];
    char *save = NULL, *tok;
    *n = 0;
    if (!s || !*s) return true;
    tcmg_strlcpy(buf, s, sizeof(buf));
    tok = strtok_r(buf, ",;", &save);
    while (tok) {
        char *colon, *end;
        unsigned long caid, provid;
        trim_field(tok);
        if (!tok[0] || *n >= MAX_IDENT_FILTERS) return false;
        colon = strchr(tok, ':');
        if (!colon || colon == tok || strchr(colon + 1, ':')) return false;
        *colon++ = '\0';
        trim_field(tok); trim_field(colon);
        if (strlen(tok) > 4 || strlen(colon) > 8 || !tok[0] || !colon[0]) return false;
        caid = strtoul(tok, &end, 16);
        if (end == tok || *end || caid == 0 || caid > 0xFFFF) return false;
        provid = strtoul(colon, &end, 16);
        if (end == colon || *end || provid > 0xFFFFFFFFUL) return false;
        for (int i = 0; i < *n; i++) if (out[i].caid == (uint16_t)caid && out[i].provid == (uint32_t)provid) return false;
        out[*n].caid = (uint16_t)caid; out[*n].provid = (uint32_t)provid; (*n)++;
        tok = strtok_r(NULL, ",;", &save);
    }
    return true;
}

static void format_reader_idents(const S_READER *r, char *out, size_t out_sz)
{
    out[0] = '\0';
    for (int i = 0; i < r->nidents && i < MAX_IDENT_FILTERS; i++) {
        char item[32];
        if (i) tcmg_strlcat(out, ",", out_sz);
        snprintf(item, sizeof(item), "%04X:%08X", r->idents[i].caid, r->idents[i].provid);
        tcmg_strlcat(out, item, out_sz);
    }
}

static void copy_reader(const S_READER *r, int idx, S_WEBIF_READER_VIEW *v)
{
    memset(v, 0, sizeof(*v));
    v->index = idx;
    v->enabled = r->enabled;
    v->inactivitytimeout = r->inactivitytimeout;
    v->ecm_whitelist = r->ecm_whitelist;
    reader_ecm_whitelist_get_spec(r, v->ecmwhitelist, sizeof(v->ecmwhitelist));
    v->deprecated = r->deprecated;
    v->fast_reset = r->fast_reset;
    v->fast_reset_idle = r->fast_reset_idle;
    v->poll_ms = r->poll_ms;
    v->maintenance_mode = r->maintenance_mode;
    v->old_ecm_source = r->old_ecm_source;
    v->old_ecm_successes = r->old_ecm_successes;
    tcmg_strlcpy(v->old_ecm, r->old_ecm, sizeof(v->old_ecm));
    S_READER_STATS_SNAPSHOT stats;
    reader_stats_snapshot(idx, &stats);
    v->cw_ok = stats.cw_ok;
    v->cw_nok = stats.cw_nok;
    v->active = r->enabled && stats.active;
    tcmg_strlcpy(v->label, r->label, sizeof(v->label));
    tcmg_strlcpy(v->protocol, r->protocol, sizeof(v->protocol));
    format_reader_idents(r, v->idents, sizeof(v->idents));
    tcmg_strlcpy(v->device, r->device, sizeof(v->device));
    if (!strcasecmp(r->protocol, "internal")) {
        S_INTERNAL_READER ir;
        if (internal_reader_get(idx, &ir) == 0 && ir.backend[0])
            tcmg_strlcpy(v->backend, ir.backend, sizeof(v->backend));
    }
    tcmg_strlcpy(v->user, r->user, sizeof(v->user));
    tcmg_strlcpy(v->password, r->password, sizeof(v->password));
    for (int i = 0; i < 14; i++) snprintf(v->key + i * 2, 3, "%02X", r->newcamd_key[i]);
    v->key[28] = 0;
    for (int i = 0; i < r->ngroups && i < MAX_GROUPS_PER_READER; i++) {
        char x[24];
        if (i) tcmg_strlcat(v->groups, ",", sizeof(v->groups));
        snprintf(x, sizeof(x), "%d", r->groups[i]);
        tcmg_strlcat(v->groups, x, sizeof(v->groups));
    }
    for (int i = 0; i < r->ncaids && i < MAX_CAIDS_PER_READER; i++) {
        char x[8];
        if (i) tcmg_strlcat(v->caids, ",", sizeof(v->caids));
        snprintf(x, sizeof(x), "%04X", r->caids[i]);
        tcmg_strlcat(v->caids, x, sizeof(v->caids));
    }
    for (int i = 0; i < r->nsid_whitelist && i < MAX_SID_WHITELIST; i++) {
        char x[8];
        if (i) tcmg_strlcat(v->sid_whitelist, ",", sizeof(v->sid_whitelist));
        snprintf(x, sizeof(x), "%04X", r->sid_whitelist[i]);
        tcmg_strlcat(v->sid_whitelist, x, sizeof(v->sid_whitelist));
    }
    for (int i = 0; i < r->nkeys; i++) {
        char hex[65], one[80];
        for (int j = 0; j < 16; j++) snprintf(hex + j * 2, 3, "%02X", r->keys[i].key0[j]);
        for (int j = 0; j < 16; j++) snprintf(hex + 32 + j * 2, 3, "%02X", r->keys[i].key1[j]);
        hex[64] = 0;
        snprintf(one, sizeof(one), "%04X=%s%s", r->keys[i].caid, hex, i + 1 < r->nkeys ? "\n" : "");
        tcmg_strlcat(v->ecmkeys, one, sizeof(v->ecmkeys));
    }
}
bool webif_reader_first_free(int *index)
{
    if (!index) return false;
    bool ok = false;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    for (int i = 0; i < MAX_READERS; i++) {
        if (!g_cfg.readers[i].in_use) { *index = i; ok = true; break; }
    }
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return ok;
}

int webif_reader_count(void)
{
    int n;
    pthread_rwlock_rdlock(&g_cfg.acc_lock); n = g_cfg.nreaders; pthread_rwlock_unlock(&g_cfg.acc_lock);
    return n;
}

int webif_reader_snapshot_all(S_WEBIF_READER_VIEW *out, size_t cap)
{
    int n = 0;
    if (!out || !cap) return 0;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    for (int i = 0; i < MAX_READERS && (size_t)n < cap; i++) if (g_cfg.readers[i].in_use) copy_reader(&g_cfg.readers[i], i, &out[n++]);
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return n;
}

static void copy_reader_list(const S_READER *r, int idx, S_WEBIF_READER_LIST_VIEW *v)
{
    memset(v, 0, sizeof(*v));
    v->index = idx;
    v->enabled = r->enabled;
    tcmg_strlcpy(v->label, r->label, sizeof(v->label));
    tcmg_strlcpy(v->protocol, r->protocol, sizeof(v->protocol));
    tcmg_strlcpy(v->device, r->device, sizeof(v->device));
    for (int i = 0; i < r->ngroups && i < MAX_GROUPS_PER_READER; i++) {
        char item[24];
        if (i) tcmg_strlcat(v->groups, ",", sizeof(v->groups));
        snprintf(item, sizeof(item), "%d", r->groups[i]);
        tcmg_strlcat(v->groups, item, sizeof(v->groups));
    }
    for (int i = 0; i < r->ncaids && i < MAX_CAIDS_PER_READER; i++) {
        char item[8];
        if (i) tcmg_strlcat(v->caids, ",", sizeof(v->caids));
        snprintf(item, sizeof(item), "%04X", r->caids[i]);
        tcmg_strlcat(v->caids, item, sizeof(v->caids));
    }
    if (!strcasecmp(r->protocol, "emu")) {
        for (int i = 0; i < r->nkeys && i < MAX_ECMKEYS_PER_ACC; i++) {
            char item[8];
            snprintf(item, sizeof(item), "%04X", r->keys[i].caid);
            if (!strstr(v->caids, item)) {
                if (v->caids[0]) tcmg_strlcat(v->caids, ",", sizeof(v->caids));
                tcmg_strlcat(v->caids, item, sizeof(v->caids));
            }
        }
    }
    S_READER_STATS_SNAPSHOT stats;
    reader_stats_snapshot(idx, &stats);
    v->cw_ok = stats.cw_ok;
    v->cw_nok = stats.cw_nok;
    v->active = r->enabled && stats.active;
}

int webif_reader_list_snapshot_all(S_WEBIF_READER_LIST_VIEW *out, size_t cap)
{
    int n = 0;
    if (!out || !cap) return 0;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    for (int i = 0; i < MAX_READERS && (size_t)n < cap; i++) {
        if (!g_cfg.readers[i].in_use) continue;
        copy_reader_list(&g_cfg.readers[i], i, &out[n]);
        n++;
    }
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return n;
}

bool webif_reader_get(int index, S_WEBIF_READER_VIEW *out)
{
    if (!out || index < 0 || index >= MAX_READERS) return false;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    if (!g_cfg.readers[index].in_use) { pthread_rwlock_unlock(&g_cfg.acc_lock); return false; }
    copy_reader(&g_cfg.readers[index], index, out);
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return true;
}

static int parse_simple_i32(const char *s, long lo, long hi, int *out)
{
    if (!s || !*s || !out) return -1;
    char *e = NULL; long v = strtol(s, &e, 10);
    if (e == s || *e || v < lo || v > hi) return -1;
    *out = (int)v; return 0;
}

bool webif_reader_save(const S_WEBIF_READER_EDIT *e)
{
    if (!e || e->index < 0 || e->index >= MAX_READERS) return false;
    S_READER value;
    memset(&value, 0, sizeof(value));
    value.in_use = 1;
    value.enabled = 1;
    value.inactivitytimeout = 30;
    value.ecm_whitelist = 0;
    value.poll_ms = 250;
    value.maintenance_mode = TCMG_READER_MAINT_FAST_RESET;
    value.old_ecm_source = TCMG_OLD_ECM_SOURCE_AUTO;
    value.old_ecm_successes = 10;
    snprintf(value.label, sizeof(value.label), "reader%d", e->index);
    tcmg_strlcpy(value.protocol, "emu", sizeof(value.protocol));

    tcmg_strlcpy(value.label, e->label, sizeof(value.label));
    tcmg_strlcpy(value.protocol, e->protocol, sizeof(value.protocol));
    tcmg_strlcpy(value.device, e->device, sizeof(value.device));
    tcmg_strlcpy(value.user, e->user, sizeof(value.user));
    tcmg_strlcpy(value.password, e->password, sizeof(value.password));
    int iv;
    if (parse_simple_i32(e->enabled, 0, 1, &iv) < 0) return false;
    value.enabled = (int8_t)iv;
    if (!reader_ecm_whitelist_parse(&value, e->ecmwhitelist)) return false;
    const S_READER_PROTOCOL *protocol = reader_protocol_find(e->protocol);
    if (!protocol) return false;

    if (protocol->kind == READER_PROTOCOL_EMU) {
        value.device[0] = 0; value.user[0] = 0; value.password[0] = 0;
        value.inactivitytimeout = 30; value.fast_reset = 0; value.fast_reset_idle = 300; value.poll_ms = 250;
        value.maintenance_mode = TCMG_READER_MAINT_FAST_RESET; value.old_ecm_source = TCMG_OLD_ECM_SOURCE_AUTO; value.old_ecm_successes = 10; value.old_ecm[0] = 0;
    } else if (protocol->kind == READER_PROTOCOL_CARD) {
        value.user[0] = 0; value.password[0] = 0; value.inactivitytimeout = 30;
        value.deprecated = 0;
        if (e->deprecated[0]) {
            if (parse_simple_i32(e->deprecated, 0, 1, &value.deprecated) < 0) return false;
            if (strcasecmp(value.protocol, "internal") != 0) value.deprecated = 0;
        }
        if (parse_simple_i32(e->fast_reset, 0, 86400, &value.fast_reset) < 0) return false;
        if (parse_simple_i32(e->fast_reset_idle, 0, 86400, &value.fast_reset_idle) < 0) return false;
        if (!strcasecmp(e->maintenance_mode, "fast_reset")) value.maintenance_mode = TCMG_READER_MAINT_FAST_RESET;
        else if (!strcasecmp(e->maintenance_mode, "old_ecm")) value.maintenance_mode = TCMG_READER_MAINT_OLD_ECM;
        else return false;
        if (!strcasecmp(e->old_ecm_source, "auto")) value.old_ecm_source = TCMG_OLD_ECM_SOURCE_AUTO;
        else if (!strcasecmp(e->old_ecm_source, "manual")) value.old_ecm_source = TCMG_OLD_ECM_SOURCE_MANUAL;
        else return false;
        if (parse_simple_i32(e->old_ecm_successes, 1, 1000000, &value.old_ecm_successes) < 0) return false;
        size_t old_len = strlen(e->old_ecm);
        if (old_len > TCMG_OLD_ECM_HEX_LEN || (old_len & 1u)) return false;
        for (size_t z = 0; z < old_len; z++) if (!isxdigit((unsigned char)e->old_ecm[z])) return false;
        if (value.maintenance_mode == TCMG_READER_MAINT_OLD_ECM && value.old_ecm_source == TCMG_OLD_ECM_SOURCE_MANUAL && old_len < 2) return false;
        if (value.maintenance_mode == TCMG_READER_MAINT_OLD_ECM && value.old_ecm_source == TCMG_OLD_ECM_SOURCE_MANUAL && old_len > 0) {
            uint16_t old_caid = value.ncaids > 0 ? value.caids[0] : (value.nidents > 0 ? value.idents[0].caid : 0);
            uint32_t old_provid = 0;
            for (int j = 0; j < value.nidents; j++) {
                if (value.idents[j].caid == old_caid) { old_provid = value.idents[j].provid; break; }
            }
            if (!reader_ecm_whitelist_allows(&value, old_caid, old_provid, (int32_t)(old_len / 2u))) return false;
        }
        tcmg_strlcpy(value.old_ecm, e->old_ecm, sizeof(value.old_ecm));
        if (strcasecmp(value.protocol, "internal") != 0) {
            if (parse_simple_i32(e->poll_ms, 50, 10000, &value.poll_ms) < 0) return false;
        }
    } else {
        if (!e->device[0]) return false;
        if (parse_simple_i32(e->inactivitytimeout, 1, 600, &value.inactivitytimeout) < 0) return false;
    }
    if (strlen(e->group) >= sizeof(e->group) || strlen(e->caid) >= sizeof(e->caid) ||
        strlen(e->sid_whitelist) >= sizeof(e->sid_whitelist) || strlen(e->ecmkeys) >= sizeof(e->ecmkeys)) return false;
    char groups[sizeof(e->group)]; tcmg_strlcpy(groups, e->group, sizeof(groups));
    char *save = NULL, *tok = strtok_r(groups, ",", &save);
    while (tok) {
        char *q = tok; while (*q && isspace((unsigned char)*q)) q++;
        char *end = NULL; long x = strtol(q, &end, 10);
        while (end && *end && isspace((unsigned char)*end)) end++;
        if (end == q || (end && *end) || x < 1 || x > 65535 || value.ngroups >= MAX_GROUPS_PER_READER) return false;
        for (int i = 0; i < value.ngroups; i++) if (value.groups[i] == (int32_t)x) return false;
        value.groups[value.ngroups++] = (int32_t)x; tok = strtok_r(NULL, ",", &save);
    }
    if (value.ngroups == 0) return false;

    char caids[sizeof(e->caid)]; tcmg_strlcpy(caids, e->caid, sizeof(caids)); save = NULL; tok = strtok_r(caids, ", ;", &save);
    while (tok) {
        char *end = NULL; unsigned long x = strtoul(tok, &end, 16);
        if (end == tok || *end || x > 0xFFFF || value.ncaids >= MAX_CAIDS_PER_READER) return false;
        for (int i = 0; i < value.ncaids; i++) if (value.caids[i] == (uint16_t)x) return false;
        value.caids[value.ncaids++] = (uint16_t)x; tok = strtok_r(NULL, ", ;", &save);
    }
    if (strlen(e->ident) >= sizeof(e->ident)) return false;
    if (!parse_ident_field(e->ident, value.idents, &value.nidents)) return false;
    char sid[sizeof(e->sid_whitelist)]; tcmg_strlcpy(sid, e->sid_whitelist, sizeof(sid)); save = NULL; tok = strtok_r(sid, ", ;", &save);
    while (tok) {
        char *end = NULL; unsigned long x = strtoul(tok, &end, 16);
        if (end == tok || *end || x > 0xFFFF || value.nsid_whitelist >= MAX_SID_WHITELIST) return false;
        for (int i = 0; i < value.nsid_whitelist; i++) if (value.sid_whitelist[i] == (uint16_t)x) return false;
        value.sid_whitelist[value.nsid_whitelist++] = (uint16_t)x; tok = strtok_r(NULL, ", ;", &save);
    }
    if (strlen(e->key) >= sizeof(value.newcamd_key) * 2 + 1) return false;
    char key[sizeof(e->key)]; tcmg_strlcpy(key, e->key, sizeof(key));
    for (int i = 0; i < 14; i++) {
        char b[3] = { key[i * 2], key[i * 2 + 1], 0 };
        if (!isxdigit((unsigned char)b[0]) || !isxdigit((unsigned char)b[1])) {
            if (!strcmp(protocol->name, "newcamd")) return false;
            break;
        }
        value.newcamd_key[i] = (uint8_t)strtoul(b, NULL, 16);
    }
    char ek[WEBIF_ECMKEYS_LEN]; tcmg_strlcpy(ek, e->ecmkeys, sizeof(ek)); save = NULL; tok = strtok_r(ek, "\r\n;", &save);
    while (tok) {
        if (value.nkeys >= MAX_ECMKEYS_PER_ACC) return false;
        char *eq = strchr(tok, '='); if (!eq) return false; *eq++ = 0; char *end = NULL; unsigned long caid = strtoul(tok, &end, 16); if (end==tok||*end||caid>0xFFFF||strlen(eq)!=64) return false;
        for (int i = 0; i < value.nkeys; i++) if (value.keys[i].caid == (uint16_t)caid) return false;
        S_ECMKEY parsed; memset(&parsed, 0, sizeof(parsed)); parsed.caid=(uint16_t)caid;
        for(int j=0;j<64;j++) if(!isxdigit((unsigned char)eq[j])) return false;
        for(int j=0;j<16;j++){char b[3]={eq[j*2],eq[j*2+1],0};parsed.key0[j]=(uint8_t)strtoul(b,NULL,16);b[0]=eq[32+j*2];b[1]=eq[33+j*2];parsed.key1[j]=(uint8_t)strtoul(b,NULL,16);}
        value.keys[value.nkeys++] = parsed;
        tok=strtok_r(NULL,"\r\n;",&save);
    }

    pthread_mutex_lock(&g_cfg_transition_mtx);
    S_READER old_value;
    pthread_rwlock_wrlock(&g_cfg.acc_lock);
    if (g_cfg.readers[e->index].in_use) old_value = g_cfg.readers[e->index];
    else memset(&old_value, 0, sizeof(old_value));
    g_cfg.readers[e->index] = value;
    g_cfg.nreaders = 0; for (int i = 0; i < MAX_READERS; i++) if (g_cfg.readers[i].in_use) g_cfg.nreaders++;
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    bool ok = cfg_save(&g_cfg);
    if (!ok) {
        pthread_rwlock_wrlock(&g_cfg.acc_lock);
        g_cfg.readers[e->index] = old_value;
        g_cfg.nreaders = 0; for (int i = 0; i < MAX_READERS; i++) if (g_cfg.readers[i].in_use) g_cfg.nreaders++;
        pthread_rwlock_unlock(&g_cfg.acc_lock);
    } else g_reload_cfg = 1;
    pthread_mutex_unlock(&g_cfg_transition_mtx);
    return ok;
}

bool webif_reader_toggle(int index, int *enabled)
{
    if (index < 0 || index >= MAX_READERS) return false;
    pthread_mutex_lock(&g_cfg_transition_mtx);
    pthread_rwlock_wrlock(&g_cfg.acc_lock);
    if (!g_cfg.readers[index].in_use) {
        pthread_rwlock_unlock(&g_cfg.acc_lock);
        pthread_mutex_unlock(&g_cfg_transition_mtx);
        return false;
    }
    int old = g_cfg.readers[index].enabled;
    g_cfg.readers[index].enabled = old ? 0 : 1;
    int value = g_cfg.readers[index].enabled;
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    bool ok = cfg_save(&g_cfg);
    if (!ok) {
        pthread_rwlock_wrlock(&g_cfg.acc_lock);
        g_cfg.readers[index].enabled = old;
        pthread_rwlock_unlock(&g_cfg.acc_lock);
    } else {
        g_reload_cfg = 1;
        if (enabled) *enabled = value;
    }
    pthread_mutex_unlock(&g_cfg_transition_mtx);
    return ok;
}

bool webif_reader_delete(int index)
{
    if (index < 0 || index >= MAX_READERS) return false;
    pthread_mutex_lock(&g_cfg_transition_mtx);
    S_READER old_value;
    pthread_rwlock_wrlock(&g_cfg.acc_lock);
    if (!g_cfg.readers[index].in_use) {
        pthread_rwlock_unlock(&g_cfg.acc_lock);
        pthread_mutex_unlock(&g_cfg_transition_mtx);
        return false;
    }
    old_value = g_cfg.readers[index];
    memset(&g_cfg.readers[index], 0, sizeof(g_cfg.readers[index]));
    g_cfg.nreaders = 0; for (int i = 0; i < MAX_READERS; i++) if (g_cfg.readers[i].in_use) g_cfg.nreaders++;
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    bool ok = cfg_save(&g_cfg);
    if (!ok) {
        pthread_rwlock_wrlock(&g_cfg.acc_lock);
        g_cfg.readers[index] = old_value;
        g_cfg.nreaders = 0; for (int i = 0; i < MAX_READERS; i++) if (g_cfg.readers[i].in_use) g_cfg.nreaders++;
        pthread_rwlock_unlock(&g_cfg.acc_lock);
    } else {
        reader_stats_reset(index);
        g_reload_cfg = 1;
    }
    pthread_mutex_unlock(&g_cfg_transition_mtx);
    return ok;
}
