#define MODULE_LOG_PREFIX "webif"
#include "service.h"
#include "../../src/core/config_state.h"
#include "../../src/config/runtime_access.h"
#include "../../src/core/runtime_state.h"
#include "../../src/core/utils.h"
#include "../../src/crypto/crypto.h"
#include "../../src/security/failban.h"
#include "../../src/stats/account_stats.h"
#include "../../src/pcsc/pcsc.h"
#include "../../src/reader/protocol.h"
#include "../internal/proto.h"
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

static bool webif_bind_is_loopback(const char *bindaddr)
{
    struct in_addr addr;
    if (!bindaddr || inet_pton(AF_INET, bindaddr, &addr) != 1) return false;
    return (ntohl(addr.s_addr) & 0xFF000000u) == 0x7F000000u;
}

S_WEBIF_SERVER_STATS webif_server_stats(void)
{
    S_WEBIF_SERVER_STATS s;
    memset(&s, 0, sizeof(s));
    time_t now = time(NULL);

    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    s.naccounts = g_cfg.naccounts;
    pthread_rwlock_unlock(&g_cfg.acc_lock);

    account_stats_global_snapshot(&s.cw_found, &s.cw_not);

    pthread_mutex_lock(&g_cfg.ban_lock);
    for (int i = 0; i < BAN_BUCKETS; i++)
        for (const S_BAN_ENTRY *b = g_cfg.ban_table[i]; b; b = b->next)
            if (b->until > now) s.nbans++;
    pthread_mutex_unlock(&g_cfg.ban_lock);

    s.ecm_total = s.cw_found + s.cw_not;
    s.hit_rate = s.ecm_total > 0
        ? (double)s.cw_found * 100.0 / (double)s.ecm_total
        : 0.0;
    s.active_conns = atomic_load(&g_active_conns);
    s.uptime_s = now - g_start_time;
    format_uptime(s.uptime_s, s.uptime_str, sizeof(s.uptime_str));
    return s;
}

static bool reader_is_enabled_pcsc(const S_READER *r, void *ctx)
{
    (void)ctx;
    return r->enabled &&
           reader_protocol_kind(r->protocol) == READER_PROTOCOL_CARD &&
           strcasecmp(r->protocol, "pcsc") == 0;
}

int webif_pcsc_enabled(void)
{
    return cfg_runtime_reader_any(reader_is_enabled_pcsc, NULL) ? 1 : 0;
}

int webif_ban_snapshot(S_WEBIF_BAN_VIEW *out, size_t cap, S_WEBIF_BAN_STATS *stats)
{
    int n = 0;
    time_t now = time(NULL);
    if (stats) memset(stats, 0, sizeof(*stats));

    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    if (stats) {
        stats->max_fails = g_cfg.failban_max_fails > 0 ? g_cfg.failban_max_fails : BAN_MAX_FAILS;
        stats->ban_secs = g_cfg.failban_ban_secs > 0 ? g_cfg.failban_ban_secs : BAN_SECS;
    }
    pthread_rwlock_unlock(&g_cfg.acc_lock);

    pthread_mutex_lock(&g_cfg.ban_lock);
    for (int i = 0; i < BAN_BUCKETS; i++) {
        for (S_BAN_ENTRY *b = g_cfg.ban_table[i]; b; b = b->next) {
            if (b->until <= now) continue;
            if (stats) {
                stats->active_bans++;
            }
            if (out && (size_t)n < cap) {
                tcmg_strlcpy(out[n].ip, b->ip, sizeof(out[n].ip));
                out[n].until = b->until;
                n++;
            }
        }
    }
    pthread_mutex_unlock(&g_cfg.ban_lock);
    return n;
}

int webif_ban_clear(const char *ip)
{
    int n = 0;
    time_t now = time(NULL);
    if (!ip || !*ip) return 0;

    uint32_t h = ban_hash_pub(ip);
    pthread_mutex_lock(&g_cfg.ban_lock);
    for (S_BAN_ENTRY *b = g_cfg.ban_table[h]; b; b = b->next) {
        if (strcmp(b->ip, ip) != 0) continue;
        if (b->until > now) n++;
        b->until = 0;
        b->fails = 0;
    }
    pthread_mutex_unlock(&g_cfg.ban_lock);
    return n;
}

int webif_ban_clear_all(void)
{
    int n = 0;
    time_t now = time(NULL);
    pthread_mutex_lock(&g_cfg.ban_lock);
    for (int i = 0; i < BAN_BUCKETS; i++) {
        for (S_BAN_ENTRY *b = g_cfg.ban_table[i]; b; b = b->next) {
            if (b->until > now) n++;
            b->until = 0;
            b->fails = 0;
        }
    }
    pthread_mutex_unlock(&g_cfg.ban_lock);
    return n;
}

bool webif_auth_enabled(void)
{
    bool enabled;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    /* With no credentials, authentication may be omitted only when the HTTP
     * listener is explicitly bound to loopback. Empty bind means INADDR_ANY. */
    enabled = g_cfg.webif_user[0] || g_cfg.webif_pass[0] ||
              !webif_bind_is_loopback(g_cfg.webif_bindaddr);
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return enabled;
}

bool webif_auth_basic_valid(const char *header)
{
    if (!header) return false;

    S_WEBIF_CONFIG_VIEW c;
    if (!webif_config_snapshot(&c)) return false;
    /* Never accept an empty Basic credential pair. Local loopback with no
     * configured credentials is handled by webif_auth_enabled() instead. */
    if (!c.webif_user[0] && !c.webif_pass[0]) return false;

    const char *p = header;
    while (*p == ' ' || *p == '\t') p++;
    static const char scheme[] = "Basic";
    if (strncasecmp(p, scheme, sizeof(scheme) - 1) != 0) return false;
    p += sizeof(scheme) - 1;
    if (*p != ' ' && *p != '\t') return false;
    while (*p == ' ' || *p == '\t') p++;

    char got[512];
    size_t n = 0;
    while (*p && *p != '\r' && *p != '\n' && *p != ' ' && *p != '\t' && n + 1 < sizeof(got))
        got[n++] = *p++;
    got[n] = '\0';
    if (!got[0] || *p == ' ' || *p == '\t') return false;

    char creds[256];
    char expected[512];
    snprintf(creds, sizeof(creds), "%s:%s", c.webif_user, c.webif_pass);
    b64_encode(creds, (int)strlen(creds), expected, sizeof(expected));
    return ct_streq(got, expected) != 0;
}

bool webif_credentials_valid(const char *user, const char *pass)
{
    S_WEBIF_CONFIG_VIEW c;
    if (!webif_config_snapshot(&c)) return false;
    if (!c.webif_user[0] && !c.webif_pass[0]) {
        /* Loopback-only mode may omit authentication, but it must not make
         * arbitrary non-empty credentials appear valid to other callers. */
        return webif_bind_is_loopback(c.webif_bindaddr) &&
               (!user || !user[0]) && (!pass || !pass[0]);
    }
    if (!user || !pass) return false;
    return ct_streq(user, c.webif_user) && ct_streq(pass, c.webif_pass);
}

int webif_port(void)
{
    S_WEBIF_CONFIG_VIEW c;
    return webif_config_snapshot(&c) ? c.webif_port : 0;
}

void webif_bindaddr(char *out, size_t sz)
{
    if (!out || sz == 0) return;
    S_WEBIF_CONFIG_VIEW c;
    if (!webif_config_snapshot(&c)) {
        out[0] = '\0';
        return;
    }
    tcmg_strlcpy(out, c.webif_bindaddr, sz);
}

int webif_max_refresh(void)
{
    S_WEBIF_CONFIG_VIEW c;
    return webif_config_snapshot(&c) ? c.webif_refresh : 0;
}
