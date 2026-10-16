#define MODULE_LOG_PREFIX "conf"
#include "runtime_access.h"
#include "../core/config_state.h"
#include "../core/utils.h"
#include <pthread.h>
#include <string.h>

bool cfg_runtime_failban_snapshot(S_CONFIG_FAILBAN_VIEW *out)
{
    if (!out) return false;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    out->enabled = g_cfg.failban_enabled != 0;
    out->max_fails = g_cfg.failban_max_fails;
    out->ban_secs = g_cfg.failban_ban_secs;
    tcmg_strlcpy(out->allowlist, g_cfg.failban_allowlist, sizeof(out->allowlist));
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return true;
}

int cfg_runtime_reader_snapshot(S_READER *out, size_t cap)
{
    int n = 0;
    if (!out || cap == 0) return 0;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    for (int i = 0; i < MAX_READERS && (size_t)n < cap; i++) {
        if (!g_cfg.readers[i].in_use) continue;
        out[n++] = g_cfg.readers[i];
    }
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return n;
}

int cfg_runtime_reader_snapshot_indexed(S_READER *out, size_t cap)
{
    if (!out || cap < MAX_READERS) return 0;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    for (int i = 0; i < MAX_READERS; i++)
        out[i] = g_cfg.readers[i];
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return MAX_READERS;
}

bool cfg_runtime_reader_get(int index, S_READER *out)
{
    if (!out || index < 0 || index >= MAX_READERS) return false;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    if (!g_cfg.readers[index].in_use) {
        pthread_rwlock_unlock(&g_cfg.acc_lock);
        return false;
    }
    *out = g_cfg.readers[index];
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return true;
}

bool cfg_runtime_reader_any(bool (*pred)(const S_READER *r, void *ctx), void *ctx)
{
    bool found = false;
    if (!pred) return false;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    for (int i = 0; i < MAX_READERS && !found; i++) {
        if (!g_cfg.readers[i].in_use) continue;
        found = pred(&g_cfg.readers[i], ctx);
    }
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return found;
}

bool cfg_runtime_network_snapshot(S_CONFIG_NETWORK_VIEW *out)
{
    if (!out) return false;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    out->sock_timeout = g_cfg.sock_timeout;
    out->server_keepalive = g_cfg.server_keepalive;
    out->server_keepalive_misses = g_cfg.server_keepalive_misses;
    out->newcamd_keepalive = g_cfg.newcamd_keepalive;
    out->newcamd_mgclient = g_cfg.newcamd_mgclient;
    memcpy(out->newcamd_key, g_cfg.newcamd_key, sizeof(out->newcamd_key));
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return true;
}

bool cfg_runtime_dvbapi_snapshot(S_CONFIG_DVBAPI_VIEW *out)
{
    if (!out) return false;
    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    out->enabled = g_cfg.dvbapi_enabled;
    tcmg_strlcpy(out->user, g_cfg.dvbapi_user, sizeof(out->user));
    tcmg_strlcpy(out->socket, g_cfg.dvbapi_socket, sizeof(out->socket));
    tcmg_strlcpy(out->boxtype, g_cfg.dvbapi_boxtype, sizeof(out->boxtype));
    out->delay_ms = g_cfg.dvbapi_delay_ms;
    out->max_services = g_cfg.dvbapi_max_services;
    out->pmt_mode = g_cfg.dvbapi_pmt_mode;
    out->listen_port = g_cfg.dvbapi_listen_port;
    tcmg_strlcpy(out->serverip, g_cfg.dvbapi_serverip, sizeof(out->serverip));
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return true;
}
