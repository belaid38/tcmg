#define MODULE_LOG_PREFIX "webif"
#include "service.h"
#include "../../src/client/client.h"
#include "../../src/core/runtime_state.h"
#include "../../src/core/client_state.h"
#include "../../src/core/client_types.h"
#include "../../src/core/config_state.h"
#include "../../src/account/account.h"
#include "../../src/stats/account_stats.h"
#include "../../src/core/utils.h"
#include <pthread.h>
#include <string.h>
int webif_active_connection_count(void)
{
    return atomic_load_explicit(&g_active_conns, memory_order_relaxed);
}

static int snapshot_client(S_WEBIF_CLIENT_VIEW *out, int n, const S_CLIENT *cl, S_ACCOUNT *account)
{
    pthread_mutex_lock((pthread_mutex_t *)&cl->state_mtx);
    tcmg_strlcpy(out[n].user, cl->identity.user, sizeof(out[n].user));
    if (!out[n].user[0] && account) tcmg_strlcpy(out[n].user, account->user, sizeof(out[n].user));
    tcmg_strlcpy(out[n].ip, cl->identity.ip, sizeof(out[n].ip));
    tcmg_strlcpy(out[n].proto, cl->protocol.name[0] ? cl->protocol.name : "unknown", sizeof(out[n].proto));
    tcmg_strlcpy(out[n].channel, cl->ecm.last_channel, sizeof(out[n].channel));
    out[n].caid = cl->ecm.last_caid;
    out[n].sid = cl->ecm.last_srvid;
    out[n].thread_id = cl->identity.thread_id;
    out[n].connect_time = cl->session.connect_time;
    out[n].last_activity = atomic_load_explicit(&cl->session.last_activity, memory_order_relaxed);
    if (!out[n].last_activity) out[n].last_activity = atomic_load_explicit(&cl->ecm.last_ecm_time, memory_order_relaxed);
    if (!out[n].last_activity) out[n].last_activity = cl->session.connect_time;
    pthread_mutex_unlock((pthread_mutex_t *)&cl->state_mtx);
    return n + 1;
}

int webif_client_snapshot_all(S_WEBIF_CLIENT_VIEW *out, size_t cap)
{
    if (!out || !cap) return 0;
    int n = 0;
    pthread_mutex_lock(&g_clients_mtx);
    for (int i = 0; i < MAX_ACTIVE_CLIENTS && (size_t)n < cap; i++) {
        S_CLIENT *cl = g_clients[i];
        if (!cl) continue;
        S_ACCOUNT *account = account_session_acquire(cl);
        if (!account) continue;
        n = snapshot_client(out, n, cl, account);
        {
            S_ACCOUNT_STATS_SNAPSHOT st;
            account_stats_snapshot(account, &st);
            out[n - 1].cw_last_60s = st.cw_last_60s;
        }
        account_release(account);
    }
    pthread_mutex_unlock(&g_clients_mtx);
    return n;
}


void webif_client_kill_by_tid(uint32_t tid) { client_kill_by_tid(tid); }
void webif_client_kill_by_user(const char *user) { client_kill_by_user(user); }
