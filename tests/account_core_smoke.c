#include "account/account.h"
#include "ecm/ecm.h"
#include "core/config_state.h"
#include "client/client.h"
#include "stats/account_stats.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

static void init_account(S_ACCOUNT *a)
{
    memset(a, 0, sizeof(*a));
    a->enabled = 1;
    a->max_connections = 1;
    a->caid = 0x0B00;
    a->ncaids = 0;
    a->sid_whitelist[0] = 0x1234;
    a->nsid_whitelist = 1;
    a->anti_share = 0;
    a->expirationdate = 0;
    a->sched_day_from = -1;
    a->sched_day_to = -1;
}

int main(void)
{
    S_ACCOUNT account;
    S_CLIENT first;
    S_CLIENT second;
    pthread_rwlock_init(&g_cfg.acc_lock, NULL);
    init_account(&account);
    client_init(&first, 42, "192.0.2.10");
    assert(first.session.fd == 42);
    assert(strcmp(first.identity.ip, "192.0.2.10") == 0);
    assert(first.session.connect_time > 0);
    assert(first.session.last_activity == first.session.connect_time);
    assert(first.ecm.last_ecm_time == first.session.connect_time);
    memset(&second, 0, sizeof(second));

    assert(account_validate(&account, "127.0.0.1") == ACCOUNT_OK);
    assert(account_allows_caid(&account, 0x0B00));
    assert(!account_allows_caid(&account, 0x0500));
    assert(account_allows_sid(&account, 0x1234));
    assert(!account_allows_sid(&account, 0x0001));
    assert(account_in_schedule(&account));

    memset(g_cfg.readers, 0, sizeof(g_cfg.readers));
    g_cfg.readers[0].in_use = 1;
    g_cfg.readers[0].enabled = 1;
    g_cfg.readers[0].ngroups = 1;
    g_cfg.readers[0].groups[0] = 1;
    g_cfg.readers[0].ncaids = 1;
    g_cfg.readers[0].caids[0] = 0x0B00;
    g_cfg.readers[1].in_use = 1;
    g_cfg.readers[1].enabled = 1;
    g_cfg.readers[1].ngroups = 1;
    g_cfg.readers[1].groups[0] = 2;
    g_cfg.readers[1].ncaids = 1;
    g_cfg.readers[1].caids[0] = 0x0500;

    account.caid = 0;
    account.ngroups = 1;
    account.groups[0] = 1;
    account.group = 1;
    assert(account_allows_caid(&account, 0x0B00));
    assert(account_allows_caid(&account, 0x0500));
    account.caid = 0x0B00;
    assert(account_allows_caid(&account, 0x0B00));
    assert(!account_allows_caid(&account, 0x0500));
    account.caid = 0;
    account.nidents = 1;
    account.idents[0].caid = 0x0B00;
    account.idents[0].provid = 0x000001;
    assert(account_allows_ident(&account, 0x0B00, 0x000001));
    assert(!account_allows_ident(&account, 0x0B00, 0x000002));
    assert(!account_allows_ident(&account, 0x0500, 0x000001));
    account.nidents = 0;

    assert(account_stats_init(&account.stats));
    int64_t global_found0 = 0, global_not0 = 0;
    int64_t global_found1 = 0, global_not1 = 0;
    account_stats_global_snapshot(&global_found0, &global_not0);
    account_stats_mark_login(&account, "192.0.2.10");
    account_stats_record_ecm(&account, true, 25);
    account_stats_record_ecm(&account, false, 0);
    account_stats_record_ecm_result(&account, ACCOUNT_ECM_REJECTED, 2);
    account_stats_global_snapshot(&global_found1, &global_not1);
    assert(global_found1 == global_found0 + 1 && global_not1 == global_not0 + 1);
    S_ACCOUNT_STATS_SNAPSHOT stats;
    account_stats_snapshot(&account, &stats);
    assert(stats.ecm_total == 3);
    assert(stats.cw_found == 1);
    assert(stats.cw_not == 1);
    assert(stats.cw_time_total_ms == 25);
    assert(stats.cw_last_60s == 1);
    assert(strcmp(stats.last_ip, "192.0.2.10") == 0);
    account_stats_reset(&account);
    account_stats_snapshot(&account, &stats);
    assert(stats.ecm_total == 0 && stats.cw_found == 0 && stats.cw_not == 0 && stats.cw_last_60s == 0);
    account_stats_global_snapshot(&global_found1, &global_not1);
    assert(global_found1 == global_found0 && global_not1 == global_not0);
    account_stats_record_ecm(&account, true, 5);
    account_stats_global_remove(&account);
    account_stats_global_snapshot(&global_found1, &global_not1);
    assert(global_found1 == global_found0 && global_not1 == global_not0);
    account_stats_destroy(&account.stats);

    account.enabled = 0;
    assert(account_validate(&account, "127.0.0.1") == ACCOUNT_DISABLED);
    account.enabled = 1;
    account.expirationdate = time(NULL) - 1;
    assert(account_validate(&account, "127.0.0.1") == ACCOUNT_EXPIRED);
    account.expirationdate = 0;
    atomic_init(&account.active, 0);
    atomic_init(&account.refs, 1);

    first.auth.account = &account;
    assert(account_session_open(&first, &account) == 0);
    assert(account.active == 1);
    assert(first.auth.counted);
    assert(account_session_open(&second, &account) != 0);
    account_session_close(&first);
    assert(account.active == 0);
    assert(!first.auth.counted);

    first.auth.account = &account;
    account.caid = 0x0B00;
    assert(ecm_access(&first, 0x0B00, 0x1234, 0) == ECM_ACCESS_OK);
    assert(ecm_access(&first, 0x0500, 0x1234, 0) == ECM_ACCESS_CAID_DENIED);
    account.caid = 0;
    assert(ecm_access(&first, 0x0500, 0x1234, 0) == ECM_ACCESS_OK);
    account.nidents = 1;
    account.idents[0].caid = 0x0B00;
    account.idents[0].provid = 0x000001;
    assert(ecm_access(&first, 0x0B00, 0x1234, 0x000001) == ECM_ACCESS_OK);
    assert(ecm_access(&first, 0x0B00, 0x1234, 0x000002) == ECM_ACCESS_IDENT_DENIED);
    assert(ecm_access(&first, 0x0500, 0x1234, 0x000001) == ECM_ACCESS_IDENT_DENIED);
    account.nidents = 0;
    assert(ecm_access(&first, 0x0B00, 0x0001, 0) == ECM_ACCESS_SID_DENIED);

    /* The schedule check must be enforced regardless of which protocol calls
     * ecm_access(). Force the account window to tomorrow only. */
    time_t now = time(NULL);
    struct tm local_now;
    assert(localtime_r(&now, &local_now) != NULL);
    int current_wday = (local_now.tm_wday == 0) ? 6 : local_now.tm_wday - 1;
    int tomorrow_wday = (current_wday + 1) % 7;
    account.sched_day_from = (int8_t)tomorrow_wday;
    account.sched_day_to = (int8_t)tomorrow_wday;
    assert(ecm_access(&first, 0x0B00, 0x1234, 0) == ECM_ACCESS_SCHEDULE);
    account.sched_day_from = -1;
    account.sched_day_to = -1;

    first.auth.account = NULL;
    assert(ecm_access(&first, 0x0B00, 0x1234, 0) == ECM_ACCESS_NO_ACCOUNT);

    pthread_rwlock_destroy(&g_cfg.acc_lock);
    puts("account_core_smoke: PASS");
    return 0;
}
