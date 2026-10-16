#include "core/config_state.h"
#include "core/runtime_state.h"
#include "config/config.h"
#include "log/log.h"
#include "emu/emu.h"
#include "reader/reader.h"
#include "reader/result.h"
#include "reader/stats.h"
#include "account/account.h"
#include "core/utils.h"
#include <stdio.h>
#include <string.h>

static void dump16(const char *p, const unsigned char *b) {
    printf("%s", p);
    for (int i=0;i<16;i++) printf("%02X", b[i]);
    putchar('\n');
}

int main(int argc, char **argv) {
    reader_stats_reset(0);
    S_READER_STATS_SNAPSHOT initial_stats;
    reader_stats_snapshot(0, &initial_stats);
    if (initial_stats.cw_ok != 0 || initial_stats.cw_nok != 0 || initial_stats.active) {
        fprintf(stderr,"FAIL initial reader stats\n");
        return 6;
    }
    reader_stats_record(0, true);
    reader_stats_record(0, false);
    S_READER_STATS_SNAPSHOT sample_stats;
    reader_stats_snapshot(0, &sample_stats);
    if (sample_stats.cw_ok != 1 || sample_stats.cw_nok != 1 || !sample_stats.active) {
        fprintf(stderr,"FAIL reader runtime stats\n");
        return 7;
    }
    reader_stats_reset(0);
    reader_stats_record_timed(0, false, 2);
    S_READER_STATS_SNAPSHOT failed_timing_stats;
    reader_stats_snapshot(0, &failed_timing_stats);
    if (failed_timing_stats.cw_nok != 1 || failed_timing_stats.samples != 0 || failed_timing_stats.avg_ms != 0) {
        fprintf(stderr,"FAIL failed ECM must not train fastest-reader timing\n");
        return 10;
    }
    reader_stats_reset(0);
    reader_stats_job_begin(0);
    S_READER_STATS_SNAPSHOT busy_stats;
    reader_stats_snapshot(0, &busy_stats);
    if (busy_stats.busy != 1) {
        fprintf(stderr,"FAIL reader busy accounting begin=%d\n", busy_stats.busy);
        return 8;
    }
    reader_stats_record_timed(0, true, 40);
    reader_stats_job_end(0);
    S_READER_STATS_SNAPSHOT timed_stats;
    reader_stats_snapshot(0, &timed_stats);
    if (timed_stats.busy != 0 || timed_stats.samples != 1 || timed_stats.avg_ms != 40 || timed_stats.cw_ok != 1) {
        fprintf(stderr,"FAIL timed reader stats busy=%d samples=%u avg=%u cw_ok=%lld\n",
                timed_stats.busy, timed_stats.samples, timed_stats.avg_ms,
                (long long)timed_stats.cw_ok);
        return 9;
    }
    reader_stats_reset(0);
    bool expect_login_fail = false;
    bool expect_negative_cache = false;
    if (argc == 3 && strcmp(argv[2], "expect-login-fail") == 0) expect_login_fail = true;
    if (argc == 3 && strcmp(argv[2], "expect-negative-cache") == 0) expect_negative_cache = true;
    if (argc != 2 && !expect_login_fail && !expect_negative_cache) {
        fprintf(stderr,"usage: %s <config-dir/tcmg.conf> [expect-login-fail|expect-negative-cache]\n", argv[0]);
        return 2;
    }
    if (argc == 3 && !expect_login_fail && !expect_negative_cache) return 2;
    memset(&g_cfg,0,sizeof(g_cfg));
    pthread_rwlock_init(&g_cfg.acc_lock,NULL);
    pthread_mutex_init(&g_cfg.ban_lock,NULL);
    if (!cfg_load(argv[1], &g_cfg)) { fprintf(stderr,"cfg_load failed\n"); return 3; }
    log_init();
    g_dblevel = UINT16_MAX;
    emu_init();
    S_ACCOUNT *acc = account_acquire("client");
    if (!acc) { fprintf(stderr,"account client not found\n"); return 4; }
    S_ECM_REQUEST req; memset(&req,0,sizeof(req)); req.account=acc; req.user="smoke";
    static const unsigned char ecm[] = {
      0x80,0x00,0x34,0x00,0x32,0x64,0x00,
      0x7C,0x99,0xBB,0xE9,0x60,0x61,0x74,0x1D,0x82,0xC3,0x57,0x47,0xD5,0x26,0x2E,0x0A,0x0E,
      0x76,0x46,0xAB,0x26,0x35,0x50,0x1A,0xF2,0x63,0xD7,0x26,0x1D,0xC1,0x4F,0x0C,0xF2,
      0x63,0xD7,0x26,0x1D,0xC1,0x4F,0x0C,0x16,0x88,0x9C,0x7D,0x01,0x21,0x9A,0x20
    };
    static const unsigned char expected[16] = {
      0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
      0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
    };
    int overall = 0;
    if (expect_login_fail) {
        unsigned char cw[16]={0};
        S_READER_RESULT result; int32_t rc; req.caid=0x0B00; req.sid=0x0064; req.provid=0; req.ecm=ecm; req.ecm_len=sizeof(ecm); req.cw=cw; rc=reader_dispatch_ecm(&req,&result);
        printf("expected-login-fail rc=%d\n", rc);
        if (rc == 0) {
            fprintf(stderr,"FAIL: login unexpectedly succeeded\n");
            overall = 1;
        }
    }
    else if (expect_negative_cache) {
        int reader_index = -1;
        for (int i = 0; i < MAX_READERS; i++) {
            if (!g_cfg.readers[i].in_use) continue;
            if (reader_index < 0) reader_index = i;
            else g_cfg.readers[i].enabled = 0;
        }
        if (reader_index < 0) {
            fprintf(stderr,"FAIL: negative-cache test has no configured reader\n");
            overall = 1;
        } else {
            S_READER *reader = &g_cfg.readers[reader_index];
            tcmg_strlcpy(reader->protocol, "emu", sizeof(reader->protocol));
            reader->nkeys = 0;
            reader->ecm_whitelist = 0;
            reader->ecm_whitelist_count = 0;
            g_cfg.lb_mode = 1;
            g_cfg.lb_nbest_readers = 1;
            reader_stats_reset(reader_index);
            unsigned char cw[16] = {0};
            S_READER_RESULT first, second;
            req.caid = 0x0B00; req.sid = 0x0064; req.provid = 0;
            req.ecm = ecm; req.ecm_len = sizeof(ecm); req.cw = cw;
            int32_t rc1 = reader_dispatch_ecm(&req, &first);
            S_READER_STATS_SNAPSHOT before, after;
            reader_stats_snapshot(reader_index, &before);
            int32_t rc2 = reader_dispatch_ecm(&req, &second);
            reader_stats_snapshot(reader_index, &after);
            printf("negative-cache rc1=%d rc2=%d nok_before=%lld nok_after=%lld\n",
                   rc1, rc2, (long long)before.cw_nok, (long long)after.cw_nok);
            if (rc1 == EMU_OK || rc2 == EMU_OK || before.cw_nok < 1 ||
                after.cw_nok != before.cw_nok || after.samples != before.samples) {
                fprintf(stderr,"FAIL: exact repeated NOT_FOUND was not suppressed\n");
                overall = 1;
            }
        }
    }
    else {
        int configured_readers = 0;
        int first_reader = -1;
        for (int i = 0; i < MAX_READERS; i++) {
            if (!g_cfg.readers[i].in_use) continue;
            g_cfg.readers[i].enabled = 1;
            g_cfg.readers[i].ecm_whitelist = (int32_t)sizeof(ecm) - 1;
            if (first_reader < 0) first_reader = i;
            configured_readers++;
        }
        if (configured_readers > 0) {
            unsigned char rejected_cw[16] = {0};
            S_READER_RESULT rejected_result;
            req.caid=0x0B00; req.sid=0x0064; req.provid=0; req.ecm=ecm;
            req.ecm_len=sizeof(ecm); req.cw=rejected_cw;
            int32_t rejected_rc = reader_dispatch_ecm(&req, &rejected_result);
            S_READER_STATS_SNAPSHOT rejected_stats;
            reader_stats_snapshot(first_reader, &rejected_stats);
            if (rejected_rc != READER_RESULT_REJECTED ||
                rejected_result.status != READER_RESULT_REJECTED ||
                rejected_stats.cw_nok != 0) {
                fprintf(stderr,"FAIL whitelist rejection rc=%d status=%d cw_nok=%lld\n",
                        rejected_rc, rejected_result.status, (long long)rejected_stats.cw_nok);
                overall = 1;
            }

            for (int i = 0; i < MAX_READERS; i++) {
                if (g_cfg.readers[i].in_use) g_cfg.readers[i].ecm_whitelist = 0;
            }
        }

        for (int round=1; round<=3; round++) {
        unsigned char cw[16]={0};
        S_READER_RESULT result; int rc; req.caid=0x0B00; req.sid=0x0064; req.provid=0; req.ecm=ecm; req.ecm_len=sizeof(ecm); req.cw=cw; rc=reader_dispatch_ecm(&req,&result);
        printf("round=%d rc=%d ng=%d\n",round,rc,result.ngroups);
        dump16("cw=",cw);
        if (rc != 0 || memcmp(cw, expected, 16) != 0 || result.ngroups != 1 || result.groups[0] != 1) {
            fprintf(stderr,"FAIL round=%d\n",round);
            overall = 1;
        }
    }
    }
    account_release(acc);
    reader_shutdown(); cfg_accounts_free(&g_cfg); pthread_rwlock_destroy(&g_cfg.acc_lock); pthread_mutex_destroy(&g_cfg.ban_lock);
    return overall ? 5 : 0;
}
