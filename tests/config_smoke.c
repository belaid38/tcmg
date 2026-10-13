#include "core/config_state.h"
#include "config/config.h"
#include "config/config_internal.h"
#include "account/account.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
static int write_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t n;
    if (!f) return 0;
    n = strlen(text);
    if (fwrite(text, 1, n, f) != n) {
        fclose(f);
        return 0;
    }
    if (fclose(f) != 0) return 0;
    return 1;
}
static int init_cfg(S_CONFIG *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    if (pthread_rwlock_init(&cfg->acc_lock, NULL) != 0) return 0;
    if (pthread_mutex_init(&cfg->ban_lock, NULL) != 0) {
        pthread_rwlock_destroy(&cfg->acc_lock);
        return 0;
    }
    return 1;
}
static void free_cfg(S_CONFIG *cfg)
{
    if (!cfg) return;
    cfg_accounts_free(cfg);
    pthread_rwlock_destroy(&cfg->acc_lock);
    pthread_mutex_destroy(&cfg->ban_lock);
}
static int run_save_stress(S_CONFIG *cfg);
static int load_case(const char *dir, const char *global, const char *users, const char *readers, const char *expect)
{
    char path[1024];
    char text[4096];
    S_CONFIG cfg;
    int ok;
    snprintf(path, sizeof(path), "%s/tcmg.conf", dir);
    if (!write_text(path, global)) { fprintf(stderr, "write global: %s\n", strerror(errno)); return 0; }
    snprintf(path, sizeof(path), "%s/tcmg.users", dir);
    if (!write_text(path, users)) { fprintf(stderr, "write users: %s\n", strerror(errno)); return 0; }
    snprintf(path, sizeof(path), "%s/tcmg.readers", dir);
    if (!write_text(path, readers)) { fprintf(stderr, "write readers: %s\n", strerror(errno)); return 0; }
    if (!init_cfg(&cfg)) return 0;
    snprintf(path, sizeof(path), "%s/tcmg.conf", dir);
    ok = cfg_load(path, &cfg);
    if (ok != (expect == NULL)) {
        fprintf(stderr, "expected %s, got %s\n", expect ? "failure" : "success", ok ? "success" : "failure");
        free_cfg(&cfg);
        return 0;
    }
    if (ok) {
        int expected_sched = strstr(global, "scheduled_restart = 1") != NULL ? 1 : 0;
        int expected_minutes = 0;
        const char *st = strstr(global, "scheduled_restart_time = ");
        if (st) {
            int hh = -1, mm = -1;
            if (sscanf(st, "scheduled_restart_time = %d:%d", &hh, &mm) == 2 && hh >= 0 && hh <= 23 && mm >= 0 && mm <= 59)
                expected_minutes = hh * 60 + mm;
        }
        if (cfg.scheduled_restart_enabled != expected_sched || cfg.scheduled_restart_minutes != expected_minutes) {
            fprintf(stderr, "scheduled restart defaults/parse mismatch enabled=%d minutes=%d expected=%d/%d\n",
                    cfg.scheduled_restart_enabled, cfg.scheduled_restart_minutes, expected_sched, expected_minutes);
            free_cfg(&cfg);
            return 0;
        }
        if (cfg.naccounts != 2 || cfg.nreaders != 6) {
            fprintf(stderr, "unexpected counts accounts=%d readers=%d\n", cfg.naccounts, cfg.nreaders);
            free_cfg(&cfg);
            return 0;
        }
        if (cfg.readers[5].fast_reset != 1) {
            fprintf(stderr, "internal fast_reset user value changed value=%d\n", cfg.readers[5].fast_reset);
            free_cfg(&cfg);
            return 0;
        }
        if (strstr(readers, "maintenance_mode = old_ecm")) {
            if (cfg.readers[5].maintenance_mode != TCMG_READER_MAINT_OLD_ECM ||
                cfg.readers[5].old_ecm_source != TCMG_OLD_ECM_SOURCE_MANUAL ||
                cfg.readers[5].old_ecm_successes != 7 ||
                strcmp(cfg.readers[5].old_ecm, "817034703264216EB6EFA65A38468DA2AC005F1CC011508CA82E3E4E0F74462096EE21A7F0DD1E57DD46FF3C5133886CB0861005D9E89C") != 0) {
                fprintf(stderr, "old ECM config parse mismatch\n");
                free_cfg(&cfg);
                return 0;
            }
        }
        S_ACCOUNT *held = NULL;
        pthread_rwlock_rdlock(&cfg.acc_lock);
        for (S_ACCOUNT *a = cfg.accounts; a; a = a->next) {
            if (!strcmp(a->user, "client")) { held = a; break; }
        }
        pthread_rwlock_unlock(&cfg.acc_lock);
        if (!held) {
            fprintf(stderr, "client account not present\n");
            free_cfg(&cfg);
            return 0;
        }
        if (!cfg_save(&cfg)) {
            fprintf(stderr, "cfg_save failed\n");
            free_cfg(&cfg);
            return 0;
        }
        if (!run_save_stress(&cfg)) {
            fprintf(stderr, "concurrent cfg_save stress failed\n");
            free_cfg(&cfg);
            return 0;
        }
        S_CONFIG roundtrip;
        if (!init_cfg(&roundtrip)) { free_cfg(&cfg); return 0; }
        if (!cfg_load(path, &roundtrip) || roundtrip.naccounts != 2 || roundtrip.nreaders != 6) {
            fprintf(stderr, "roundtrip reload failed\n");
            free_cfg(&roundtrip); free_cfg(&cfg); return 0;
        }
        if (strstr(readers, "maintenance_mode = old_ecm")) {
            if (roundtrip.readers[5].maintenance_mode != TCMG_READER_MAINT_OLD_ECM ||
                roundtrip.readers[5].old_ecm_source != TCMG_OLD_ECM_SOURCE_MANUAL ||
                roundtrip.readers[5].old_ecm_successes != 7 ||
                strcmp(roundtrip.readers[5].old_ecm, "817034703264216EB6EFA65A38468DA2AC005F1CC011508CA82E3E4E0F74462096EE21A7F0DD1E57DD46FF3C5133886CB0861005D9E89C") != 0) {
                fprintf(stderr, "old ECM config roundtrip failed\n");
                free_cfg(&roundtrip); free_cfg(&cfg); return 0;
            }
        }
        free_cfg(&roundtrip);
    }
    snprintf(text, sizeof(text), "%s", expect ? expect : "ok");
    (void)text;
    free_cfg(&cfg);
    return 1;
}
static void *save_stress_thread(void *arg)
{
    S_CONFIG *cfg = (S_CONFIG *)arg;
    for (int i = 0; i < 20; i++)
        if (!cfg_save(cfg)) return (void *)1;
    return NULL;
}
static int run_save_stress(S_CONFIG *cfg)
{
    enum { THREADS = 4 };
    pthread_t tids[THREADS];
    for (int i = 0; i < THREADS; i++)
        if (pthread_create(&tids[i], NULL, save_stress_thread, cfg) != 0) {
            for (int j = 0; j < i; j++) pthread_join(tids[j], NULL);
            return 0;
        }
    for (int i = 0; i < THREADS; i++) {
        void *ret = NULL;
        if (pthread_join(tids[i], &ret) != 0 || ret != NULL) return 0;
    }
    return 1;
}
static int run_reload_lifetime(const char *dir)
{
    const char *global =
        "[global]\n"
        "socket_timeout = 30\nserver_keepalive = 20\nserver_keepalive_misses = 3\necm_log = 0\nscheduled_restart = 0\nscheduled_restart_time = 03:15\nlogfile =\nusrfile =\n"
        "[webif]\nenabled = 0\nport = 18080\nrefresh = 1\nuser =\npassword =\nbindaddr =\n"
        "[newcamd]\nport = 19050\nbindaddr =\nkey = 0102030405060708091011121314\nkeepalive = 0\nmode = auto\n"
        "[cccam]\nport = 19060\nbindaddr =\n"
        "[cs378x]\nport = 19070\nbindaddr =\n"
        "[failban]\nenabled = 0\nallowlist =\nmax_fails = 5\nban_secs = 300\n";
    const char *users_a =
        "[account]\nuser = client\npwd = one\nenabled = 1\ngroup = 1\ncaid = 0B00\n"
        "[account]\nuser = second\npwd = two\nenabled = 1\ngroup = 2\ncaid = 0B00\n";
    const char *users_b =
        "[account]\nuser = client\npwd = changed\nenabled = 1\ngroup = 1\ncaid = 0B00\n"
        "[account]\nuser = second\npwd = two\nenabled = 1\ngroup = 2\ncaid = 0B00\n";
    const char *readers =
        "[reader]\nlabel = emu\nprotocol = emu\nenabled = 1\ngroup = 1\ncaid = 0B00\necmwhitelist = 37\ninactivitytimeout = 30\n"
        "ecmkey = 0B00=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF\n";
    char path[1024], users_path[1024];
    char err[256] = "";
    S_ACCOUNT *old, *fresh;
    memset(&g_cfg, 0, sizeof(g_cfg));
    if (pthread_rwlock_init(&g_cfg.acc_lock, NULL) != 0) return 0;
    if (pthread_mutex_init(&g_cfg.ban_lock, NULL) != 0) {
        pthread_rwlock_destroy(&g_cfg.acc_lock);
        return 0;
    }
    snprintf(path, sizeof(path), "%s/tcmg.conf", dir);
    snprintf(users_path, sizeof(users_path), "%s/tcmg.users", dir);
    if (!write_text(path, global) || !write_text(users_path, users_a)) goto fail;
    snprintf(path, sizeof(path), "%s/tcmg.readers", dir);
    if (!write_text(path, readers)) goto fail;
    snprintf(path, sizeof(path), "%s/tcmg.conf", dir);
    if (!cfg_load(path, &g_cfg)) goto fail;
    if (g_cfg.readers[0].ecm_whitelist != 0x37) goto fail;
    old = account_acquire("client");
    if (!old) goto fail;
    if (!write_text(users_path, users_b)) {
        account_release(old);
        goto fail;
    }
    if (!cfg_reload(path, err, sizeof(err))) {
        fprintf(stderr, "reload lifetime failed: %s\n", err);
        account_release(old);
        goto fail;
    }
    fresh = account_acquire("client");
    if (!fresh || fresh == old || strcmp(fresh->pass, "changed") != 0) {
        fprintf(stderr, "account replacement/reference test failed\n");
        account_release(old);
        if (fresh) account_release(fresh);
        goto fail;
    }
    account_release(fresh);
    account_release(old);
    account_reap_retired();
    cfg_accounts_free(&g_cfg);
    pthread_rwlock_destroy(&g_cfg.acc_lock);
    pthread_mutex_destroy(&g_cfg.ban_lock);
    account_retired_free();
    return 1;
fail:
    cfg_accounts_free(&g_cfg);
    account_retired_free();
    pthread_rwlock_destroy(&g_cfg.acc_lock);
    pthread_mutex_destroy(&g_cfg.ban_lock);
    return 0;
}

static int run_first_start_defaults(const char *dir)
{
    char cfgpath[1024], userspath[1024], readerspath[1024];
    S_CONFIG cfg;
    uint8_t zero_key[14] = {0};
    snprintf(cfgpath, sizeof(cfgpath), "%s/first/tcmg.conf", dir);
    snprintf(userspath, sizeof(userspath), "%s/first/tcmg.users", dir);
    snprintf(readerspath, sizeof(readerspath), "%s/first/tcmg.readers", dir);
    char first_dir[1024];
    snprintf(first_dir, sizeof(first_dir), "%s/first", dir);
    if (mkdir(first_dir, 0700) != 0) return 0;
    if (!cfg_write_default(cfgpath)) return 0;
    if (!init_cfg(&cfg)) return 0;
    if (!cfg_load(cfgpath, &cfg)) { free_cfg(&cfg); return 0; }
    if (cfg.naccounts != 0 || cfg.nreaders != 0) { free_cfg(&cfg); return 0; }
    if (cfg.webif_enabled != 1 || cfg.webif_port != 8585 || strcmp(cfg.webif_bindaddr, "0.0.0.0") != 0) { free_cfg(&cfg); return 0; }
    if (cfg.cccam_port != 0 || cfg.newcamd_port != 0 || cfg.cs378x_port != 0) { free_cfg(&cfg); return 0; }
    if (cfg.scheduled_restart_enabled != 0 || cfg.scheduled_restart_minutes != 0) { free_cfg(&cfg); return 0; }
    if (memcmp(cfg.newcamd_key, zero_key, sizeof(zero_key)) != 0) { free_cfg(&cfg); return 0; }
    free_cfg(&cfg);
    return access(userspath, F_OK) == 0 && access(readerspath, F_OK) == 0;
}

int main(void)
{
    char dir[] = "/tmp/tcmg-config-smoke-XXXXXX";
    char path[1024];
    const char *global =
        "[global]\n"
        "socket_timeout = 30\nserver_keepalive = 20\nserver_keepalive_misses = 3\necm_log = 1\nscheduled_restart = 1\nscheduled_restart_time = 04:00\nlogfile =\nusrfile =\n"
        "[webif]\nenabled = 0\nport = 18080\nrefresh = 1\nuser = admin\npassword = change\nbindaddr =\n"
        "[newcamd]\nport = 18050\nbindaddr =\nkey = 0102030405060708091011121314\nkeepalive = 0\nmode = auto\n"
        "[cccam]\nport = 18060\nbindaddr =\n"
        "[cs378x]\nport = 18070\nbindaddr =\n"
        "[failban]\nenabled = 0\nallowlist =\nmax_fails = 5\nban_secs = 300\n";
    const char *users =
        "[account]\nuser = client\npwd = one\nenabled = 1\ngroup = 1\ncaid = 0B00\nmax_connections = 2\nexpiration = 0\n"
        "[account]\nuser = second\npwd = two\nenabled = 1\ngroup = 2\ncaid = 0B00\nmax_connections = 1\nexpiration = 0\n";
    const char *readers =
        "[reader]\nlabel = emu\nprotocol = emu\nenabled = 1\ngroup = 1\ncaid = 0B00\necmwhitelist = 00\ninactivitytimeout = 30\n"
        "ecmkey = 0B00=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF\n"
        "[reader]\nlabel = cccam\nprotocol = cccam\nenabled = 0\ngroup = 1\ndevice = 127.0.0.1,12050\n"
        "[reader]\nlabel = newcamd\nprotocol = newcamd\nenabled = 0\ngroup = 1\ndevice = 127.0.0.1,15050\nuser = client\nkey = 0102030405060708091011121314\n"
        "[reader]\nlabel = mgcamd\nprotocol = mgcamd\nenabled = 0\ngroup = 1\ndevice = 127.0.0.1,15050\nuser = client\nkey = 0102030405060708091011121314\n"
        "[reader]\nlabel = cs378x\nprotocol = cs378x\nenabled = 0\ngroup = 1\ndevice = 127.0.0.1,15052\n"
        "[reader]\nlabel = internal-sci\nprotocol = internal\nenabled = 0\ngroup = 1\ndevice = /dev/sci0\ndo_ecm = 1\nmaintenance_mode = old_ecm\nold_ecm_source = manual\nold_ecm_trigger = interval\nold_ecm_interval = 30\nold_ecm_successes = 7\necmwhitelist = 37\nold_ecm = 817034703264216EB6EFA65A38468DA2AC005F1CC011508CA82E3E4E0F74462096EE21A7F0DD1E57DD46FF3C5133886CB0861005D9E89C\nfast_reset = 1\npoll_ms = 100\n";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
    if (!run_first_start_defaults(dir)) { fprintf(stderr, "first-start defaults test failed\n"); return 9; }
    if (!load_case(dir, global, users, readers, NULL)) return 3;
    const char *tolerant_global =
        "[global]\n"
        "socket_timeout = 30\n"
        "bad_line_without_equals\n"
        "server_keepalive = broken\n"
        "[unknown]\n"
        "foo = bar\n"
        "[webif]\n"
        "enabled = 0\nport = 18080\nrefresh = 1\nuser = admin\npassword = change\nbindaddr =\n"
        "[newcamd]\nport = 18050\nbindaddr =\nkey = 0102030405060708091011121314\nkeepalive = 0\nmode = auto\n"
        "[cccam]\nport = 18060\nbindaddr =\n"
        "[cs378x]\nport = 18070\nbindaddr =\n"
        "[failban]\nenabled = 0\nallowlist =\nmax_fails = 5\nban_secs = 300\n";
    const char *tolerant_users =
        "[account]\nuser = client\npwd = one\nenabled = 1\ngroup = 1\ncaid = 0B00\n"
        "unknown_setting = ignored\nmax_connections = nope\n"
        "[unknown]\nuser = ignored\n"
        "[account]\nuser = second\npwd = two\nenabled = 1\ngroup = 2\ncaid = 0B00\n";
    const char *tolerant_readers =
        "[reader]\nlabel = emu\nprotocol = emu\nenabled = 1\ngroup = 1\ncaid = 0B00\necmwhitelist = 00\ninactivitytimeout = 30\n"
        "broken_reader_line\nfast_reset = invalid\n"
        "ecmkey = 0B00=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF\n"
        "[unknown]\nlabel = ignored\n"
        "[reader]\nlabel = cccam\nprotocol = cccam\nenabled = 0\ngroup = 1\ndevice = 127.0.0.1,12050\n"
        "unknown_setting = ignored\n"
        "[reader]\nlabel = newcamd\nprotocol = newcamd\nenabled = 0\ngroup = 1\ndevice = 127.0.0.1,15050\nuser = client\nkey = 0102030405060708091011121314\n"
        "[reader]\nlabel = mgcamd\nprotocol = mgcamd\nenabled = 0\ngroup = 1\ndevice = 127.0.0.1,15050\nuser = client\nkey = 0102030405060708091011121314\n"
        "[reader]\nlabel = cs378x\nprotocol = cs378x\nenabled = 0\ngroup = 1\ndevice = 127.0.0.1,15052\n"
        "[reader]\nlabel = internal-sci\nprotocol = internal\nenabled = 0\ngroup = 1\ndevice = /dev/sci0\ndo_ecm = 1\nfast_reset = 1\npoll_ms = 100\n";
    if (!load_case(dir, tolerant_global, tolerant_users, tolerant_readers, NULL)) return 4;
    const char *bad_unknown = "[global]\nsocket_timeout = 30\nnot_a_setting = 1\n";
    if (!load_case(dir, bad_unknown, users, readers, NULL)) return 5;
    const char *bad_dupe =
        "[global]\nsocket_timeout = 30\n[webif]\nenabled = 0\nport = 18080\n"
        "[newcamd]\nport = 18050\nkey = 0102030405060708091011121314\n[cccam]\nport = 18060\n[cs378x]\nport = 18070\n[failban]\nenabled = 0\n";
    const char *dupe_users =
        "[account]\nuser = client\npwd = one\ngroup = 1\n[account]\nuser = client\npwd = two\ngroup = 1\n";
    if (!load_case(dir, bad_dupe, dupe_users, readers, "duplicate")) return 6;
    const char *bad_emu =
        "[global]\nsocket_timeout = 30\n[webif]\nenabled = 0\nport = 18080\n"
        "[newcamd]\nport = 18050\nkey = 0102030405060708091011121314\n[cccam]\nport = 18060\n[cs378x]\nport = 18070\n[failban]\nenabled = 0\n";
    const char *bad_reader = "[reader]\nlabel = bad\nprotocol = emu\nenabled = 1\ngroup = 1\ncaid = 0B00\n";
    if (!load_case(dir, bad_emu, users, bad_reader, "emu-key")) return 7;
    const char *bad_conflict =
        "[global]\nsocket_timeout = 30\n[webif]\nenabled = 0\nport = 18080\n"
        "[newcamd]\nport = 18050\nkey = 0102030405060708091011121314\n[cccam]\nport = 18050\n[cs378x]\nport = 18070\n[failban]\nenabled = 0\n";
    if (!load_case(dir, bad_conflict, users, readers, "port-conflict")) return 8;
    if (!run_reload_lifetime(dir)) return 9;
    snprintf(path, sizeof(path), "%s/tcmg.conf", dir); remove(path);
    snprintf(path, sizeof(path), "%s/tcmg.users", dir); remove(path);
    snprintf(path, sizeof(path), "%s/tcmg.readers", dir); remove(path);
    rmdir(dir);
    puts("CONFIG_SMOKE: PASS");
    return 0;
}
