#define MODULE_LOG_PREFIX "pcsc"
#include "pcsc.h"
#include "../config/runtime_access.h"
#include "../core/utils.h"
#include "../log/log.h"
#include "../platform/platform.h"
#include "../crypto/crypto.h"
#include "../reader/old_ecm.h"

#ifdef TCMG_PCSC
#  ifdef TCMG_OS_WINDOWS
#    include <winscard.h>
#  else
#    include <PCSC/winscard.h>
#    include <PCSC/wintypes.h>
#  endif
#endif

#ifdef TCMG_PCSC
#  ifdef TCMG_OS_WINDOWS
#    define TCMG_SCARD_CONNECT  SCardConnectA
#    define TCMG_SCARD_STATUS   SCardStatusA
#    define TCMG_SCARD_LIST     SCardListReadersA
#  else
#    define TCMG_SCARD_CONNECT  SCardConnect
#    define TCMG_SCARD_STATUS   SCardStatus
#    define TCMG_SCARD_LIST     SCardListReaders
#  endif
#endif

static pthread_mutex_t s_pcsc_mtx = PTHREAD_MUTEX_INITIALIZER;
static S_PCSC_READER  s_readers[TCMG_PCSC_MAX_READERS];
static int             s_reader_count = 0;
static _Atomic int8_t  s_running = 0;
static _Atomic int8_t  s_available = 0;
#ifdef TCMG_PCSC
static _Atomic int32_t s_ecm_active[TCMG_PCSC_MAX_READERS];
static _Atomic uint32_t s_last_activity_ms[TCMG_PCSC_MAX_READERS];
static S_READER_OLD_ECM_STATE s_old_ecm[MAX_READERS];
static pthread_t       s_tid;
#endif

#ifdef TCMG_PCSC
static SCARDCONTEXT s_ctx = 0;
typedef struct {
    SCARDHANDLE card;
    DWORD protocol;
    int valid;
    char name[TCMG_PCSC_READER_NAME_MAX];
} S_PCSC_CARD;
static S_PCSC_CARD s_cards[TCMG_PCSC_MAX_READERS];

static void pcsc_drop_card_locked(int idx);
static void pcsc_drop_all_cards_locked(void);
static void pcsc_drop_stale_cards_locked(const S_PCSC_READER *readers, int count);
static int pcsc_ensure_card_locked(const char *reader);
static int pcsc_card_slot_locked(const char *reader);
static LONG pcsc_transmit_locked(int idx, const uint8_t *cmd, size_t cmd_len,
                                 uint8_t *rsp, size_t *rsp_len);
static int pcsc_parse_conax_cw(const uint8_t *rsp, size_t rsp_len, uint8_t cw[CW_LEN], int *found_mask);
static int pcsc_resolve_reader_locked(const char *selector);
#endif

#ifdef TCMG_PCSC
static const char *pcsc_rc_name(long rc)
{
    switch (rc) {
    case SCARD_S_SUCCESS:          return "success";
    case SCARD_E_NO_SMARTCARD:     return "no-smartcard";
    case SCARD_E_READER_UNAVAILABLE:return "reader-unavailable";
    case SCARD_E_NO_SERVICE:       return "no-service";
    case SCARD_E_SERVICE_STOPPED:  return "service-stopped";
    case SCARD_E_INVALID_HANDLE:    return "invalid-handle";
    case SCARD_W_REMOVED_CARD:     return "card-removed";
    case SCARD_E_SHARING_VIOLATION:return "sharing-violation";
    default:                       return "pcsc-error";
    }
}

static int pcsc_ensure_context_locked(void)
{
    if (s_ctx) return 0;

    LONG rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &s_ctx);
    if (rc != SCARD_S_SUCCESS) {
        s_ctx = 0;
        atomic_store(&s_available, 0);
        return -1;
    }

    atomic_store(&s_available, 1);
    return 0;
}

static void pcsc_clear_snapshot_locked(void)
{
    secure_zero(s_readers, sizeof(s_readers));
    s_reader_count = 0;
}

static int pcsc_reader_status_locked(const char *name, S_PCSC_READER *out)
{
    if (!name || !*name || !out) return 0;

    int idx = pcsc_ensure_card_locked(name);
    if (idx < 0) {
        tcmg_strlcpy(out->name, name, sizeof(out->name));
        return 0;
    }

    DWORD state = 0;
    DWORD protocol = s_cards[idx].protocol;
    DWORD atr_len = TCMG_PCSC_ATR_MAX;
    char reader_name[TCMG_PCSC_READER_NAME_MAX] = {0};
    DWORD reader_len = sizeof(reader_name);
    uint8_t atr[TCMG_PCSC_ATR_MAX] = {0};

    LONG rc = TCMG_SCARD_STATUS(s_cards[idx].card, reader_name, &reader_len,
                                &state, &protocol, atr, &atr_len);
    if (rc == SCARD_E_INVALID_HANDLE || rc == SCARD_W_REMOVED_CARD) {
        pcsc_drop_card_locked(idx);
        idx = pcsc_ensure_card_locked(name);
        if (idx < 0) {
            tcmg_strlcpy(out->name, name, sizeof(out->name));
            return 0;
        }
        protocol = s_cards[idx].protocol;
        atr_len = TCMG_PCSC_ATR_MAX;
        reader_len = sizeof(reader_name);
        memset(reader_name, 0, sizeof(reader_name));
        memset(atr, 0, sizeof(atr));
        rc = TCMG_SCARD_STATUS(s_cards[idx].card, reader_name, &reader_len,
                               &state, &protocol, atr, &atr_len);
    }

    tcmg_strlcpy(out->name, name, sizeof(out->name));
    if (rc == SCARD_S_SUCCESS) {
        out->present = (state != SCARD_ABSENT && state != SCARD_UNKNOWN) ? 1 : 0;
        out->protocol = (uint32_t)protocol;
        if (atr_len > TCMG_PCSC_ATR_MAX) atr_len = TCMG_PCSC_ATR_MAX;
        out->atr_len = (uint32_t)atr_len;
        if (atr_len) memcpy(out->atr, atr, atr_len);
        return out->present;
    }

    if (rc != SCARD_E_NO_SMARTCARD && rc != SCARD_W_REMOVED_CARD &&
        rc != SCARD_E_SHARING_VIOLATION) {
        tcmg_log_dbg(D_CONN, "status reader='%s' rc=0x%08lX (%s)",
                     name, (unsigned long)rc, pcsc_rc_name(rc));
    }
    out->present = (rc == SCARD_E_SHARING_VIOLATION) ? 1 : 0;
    return out->present;
}

static int pcsc_refresh_locked(void)
{
    if (pcsc_ensure_context_locked() < 0) {
        pcsc_drop_all_cards_locked();
        pcsc_clear_snapshot_locked();
        return -1;
    }

    DWORD chars = 0;
    LONG rc = TCMG_SCARD_LIST(s_ctx, NULL, NULL, &chars);
    if (rc != SCARD_S_SUCCESS) {
        if (rc == SCARD_E_NO_READERS_AVAILABLE) {
            pcsc_drop_all_cards_locked();
            pcsc_clear_snapshot_locked();
            return 0;
        }
        if (rc == SCARD_E_INVALID_HANDLE || rc == SCARD_E_NO_SERVICE) {
            pcsc_drop_all_cards_locked();
            if (s_ctx) {
                SCardReleaseContext(s_ctx);
                s_ctx = 0;
            }
            atomic_store(&s_available, 0);
        }
        tcmg_log_dbg(D_CONN, "list readers failed rc=0x%08lX (%s)",
                     (unsigned long)rc, pcsc_rc_name(rc));
        return -1;
    }

    char *multi = calloc(chars ? chars : 1, 1);
    if (!multi) return -1;

    rc = TCMG_SCARD_LIST(s_ctx, NULL, multi, &chars);
    if (rc != SCARD_S_SUCCESS) {
        free(multi);
        if (rc == SCARD_E_INVALID_HANDLE || rc == SCARD_E_NO_SERVICE) {
            pcsc_drop_all_cards_locked();
            if (s_ctx) {
                SCardReleaseContext(s_ctx);
                s_ctx = 0;
            }
            atomic_store(&s_available, 0);
        }
        return -1;
    }

    S_PCSC_READER next[TCMG_PCSC_MAX_READERS];
    memset(next, 0, sizeof(next));
    int next_count = 0;

    for (char *p = multi; *p && next_count < TCMG_PCSC_MAX_READERS; p += strlen(p) + 1) {
        if (pcsc_reader_status_locked(p, &next[next_count])) {
            next_count++;
        } else {
            tcmg_strlcpy(next[next_count].name, p, sizeof(next[next_count].name));
            next_count++;
        }
    }

    free(multi);
    pcsc_drop_stale_cards_locked(next, next_count);

    for (int i = 0; i < next_count; i++) {
        if (!next[i].present) continue;
        int old_found = 0;
        int old_present = 0;
        int atr_changed = 0;
        for (int j = 0; j < s_reader_count; j++) {
            if (strcmp(next[i].name, s_readers[j].name) != 0) continue;
            old_found = 1;
            old_present = s_readers[j].present;
            atr_changed = next[i].atr_len != s_readers[j].atr_len ||
                          memcmp(next[i].atr, s_readers[j].atr, next[i].atr_len) != 0;
            break;
        }
        if (!old_found || !old_present)
            tcmg_log("card present reader='%s'", next[i].name);
        if (atr_changed)
            tcmg_log_dbg(D_READER, "card reader='%s' atr=%u",
                         next[i].name, next[i].atr_len);
    }

    for (int i = 0; i < s_reader_count; i++) {
        if (!s_readers[i].present) continue;
        int still_present = 0;
        for (int j = 0; j < next_count; j++)
            if (strcmp(s_readers[i].name, next[j].name) == 0 && next[j].present) {
                still_present = 1;
                break;
            }
        if (!still_present)
            tcmg_log("card removed reader='%s'", s_readers[i].name);
    }

    memcpy(s_readers, next, sizeof(next));
    s_reader_count = next_count;
    return 0;
}

static int pcsc_reset_reader_locked(const char *reader)
{
    if (!reader || !*reader) return -1;

    int idx = pcsc_ensure_card_locked(reader);
    if (idx < 0) return -1;
    DWORD active_protocol = s_cards[idx].protocol;
    LONG rc = SCardReconnect(s_cards[idx].card, SCARD_SHARE_SHARED,
                             SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                             SCARD_RESET_CARD, &active_protocol);
    s_cards[idx].protocol = active_protocol;
    if (rc != SCARD_S_SUCCESS) {
        pcsc_drop_card_locked(idx);
        return -1;
    }
    tcmg_log_force("fast reset ok reader='%s'", reader);
    return 0;
}


static int pcsc_conax_ecm_locked(const char *reader, const uint8_t *ecm, size_t ecm_len,
                                  uint8_t cw[CW_LEN], int allow_ca, int *active_idx_out)
{
    int rc = -1;
    int active_idx = -1;
    int64_t ecm_t0 = tcmg_mono_ms();
    uint8_t apdu[5 + 255];
    uint8_t rsp[TCMG_PCSC_ATR_MAX + 256];
    if (active_idx_out) *active_idx_out = -1;
    if (!reader || !*reader || !ecm || !cw || ecm_len == 0 || ecm_len > 249) return -1;
    if (pcsc_ensure_context_locked() < 0) return -3;
    active_idx = pcsc_ensure_card_locked(reader);
    if (active_idx < 0 || active_idx >= TCMG_PCSC_MAX_READERS) return -4;
    if (active_idx_out) *active_idx_out = active_idx;
    atomic_store(&s_last_activity_ms[active_idx], tcmg_mono_ms32());
    atomic_fetch_add(&s_ecm_active[active_idx], 1);

    size_t apdu_len = 8 + ecm_len;
    size_t rsp_len = sizeof(rsp);
    int mask = 0;
    apdu[0] = 0xDD; apdu[1] = 0xA2; apdu[2] = 0x00; apdu[3] = 0x00;
    apdu[4] = (uint8_t)(ecm_len + 3); apdu[5] = 0x14; apdu[6] = (uint8_t)(ecm_len + 1); apdu[7] = 0x00;
    memcpy(apdu + 8, ecm, ecm_len);
    tcmg_dump_dbg(D_READER, apdu, (int32_t)apdu_len, "PCSC >> APDU context=%s", allow_ca ? "ecm" : "old-ecm");

    int idx = active_idx;
    LONG trc = pcsc_transmit_locked(idx, apdu, apdu_len, rsp, &rsp_len);
    if (trc == SCARD_S_SUCCESS)
        tcmg_dump_dbg(D_READER, rsp, (int32_t)rsp_len, "PCSC << RESPONSE context=%s", allow_ca ? "ecm" : "old-ecm");
    if (trc == SCARD_W_REMOVED_CARD || trc == SCARD_E_INVALID_HANDLE) {
        int old_idx = idx;
        atomic_fetch_sub(&s_ecm_active[old_idx], 1);
        pcsc_drop_card_locked(old_idx);
        idx = pcsc_ensure_card_locked(reader);
        if (idx >= 0) {
            active_idx = idx;
            if (active_idx_out) *active_idx_out = active_idx;
            atomic_store(&s_last_activity_ms[active_idx], tcmg_mono_ms32());
            atomic_fetch_add(&s_ecm_active[active_idx], 1);
            trc = pcsc_transmit_locked(idx, apdu, apdu_len, rsp, &rsp_len);
            if (trc == SCARD_S_SUCCESS)
                tcmg_dump_dbg(D_READER, rsp, (int32_t)rsp_len, "PCSC << RESPONSE context=%s retry=1", allow_ca ? "ecm" : "old-ecm");
        } else {
            active_idx = -1;
            if (active_idx_out) *active_idx_out = -1;
        }
    }
    if (trc != SCARD_S_SUCCESS) { rc = -5; goto done; }
    if (rsp_len < 2) { rc = -7; goto done; }

    uint8_t sw1 = rsp[rsp_len - 2], sw2 = rsp[rsp_len - 1];
    if (sw1 == 0x90 && sw2 == 0x00) pcsc_parse_conax_cw(rsp, rsp_len, cw, &mask);
    if (!allow_ca) {
        rc = mask == 3 ? 0 : -13;
        goto done;
    }
    while (sw1 == 0x98 && sw2 != 0x00 && sw2 != 0xFF) {
        uint8_t ins_ca[5] = {0xDD,0xCA,0x00,0x00,sw2};
        rsp_len = sizeof(rsp);
        tcmg_dump_dbg(D_READER, ins_ca, sizeof(ins_ca), "PCSC >> APDU context=%s", allow_ca ? "ecm-ca" : "old-ecm-ca");
        if (pcsc_transmit_locked(idx, ins_ca, sizeof(ins_ca), rsp, &rsp_len) != SCARD_S_SUCCESS) { rc = -8; goto done; }
        tcmg_dump_dbg(D_READER, rsp, (int32_t)rsp_len, "PCSC << RESPONSE context=%s", allow_ca ? "ecm-ca" : "old-ecm-ca");
        if (rsp_len < 2) { rc = -10; goto done; }
        sw1 = rsp[rsp_len - 2]; sw2 = rsp[rsp_len - 1];
        if (sw1 == 0x98 || (sw1 == 0x90 && sw2 == 0x00)) {
            int got = 0;
            if (pcsc_parse_conax_cw(rsp, rsp_len, cw, &got) == -2) { rc = -11; goto done; }
            mask |= got;
        } else { rc = -12; goto done; }
    }
    if (mask == 3) rc = 0;
    else if (rsp_len >= 3 && rsp[0] == 0x81 && ((rsp[2] >> 5) == 2)) rc = -11;
    else rc = -13;

done:
    if (active_idx >= 0 && active_idx < TCMG_PCSC_MAX_READERS) {
        int64_t elapsed_ms = tcmg_mono_ms() - ecm_t0;
        if (rc == 0) tcmg_log_dbg(D_ECM, "ECM ok reader='%s' elapsed=%lldms", reader, (long long)elapsed_ms);
        else tcmg_log_dbg(D_ECM, "ECM failed reader='%s' rc=%d elapsed=%lldms", reader, rc, (long long)elapsed_ms);
        atomic_fetch_sub(&s_ecm_active[active_idx], 1);
    }
    return rc;
}

static void *pcsc_thread(void *arg)
{
    (void)arg;
    int64_t last_fast_reset_ms[MAX_READERS];
    int fast_reset_paused[MAX_READERS];
    int64_t last_activity_seen_ms[MAX_READERS];
    const int64_t start_ms = tcmg_mono_ms();
    for (int i = 0; i < MAX_READERS; i++) {
        last_fast_reset_ms[i] = start_ms;
        last_activity_seen_ms[i] = start_ms;
        fast_reset_paused[i] = 0;
        memset(&s_old_ecm[i], 0, sizeof(s_old_ecm[i]));
    }
    for (int i = 0; i < TCMG_PCSC_MAX_READERS; i++) {
        atomic_store(&s_last_activity_ms[i], start_ms);
        atomic_store(&s_ecm_active[i], 0);
    }

    while (atomic_load(&s_running)) {
        int32_t poll_ms = 250;
        S_READER readers[MAX_READERS];
        int reader_count = cfg_runtime_reader_snapshot_indexed(readers, MAX_READERS);
        int enabled = 0;
        for (int i = 0; i < reader_count; i++) {
            if (!readers[i].in_use || !readers[i].enabled || strcasecmp(readers[i].protocol, "pcsc") != 0) continue;
            enabled = 1;
            int p = readers[i].poll_ms;
            if (p >= 50 && p < poll_ms) poll_ms = p;
        }
        if (poll_ms < 50) poll_ms = 50;
        if (poll_ms > 10000) poll_ms = 10000;

        if (!enabled) {
            atomic_store(&s_available, 0);
            pthread_mutex_lock(&s_pcsc_mtx);
            pcsc_drop_all_cards_locked();
            if (s_ctx) {
                SCardReleaseContext(s_ctx);
                s_ctx = 0;
            }
            pcsc_clear_snapshot_locked();
            pthread_mutex_unlock(&s_pcsc_mtx);
            const int64_t reset_ms = tcmg_mono_ms();
            for (int i = 0; i < MAX_READERS; i++) {
                last_fast_reset_ms[i] = reset_ms;
                last_activity_seen_ms[i] = reset_ms;
                fast_reset_paused[i] = 0;
                reader_old_ecm_unbind(&s_old_ecm[i]);
            }
            for (int i = 0; i < TCMG_PCSC_MAX_READERS; i++) {
                atomic_store(&s_last_activity_ms[i], reset_ms);
                atomic_store(&s_ecm_active[i], 0);
            }
        } else {
            pthread_mutex_lock(&s_pcsc_mtx);
#ifdef TCMG_PCSC
            if (pcsc_refresh_locked() < 0)
                atomic_store(&s_available, s_ctx ? 1 : 0);

            int64_t now_ms = tcmg_mono_ms();
            for (int i = 0; i < reader_count; i++) {
                S_READER *cfg = &readers[i];
                if (!cfg->in_use || !cfg->enabled || strcasecmp(cfg->protocol, "pcsc") != 0) continue;
                int target_idx = pcsc_resolve_reader_locked(cfg->device);
                if (target_idx < 0 || target_idx >= s_reader_count) {
                    reader_old_ecm_unbind(&s_old_ecm[i]);
                    continue;
                }
                if (!s_readers[target_idx].present) {
                    reader_old_ecm_unbind(&s_old_ecm[i]);
                } else {
                    reader_old_ecm_sync(&s_old_ecm[i], cfg);
                    reader_old_ecm_bind(&s_old_ecm[i], cfg, s_readers[target_idx].name,
                                        s_readers[target_idx].atr, s_readers[target_idx].atr_len);
                }

                int card_idx = pcsc_card_slot_locked(s_readers[target_idx].name);
                int busy = card_idx >= 0 && card_idx < TCMG_PCSC_MAX_READERS && atomic_load(&s_ecm_active[card_idx]) != 0;
                if (cfg->maintenance_mode == TCMG_READER_MAINT_OLD_ECM &&
                    s_readers[target_idx].present && !busy &&
                    reader_old_ecm_due(cfg, &s_old_ecm[i], busy)) {
                    const uint8_t *old_ecm = NULL;
                    size_t old_ecm_len = 0;
                    if (reader_old_ecm_get(&s_old_ecm[i], &old_ecm, &old_ecm_len) == 0) {
                        uint8_t ecm_copy[TCMG_OLD_ECM_MAX_LEN];
                        uint8_t cw[CW_LEN] = {0};
                        memcpy(ecm_copy, old_ecm, old_ecm_len);
                        tcmg_log_dbg(D_READER, "OLD ECM start reader='%s' source=%s len=%zu",
                                     s_readers[target_idx].name,
                                     cfg->old_ecm_source == TCMG_OLD_ECM_SOURCE_MANUAL ? "manual" : "auto",
                                     old_ecm_len);
                        reader_old_ecm_note_attempt(&s_old_ecm[i]);
                        int active_idx = -1;
                        int old_rc = -1;
                        int64_t old_t0 = tcmg_mono_ms();
                        old_rc = pcsc_conax_ecm_locked(s_readers[target_idx].name, ecm_copy, old_ecm_len, cw, 0, &active_idx);
                        if (active_idx >= 0 && active_idx < TCMG_PCSC_MAX_READERS)
                            atomic_store(&s_last_activity_ms[active_idx], tcmg_mono_ms32());
                        tcmg_log_dbg(D_READER, "OLD ECM result=%s reader='%s' elapsed=%lldms",
                                     old_rc == 0 ? "success" : "failed", s_readers[target_idx].name,
                                     (long long)(tcmg_mono_ms() - old_t0));
                    }
                    last_fast_reset_ms[i] = now_ms;
                    continue;
                }

                if (cfg->maintenance_mode != TCMG_READER_MAINT_FAST_RESET || cfg->fast_reset <= 0) {
                    fast_reset_paused[i] = 0;
                    continue;
                }
                if (card_idx < 0 || card_idx >= TCMG_PCSC_MAX_READERS) continue;
                const uint32_t activity_ms = atomic_load(&s_last_activity_ms[card_idx]);
                const int idle_enabled = cfg->fast_reset_idle > 0;
                const uint32_t idle_ms = now_ms - activity_ms;
                const int idle = idle_enabled && idle_ms >= (uint32_t)cfg->fast_reset_idle * 1000u;
                if (fast_reset_paused[i]) {
                    if (activity_ms != last_activity_seen_ms[i]) {
                        fast_reset_paused[i] = 0;
                        last_activity_seen_ms[i] = activity_ms;
                        last_fast_reset_ms[i] = now_ms;
                        tcmg_log_force("fast reset resumed reader='%s'", cfg->device);
                    } else continue;
                } else if (idle) {
                    fast_reset_paused[i] = 1;
                    last_activity_seen_ms[i] = activity_ms;
                    tcmg_log_force("fast reset paused reader='%s' idle=%ds", cfg->device, cfg->fast_reset_idle);
                    continue;
                }
                if (busy) continue;
                int64_t due = (int64_t)cfg->fast_reset * 1000LL;
                if (now_ms - last_fast_reset_ms[i] < due) continue;
                pcsc_reset_reader_locked(s_readers[target_idx].name);
                last_fast_reset_ms[i] = now_ms;
            }
#else
            atomic_store(&s_available, 0);
            pcsc_clear_snapshot_locked();
#endif
            pthread_mutex_unlock(&s_pcsc_mtx);
        }

        int waited = 0;
        while (atomic_load(&s_running) && waited < poll_ms) {
            int step = poll_ms - waited;
            if (step > 100) step = 100;
            tcmg_sleep_ms(step);
            waited += step;
        }
    }

    return NULL;
}

#endif

int pcsc_start(void)
{
#ifdef TCMG_PCSC
    if (atomic_exchange(&s_running, 1)) return 0;
    int trc = pthread_create(&s_tid, NULL, pcsc_thread, NULL);
    if (trc != 0) {
        atomic_store(&s_running, 0);
        tcmg_log("PCSC worker thread failed rc=%d (%s)", trc, strerror(trc));
        return -1;
    }
    tcmg_log("support enabled");
    return 0;
#else
    atomic_store(&s_running, 0);
    atomic_store(&s_available, 0);
    tcmg_log("support not built");
    return 0;
#endif
}

void pcsc_stop(void)
{
#ifdef TCMG_PCSC
    if (atomic_exchange(&s_running, 0))
        pthread_join(s_tid, NULL);

    pthread_mutex_lock(&s_pcsc_mtx);
    for (int i = 0; i < TCMG_PCSC_MAX_READERS; i++) pcsc_drop_card_locked(i);
    if (s_ctx) {
        SCardReleaseContext(s_ctx);
        s_ctx = 0;
    }
    pcsc_clear_snapshot_locked();
    atomic_store(&s_available, 0);
    pthread_mutex_unlock(&s_pcsc_mtx);
#else
    atomic_store(&s_available, 0);
#endif
}

int pcsc_available(void)
{
    return atomic_load(&s_available) ? 1 : 0;
}

int pcsc_reader_count(void)
{
    int n;
    pthread_mutex_lock(&s_pcsc_mtx);
    n = s_reader_count;
    pthread_mutex_unlock(&s_pcsc_mtx);
    return n;
}

int pcsc_reader_get(int index, S_PCSC_READER *out)
{
    if (!out || index < 0 || index >= TCMG_PCSC_MAX_READERS) return -1;
    pthread_mutex_lock(&s_pcsc_mtx);
    if (index >= s_reader_count) {
        pthread_mutex_unlock(&s_pcsc_mtx);
        return -1;
    }
    *out = s_readers[index];
    pthread_mutex_unlock(&s_pcsc_mtx);
    return 0;
}

#ifdef TCMG_PCSC
static void pcsc_drop_card_locked(int idx)
{
    if (idx < 0 || idx >= TCMG_PCSC_MAX_READERS) return;
    if (s_cards[idx].valid && s_cards[idx].card)
        SCardDisconnect(s_cards[idx].card, SCARD_LEAVE_CARD);
    memset(&s_cards[idx], 0, sizeof(s_cards[idx]));
}

static void pcsc_drop_all_cards_locked(void)
{
    for (int i = 0; i < TCMG_PCSC_MAX_READERS; i++)
        pcsc_drop_card_locked(i);
}

static void pcsc_drop_stale_cards_locked(const S_PCSC_READER *readers, int count)
{
    for (int i = 0; i < TCMG_PCSC_MAX_READERS; i++) {
        if (!s_cards[i].valid) continue;
        int found = 0;
        for (int j = 0; j < count; j++) {
            if (strcmp(s_cards[i].name, readers[j].name) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) pcsc_drop_card_locked(i);
    }
}

static int pcsc_card_slot_locked(const char *reader)
{
    if (!reader || !*reader) return -1;
    for (int i = 0; i < TCMG_PCSC_MAX_READERS; i++)
        if (s_cards[i].valid && strcmp(s_cards[i].name, reader) == 0) return i;
    return -1;
}

static int pcsc_card_index_locked(const char *reader)
{
    if (!reader || !*reader) return -1;
    for (int i = 0; i < TCMG_PCSC_MAX_READERS; i++)
        if (s_cards[i].valid && strcmp(s_cards[i].name, reader) == 0) return i;
    for (int i = 0; i < TCMG_PCSC_MAX_READERS; i++)
        if (!s_cards[i].valid) return i;
    return -1;
}

static int pcsc_ensure_card_locked(const char *reader)
{
    int idx = pcsc_card_index_locked(reader);
    if (idx < 0) return -1;
    if (s_cards[idx].valid) return idx;

    SCARDHANDLE card = 0;
    DWORD active_protocol = 0;
    LONG rc = TCMG_SCARD_CONNECT(s_ctx, reader,
                                  SCARD_SHARE_SHARED,
                                  SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                  &card, &active_protocol);
    if (rc != SCARD_S_SUCCESS) return -1;

    s_cards[idx].card = card;
    s_cards[idx].protocol = active_protocol;
    s_cards[idx].valid = 1;
    tcmg_strlcpy(s_cards[idx].name, reader, sizeof(s_cards[idx].name));
    return idx;
}

static LONG pcsc_transmit_locked(int idx, const uint8_t *cmd, size_t cmd_len,
                                 uint8_t *rsp, size_t *rsp_len)
{
    SCARD_IO_REQUEST send_pci;
    memset(&send_pci, 0, sizeof(send_pci));
    send_pci.dwProtocol = s_cards[idx].protocol;
    send_pci.cbPciLength = sizeof(send_pci);

    DWORD out_len = (DWORD)*rsp_len;
    LONG rc = SCardTransmit(s_cards[idx].card, &send_pci, cmd, (DWORD)cmd_len,
                            NULL, rsp, &out_len);
    *rsp_len = out_len;
    return rc;
}

#endif

int pcsc_transmit(const char *reader, const uint8_t *cmd, size_t cmd_len,
                  uint8_t *rsp, size_t *rsp_len)
{
#ifdef TCMG_PCSC
    if (!reader || !*reader || !cmd || !cmd_len || !rsp || !rsp_len || *rsp_len == 0)
        return -1;

    if (cmd_len > 4096 || *rsp_len > 65536) return -1;

    pthread_mutex_lock(&s_pcsc_mtx);
    if (pcsc_ensure_context_locked() < 0) {
        pthread_mutex_unlock(&s_pcsc_mtx);
        return -2;
    }

    int idx = pcsc_ensure_card_locked(reader);
    if (idx < 0) {
        pthread_mutex_unlock(&s_pcsc_mtx);
        return -3;
    }

    LONG rc = pcsc_transmit_locked(idx, cmd, cmd_len, rsp, rsp_len);
    if (rc == SCARD_W_REMOVED_CARD || rc == SCARD_E_INVALID_HANDLE) {
        pcsc_drop_card_locked(idx);
        idx = pcsc_ensure_card_locked(reader);
        if (idx >= 0)
            rc = pcsc_transmit_locked(idx, cmd, cmd_len, rsp, rsp_len);
    }
    pthread_mutex_unlock(&s_pcsc_mtx);

    if (rc != SCARD_S_SUCCESS) return (int)rc;
    return 0;
#else
    (void)reader;
    (void)cmd;
    (void)cmd_len;
    (void)rsp;
    (void)rsp_len;
    return -1;
#endif
}

#ifdef TCMG_PCSC
static int pcsc_resolve_reader_locked(const char *selector)
{
    if (selector && *selector) {
        char *end = NULL;
        long idx = strtol(selector, &end, 10);
        if (end && *end == '\0' && idx >= 0 && idx < s_reader_count)
            return (int)idx;
        for (int i = 0; i < s_reader_count; i++)
            if (strcmp(selector, s_readers[i].name) == 0) return i;
        return -1;
    }
    for (int i = 0; i < s_reader_count; i++)
        if (s_readers[i].present) return i;
    return -1;
}

static int pcsc_select_reader_ex(const char *selector, char *out, size_t out_len)
{
    if (!out || out_len == 0) return -1;
    out[0] = '\0';
    pthread_mutex_lock(&s_pcsc_mtx);
    int idx = pcsc_resolve_reader_locked(selector);
    int rc = idx >= 0 && idx < s_reader_count && s_readers[idx].present ? 0 : -1;
    if (rc == 0) tcmg_strlcpy(out, s_readers[idx].name, out_len);
    pthread_mutex_unlock(&s_pcsc_mtx);
    return rc;
}

static int pcsc_note_old_ecm_success_locked(const char *reader, const uint8_t *ecm, size_t ecm_len, int64_t now_ms)
{
    if (!reader || !ecm || ecm_len == 0) return 0;
    int target_idx = -1;
    for (int i = 0; i < s_reader_count; i++) {
        if (strcmp(reader, s_readers[i].name) == 0) { target_idx = i; break; }
    }
    if (target_idx < 0) return 0;

    S_READER cfgs[MAX_READERS];
    int count = cfg_runtime_reader_snapshot_indexed(cfgs, MAX_READERS);
    for (int i = 0; i < count; i++) {
        S_READER *cfg = &cfgs[i];
        if (!cfg->in_use || !cfg->enabled || strcasecmp(cfg->protocol, "pcsc") != 0) continue;
        int match = strcmp(cfg->device, reader) == 0;
        if (!match) {
            char *end = NULL;
            long idx = strtol(cfg->device, &end, 10);
            match = end && *end == '\0' && idx == target_idx;
        }
        if (!match) continue;
        reader_old_ecm_sync(&s_old_ecm[i], cfg);
        if (s_readers[target_idx].present)
            reader_old_ecm_bind(&s_old_ecm[i], cfg, reader, s_readers[target_idx].atr,
                                s_readers[target_idx].atr_len);
        reader_old_ecm_note_success(&s_old_ecm[i], cfg, ecm, ecm_len);
    }
    return 0;
}

static int pcsc_parse_conax_cw(const uint8_t *rsp, size_t rsp_len, uint8_t cw[CW_LEN], int *found_mask)
{
    if (!rsp || rsp_len < 2 || !cw || !found_mask) return -1;
    *found_mask = 0;

    if (rsp_len >= 3 && rsp[0] == 0x81 && ((rsp[2] >> 5) == 2))
        return -2;

    size_t data_len = rsp_len - 2;
    size_t i = 0;
    while (i + 2 <= data_len) {
        uint8_t tag = rsp[i];
        uint8_t len = rsp[i + 1];
        size_t end = i + 2u + len;
        if (end > data_len) break;

        if (tag == 0x25 && len >= 0x0D) {
            uint8_t n = rsp[i + 4];
            if (n < 2 && !(rsp[i + 4] & 0xFE) && i + 15 <= data_len) {
                memcpy(cw + ((size_t)n << 3), rsp + i + 7, 8);
                *found_mask |= (1 << n);
            }
        }

        i = end;
    }

    return 0;
}
#endif

int pcsc_do_ecm_reader(const char *selector, uint16_t caid, const uint8_t *ecm, size_t ecm_len, uint8_t cw[CW_LEN], int32_t whitelist)
{
#ifdef TCMG_PCSC
    if (!ecm || !cw || ecm_len == 0 || ecm_len > 249) return -1;
    if ((caid & 0xFF00u) != 0x0B00u) return -2;
    if (!pcsc_available()) return -3;
    if (whitelist > 0 && ecm_len != (size_t)whitelist) {
        tcmg_log_dbg(D_ECM, "ecm rejected: length=%u != whitelist=%02X (%d bytes)",
                     (unsigned)ecm_len, (unsigned)(whitelist & 0xFF), whitelist);
        return -13;
    }
    char reader[TCMG_PCSC_READER_NAME_MAX];
    if (pcsc_select_reader_ex(selector, reader, sizeof(reader)) < 0) return -4;
    pthread_mutex_lock(&s_pcsc_mtx);
    int rc = pcsc_conax_ecm_locked(reader, ecm, ecm_len, cw, 1, NULL);
    if (rc == 0) pcsc_note_old_ecm_success_locked(reader, ecm, ecm_len, tcmg_mono_ms());
    pthread_mutex_unlock(&s_pcsc_mtx);
    return rc;
#else
    (void)selector; (void)caid; (void)ecm; (void)ecm_len; (void)cw; (void)whitelist;
    return -3;
#endif
}
