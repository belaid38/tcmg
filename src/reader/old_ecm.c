#define MODULE_LOG_PREFIX "reader"
#include "old_ecm.h"
#include <ctype.h>
#include <string.h>

static uint64_t old_ecm_hash_bytes(uint64_t h, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static uint64_t old_ecm_config_tag(const S_READER *cfg)
{
    uint64_t h = UINT64_C(1469598103934665603);
    if (!cfg) return 0;
    h = old_ecm_hash_bytes(h, (const uint8_t *)&cfg->maintenance_mode, sizeof(cfg->maintenance_mode));
    h = old_ecm_hash_bytes(h, (const uint8_t *)&cfg->old_ecm_source, sizeof(cfg->old_ecm_source));
    h = old_ecm_hash_bytes(h, (const uint8_t *)&cfg->old_ecm_successes, sizeof(cfg->old_ecm_successes));
    h = old_ecm_hash_bytes(h, (const uint8_t *)cfg->old_ecm, strlen(cfg->old_ecm));
    h = old_ecm_hash_bytes(h, (const uint8_t *)&cfg->ecm_whitelist, sizeof(cfg->ecm_whitelist));
    return h;
}


static void old_ecm_load_manual(S_READER_OLD_ECM_STATE *state, const S_READER *cfg)
{
    size_t len = 0;
    if (!state || !cfg || cfg->old_ecm_source != TCMG_OLD_ECM_SOURCE_MANUAL) return;
    if (reader_old_ecm_parse_hex(cfg->old_ecm, state->ecm, sizeof(state->ecm), &len) != 0) return;
    if (cfg->ecm_whitelist && (int32_t)len != cfg->ecm_whitelist) return;
    state->ecm_len = len;
    state->valid = 1;
}

int reader_old_ecm_parse_hex(const char *text, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t n;
    if (!text || !out || !out_len || out_cap == 0) return -1;
    n = strlen(text);
    if (n < 2 || n > out_cap * 2u || (n & 1u)) return -1;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)text[i])) return -1;
    for (size_t i = 0; i < n / 2u; i++) {
        unsigned hi = (unsigned)(isdigit((unsigned char)text[i * 2u]) ? text[i * 2u] - '0' : toupper((unsigned char)text[i * 2u]) - 'A' + 10);
        unsigned lo = (unsigned)(isdigit((unsigned char)text[i * 2u + 1u]) ? text[i * 2u + 1u] - '0' : toupper((unsigned char)text[i * 2u + 1u]) - 'A' + 10);
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n / 2u;
    return 0;
}

void reader_old_ecm_sync(S_READER_OLD_ECM_STATE *state, const S_READER *cfg)
{
    uint64_t tag;
    if (!state || !cfg) return;
    tag = old_ecm_config_tag(cfg);
    if (state->config_tag == tag) return;
    memset(state, 0, sizeof(*state));
    state->config_tag = tag;
    if (cfg->maintenance_mode != TCMG_READER_MAINT_OLD_ECM)
        return;
    old_ecm_load_manual(state, cfg);
}

void reader_old_ecm_bind(S_READER_OLD_ECM_STATE *state, const S_READER *cfg,
                         const char *identity, const uint8_t *atr, size_t atr_len)
{
    uint64_t h = UINT64_C(1469598103934665603);
    uint64_t tag;
    if (!state || !cfg) return;
    if (identity) h = old_ecm_hash_bytes(h, (const uint8_t *)identity, strlen(identity));
    h = old_ecm_hash_bytes(h, &((uint8_t){0}), 1);
    if (atr && atr_len) h = old_ecm_hash_bytes(h, atr, atr_len);
    tag = h;
    if (state->card_tag == tag) return;
    state->card_tag = tag;
    state->ecm_len = 0;
    state->valid = 0;
    state->successful_ecms = 0;
    old_ecm_load_manual(state, cfg);
}

void reader_old_ecm_unbind(S_READER_OLD_ECM_STATE *state)
{
    if (!state) return;
    state->card_tag = 0;
    state->ecm_len = 0;
    state->valid = 0;
    state->successful_ecms = 0;
}

int reader_old_ecm_enabled(const S_READER *cfg)
{
    return cfg && cfg->maintenance_mode == TCMG_READER_MAINT_OLD_ECM;
}

int reader_old_ecm_due(const S_READER *cfg, const S_READER_OLD_ECM_STATE *state, int busy)
{
    if (!reader_old_ecm_enabled(cfg) || !state || !state->valid || busy)
        return 0;
    return cfg->old_ecm_successes > 0 && state->successful_ecms >= (uint32_t)cfg->old_ecm_successes;
}

void reader_old_ecm_note_success(S_READER_OLD_ECM_STATE *state, const S_READER *cfg,
                                 const uint8_t *ecm, size_t ecm_len)
{
    if (!state || !cfg || !ecm || ecm_len == 0 || ecm_len > sizeof(state->ecm)) return;
    if (cfg->maintenance_mode != TCMG_READER_MAINT_OLD_ECM) return;
    if (!state->valid && cfg->old_ecm_source == TCMG_OLD_ECM_SOURCE_AUTO) {
        memcpy(state->ecm, ecm, ecm_len);
        state->ecm_len = ecm_len;
        state->valid = 1;
    }
    if (state->successful_ecms < UINT32_MAX)
        state->successful_ecms++;
}

void reader_old_ecm_note_attempt(S_READER_OLD_ECM_STATE *state)
{
    if (!state) return;
    state->successful_ecms = 0;
}

int reader_old_ecm_get(const S_READER_OLD_ECM_STATE *state, const uint8_t **ecm, size_t *ecm_len)
{
    if (!state || !ecm || !ecm_len || !state->valid || state->ecm_len == 0) return -1;
    *ecm = state->ecm;
    *ecm_len = state->ecm_len;
    return 0;
}
