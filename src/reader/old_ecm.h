#ifndef TCMG_READER_OLD_ECM_H_
#define TCMG_READER_OLD_ECM_H_

#include <stddef.h>
#include <stdint.h>
#include "../core/reader_types.h"

#define TCMG_OLD_ECM_MAX_LEN 249

typedef struct {
    uint8_t ecm[TCMG_OLD_ECM_MAX_LEN];
    size_t ecm_len;
    int valid;
    uint64_t config_tag;
    uint64_t card_tag;
    uint32_t successful_ecms;
} S_READER_OLD_ECM_STATE;

void reader_old_ecm_sync(S_READER_OLD_ECM_STATE *state, const S_READER *cfg);
void reader_old_ecm_bind(S_READER_OLD_ECM_STATE *state, const S_READER *cfg,
                         const char *identity, const uint8_t *atr, size_t atr_len);
void reader_old_ecm_unbind(S_READER_OLD_ECM_STATE *state);
int reader_old_ecm_enabled(const S_READER *cfg);
int reader_old_ecm_due(const S_READER *cfg, const S_READER_OLD_ECM_STATE *state, int busy);
void reader_old_ecm_note_success(S_READER_OLD_ECM_STATE *state, const S_READER *cfg,
                                 const uint8_t *ecm, size_t ecm_len);
void reader_old_ecm_note_attempt(S_READER_OLD_ECM_STATE *state);
int reader_old_ecm_get(const S_READER_OLD_ECM_STATE *state, const uint8_t **ecm, size_t *ecm_len);
int reader_old_ecm_parse_hex(const char *text, uint8_t *out, size_t out_cap, size_t *out_len);

#endif
