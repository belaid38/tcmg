#ifndef TCMG_READER_RULES_H_
#define TCMG_READER_RULES_H_

#include "core/account_types.h"
#include "core/reader_types.h"
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    READER_RULE_ALLOW = 0,
    READER_RULE_DISABLED,
    READER_RULE_GROUP,
    READER_RULE_CAID,
    READER_RULE_IDENT,
    READER_RULE_SID,
    READER_RULE_ECM_WHITELIST,
} E_READER_RULE_RESULT;

bool reader_account_has_group(const S_ACCOUNT *acc, int32_t group);
/* Accepts OSCam syntax: [CAID[@provid]:]len[,len][;...], lengths in hex. */
bool reader_ecm_whitelist_parse(S_READER *reader, const char *spec);
bool reader_ecm_whitelist_validate(const char *spec);
bool reader_ecm_whitelist_allows(const S_READER *reader, uint16_t caid,
                                 uint32_t provid, int32_t ecm_len);
void reader_ecm_whitelist_get_spec(const S_READER *reader, char *out, size_t out_sz);
int reader_collect_account_caids(const S_ACCOUNT *acc, uint16_t *out, int32_t cap);
E_READER_RULE_RESULT reader_rule_check(const S_READER *reader, const S_ACCOUNT *acc,
                                        uint16_t caid, uint16_t sid, uint32_t provid, int32_t ecm_len);
bool reader_allows(const S_READER *reader, const S_ACCOUNT *acc,
                   uint16_t caid, uint16_t sid, uint32_t provid, int32_t ecm_len);
/* DVBAPI preflight before an ECM section is available: ignores length whitelist,
 * but verifies that at least one enabled configured reader can handle the PID. */
bool reader_dvbapi_candidate(const S_ACCOUNT *acc, uint16_t caid, uint16_t sid, uint32_t provid);

#endif
