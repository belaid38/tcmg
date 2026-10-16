#ifndef TCMG_READER_TYPES_H_
#define TCMG_READER_TYPES_H_

#include "account_types.h"
#include "ident_types.h"

#define TCMG_READER_MAINT_FAST_RESET 0
#define TCMG_READER_MAINT_OLD_ECM 1
#define TCMG_OLD_ECM_SOURCE_AUTO 0
#define TCMG_OLD_ECM_SOURCE_MANUAL 1
#define TCMG_OLD_ECM_HEX_LEN 498
#define TCMG_MAX_ECM_WHITELIST_ENTRIES 128

typedef struct {
    uint16_t len;
    uint16_t caid;
    uint32_t provid;
} S_ECM_WHITELIST_ENTRY;

typedef struct {
    char     label[READER_LABEL_LEN];
    char     protocol[READER_PROTOCOL_LEN];
    bool     enabled;
    int8_t   in_use;
    char     device[CFGVAL_LEN];
    char     user[CFGKEY_LEN];
    char     password[CFGKEY_LEN];
    int32_t  inactivitytimeout;
    uint16_t caids[MAX_CAIDS_PER_READER];
    int32_t  ncaids;
    S_IDENT_FILTER idents[MAX_IDENT_FILTERS];
    int32_t  nidents;
    uint16_t sid_whitelist[MAX_SID_WHITELIST];
    int32_t  nsid_whitelist;
    int32_t  ecm_whitelist;
    char     ecm_whitelist_spec[CFGVAL_LEN];
    S_ECM_WHITELIST_ENTRY ecm_whitelist_entries[TCMG_MAX_ECM_WHITELIST_ENTRIES];
    int32_t  ecm_whitelist_count;
    int32_t  groups[MAX_GROUPS_PER_READER];
    int32_t  ngroups;
    S_ECMKEY keys[MAX_ECMKEYS_PER_ACC];
    int32_t  nkeys;
    int32_t  deprecated;
    int32_t  fast_reset;
    int32_t  fast_reset_idle;
    int32_t  poll_ms;
    int32_t  maintenance_mode;
    int32_t  old_ecm_source;
    int32_t  old_ecm_successes;
    char     old_ecm[TCMG_OLD_ECM_HEX_LEN + 1];
    uint8_t  newcamd_key[14];
} S_READER;

#endif
