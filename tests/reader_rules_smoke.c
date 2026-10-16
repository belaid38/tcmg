#include <string.h>
#include "../src/reader/rules.h"
#include "../src/core/account_types.h"
#include "../src/core/reader_types.h"
#include "../src/core/config_state.h"
#include <pthread.h>

int main(void)
{
    S_ACCOUNT a;
    S_READER r;
    memset(&a, 0, sizeof(a));
    memset(&r, 0, sizeof(r));
    a.group = 1;
    r.in_use = 1;
    r.enabled = 1;
    r.ecm_whitelist = 0x37;
    if (reader_rule_check(&r, &a, 0x0100, 0x0001, 0, 55) != READER_RULE_ALLOW) return 1;
    if (reader_rule_check(&r, &a, 0x0100, 0x0001, 0, 54) != READER_RULE_ECM_WHITELIST) return 2;
    if (reader_rule_check(&r, &a, 0x0100, 0x0001, 0, 56) != READER_RULE_ECM_WHITELIST) return 3;
    r.ecm_whitelist = 0;
    r.nidents = 1;
    r.idents[0].caid = 0x0B00;
    r.idents[0].provid = 0x000001;
    if (reader_rule_check(&r, &a, 0x0500, 0x0001, 0x000001, 55) != READER_RULE_IDENT) return 4;
    if (reader_rule_check(&r, &a, 0x0B00, 0x0001, 0x000002, 55) != READER_RULE_IDENT) return 5;
    if (reader_rule_check(&r, &a, 0x0B00, 0x0001, 0x000001, 55) != READER_RULE_ALLOW) return 6;
    r.nidents = 0;
    r.ncaids = 0;
    if (reader_rule_check(&r, &a, 0x0500, 0x0001, 0, 55) != READER_RULE_ALLOW) return 7;
    r.groups[0] = 2;
    r.ngroups = 1;
    r.ecm_whitelist = 0x37;
    if (reader_rule_check(&r, &a, 0x0500, 0x0001, 0, 54) != READER_RULE_ECM_WHITELIST) return 8;
    if (reader_rule_check(&r, &a, 0x0500, 0x0001, 0, 55) != READER_RULE_GROUP) return 9;

    /* OSCam-style whitelist: multiple lengths; ECM contents are not compared here. */
    if (!reader_ecm_whitelist_parse(&r, "3F,AF")) return 10;
    if (!reader_ecm_whitelist_allows(&r, 0x0B00, 0, 0x3F)) return 11;
    if (!reader_ecm_whitelist_allows(&r, 0x0B00, 0, 0xAF)) return 12;
    if (reader_ecm_whitelist_allows(&r, 0x0B00, 0, 0x40)) return 13;

    /* CAID/provider-scoped entries; an unrelated selector does not block the request. */
    if (!reader_ecm_whitelist_parse(&r, "0B00@000001:3F,AF;0100:10")) return 14;
    if (!reader_ecm_whitelist_allows(&r, 0x0B00, 0x000001, 0xAF)) return 15;
    if (reader_ecm_whitelist_allows(&r, 0x0B00, 0x000001, 0x40)) return 16;
    if (!reader_ecm_whitelist_allows(&r, 0x0B00, 0x000002, 0x40)) return 17;
    if (!reader_ecm_whitelist_allows(&r, 0x0100, 0, 0x10)) return 18;
    if (reader_ecm_whitelist_allows(&r, 0x0100, 0, 0xAF)) return 19;

    if (!reader_ecm_whitelist_parse(&r, "00")) return 20;
    if (!reader_ecm_whitelist_allows(&r, 0x0B00, 0, 0xAF)) return 21;
    if (!reader_ecm_whitelist_validate("100")) return 22;
    if (reader_ecm_whitelist_validate("401")) return 24;
    if (reader_ecm_whitelist_validate("3F,,AF")) return 23;

    /* DVBAPI preflight mirrors OSCam matching_reader(): skip PIDs for which
     * no enabled reader can service the CAID/provider/service combination. */
    if (pthread_rwlock_init(&g_cfg.acc_lock, NULL) != 0) return 25;
    memset(g_cfg.readers, 0, sizeof(g_cfg.readers));
    S_READER *configured = &g_cfg.readers[0];
    configured->in_use = 1;
    configured->enabled = 1;
    strcpy(configured->protocol, "emu");
    configured->ncaids = 1;
    configured->caids[0] = 0x0B00;
    configured->nidents = 1;
    configured->idents[0].caid = 0x0B00;
    configured->idents[0].provid = 0x000001;
    configured->nsid_whitelist = 1;
    configured->sid_whitelist[0] = 0x0001;
    if (!reader_dvbapi_candidate(&a, 0x0B00, 0x0001, 0x000001)) return 26;
    if (reader_dvbapi_candidate(&a, 0x0500, 0x0001, 0x000001)) return 27;
    if (reader_dvbapi_candidate(&a, 0x0B00, 0x0002, 0x000001)) return 28;
    if (reader_dvbapi_candidate(&a, 0x0B00, 0x0001, 0x000002)) return 29;
    /* Unknown provider is not a false negative if the reader has an ident for
     * the same CAID; the ECM section may resolve provider later. */
    if (!reader_dvbapi_candidate(&a, 0x0B00, 0x0001, 0)) return 30;
    pthread_rwlock_destroy(&g_cfg.acc_lock);
    return 0;
}
