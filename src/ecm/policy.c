#define MODULE_LOG_PREFIX "ecm"
#include "policy.h"
#include "account/account.h"
#include "security/antishare.h"
#include "core/constants.h"
#include "log/log.h"
#include <stddef.h>
#include <time.h>

T_ECM_ACCESS_STATUS ecm_access(S_CLIENT *client, uint16_t caid, uint16_t sid, uint32_t provid)
{
    S_ACCOUNT *account;
    T_ECM_ACCESS_STATUS status = ECM_ACCESS_OK;
    int anti_delay_ms = 0;

    if (!client) return ECM_ACCESS_NO_ACCOUNT;
    account = account_session_acquire(client);
    if (!account) return ECM_ACCESS_NO_ACCOUNT;

    if (!account->enabled) status = ECM_ACCESS_DISABLED;
    else if (account->expirationdate > 0 && time(NULL) > account->expirationdate) status = ECM_ACCESS_EXPIRED;
    else if (!account_in_schedule(account)) status = ECM_ACCESS_SCHEDULE;
    else if (!account_allows_caid(account, caid)) status = ECM_ACCESS_CAID_DENIED;
    else if (!account_allows_ident(account, caid, provid)) status = ECM_ACCESS_IDENT_DENIED;
    else if (!account_allows_sid(account, sid)) status = ECM_ACCESS_SID_DENIED;
    else if (antishare_check_channel(account, client->identity.thread_id, caid, sid, &anti_delay_ms) != AS_CHECK_OK) status = ECM_ACCESS_ANTISHARE;

    if (status == ECM_ACCESS_OK) {
        pthread_mutex_lock(&client->state_mtx);
        client->ecm.antishare_delay_ms = anti_delay_ms;
        client->ecm.antishare_prepared = 1;
        pthread_mutex_unlock(&client->state_mtx);
    } else {
        pthread_mutex_lock(&client->state_mtx);
        client->ecm.antishare_delay_ms = 0;
        client->ecm.antishare_prepared = 0;
        pthread_mutex_unlock(&client->state_mtx);
    }
    account_release(account);
    return status;
}

uint32_t ecm_resolve_provid(S_CLIENT *client, uint16_t caid, uint32_t provid,
                            const uint8_t *ecm, int32_t ecm_len)
{
    S_ACCOUNT *account;
    if (provid) return provid;
    if (ecm && ecm_len >= 8 && (caid >> 8) == 0x05 && ecm[3] == 0x90 && ecm[4] == 0x03)
        return (((uint32_t)ecm[5] << 16) | ((uint32_t)ecm[6] << 8) | ecm[7]) & 0xFFFFF0u;
    if (!client) return 0;
    account = account_session_acquire(client);
    if (!account) return 0;
    for (int32_t i = 0; i < account->nidents; i++) {
        if (account->idents[i].caid == caid) {
            provid = account->idents[i].provid;
            break;
        }
    }
    account_release(account);
    return provid;
}


/* OSCam's chk_provid() logic, with explicit bounds checks because these
 * offsets are read from packets supplied by network clients. */
static uint32_t ecm_provider_from_section(uint16_t caid,
                                          const uint8_t *ecm, int32_t len)
{
    uint32_t provid = 0;
    if (!ecm || len < 4) return 0;

    switch (caid >> 8) {
    case 0x01: /* Seca */
        if (len >= 5)
            provid = ((uint32_t)ecm[3] << 8) | ecm[4];
        break;

    case 0x05: { /* Viaccess, including D2-nano offsets */
        size_t off = 0;
        if (len >= 6 && ecm[4] == 0xD2)
            off = (size_t)ecm[5] + 2u;
        if (5u + off < (size_t)len && 4u + off < (size_t)len &&
            8u + off < (size_t)len && ecm[5u + off] == 3 &&
            (ecm[4u + off] == 0x90 || ecm[4u + off] == 0x40)) {
            provid = (((uint32_t)ecm[6u + off] << 16) |
                      ((uint32_t)ecm[7u + off] << 8) | ecm[8u + off]) & 0xFFFFF0u;
        }

        off = 0;
        if (len >= 8 && ecm[6] == 0xD2)
            off = (size_t)ecm[7] + 2u;
        if (7u + off < (size_t)len && 6u + off < (size_t)len &&
            10u + off < (size_t)len && ecm[7u + off] == 7 &&
            (ecm[6u + off] == 0x90 || ecm[6u + off] == 0x40)) {
            provid = (((uint32_t)ecm[8u + off] << 16) |
                      ((uint32_t)ecm[9u + off] << 8) | ecm[10u + off]) & 0xFFFFF0u;
        }
        break;
    }

    case 0x0D: { /* CryptoWorks descriptor 0x83 */
        size_t pos = 8;
        while (pos + 2u <= (size_t)len) {
            size_t desc_len = ecm[pos + 1u];
            if (pos + 2u + desc_len > (size_t)len) break;
            if (ecm[pos] == 0x83 && desc_len >= 1u) {
                provid = (uint32_t)ecm[pos + 2u] & 0xFEu;
                break;
            }
            pos += desc_len + 2u;
        }
        break;
    }

    case 0x18: /* Nagra2, retain OSCam's 1801-specific rule */
        if (caid == 0x1801 && len >= 7)
            provid = ((uint32_t)ecm[5] << 8) | ecm[6];
        break;
    }
    return provid;
}

bool ecm_prepare_input(uint16_t caid, uint32_t *provid,
                       const uint8_t *ecm, int32_t *ecm_len)
{
    int32_t section_len;
    uint32_t extracted;

    if (!provid || !ecm || !ecm_len || caid == 0 || *ecm_len < 3 ||
        *ecm_len > TCMG_MAX_ECM_SIZE) {
        tcmg_log_dbg(D_ECM, "ECM input rejected: invalid CAID or input length");
        return false;
    }

    /* OSCam get_odd_even() accepts ECM table IDs 0x80 (even) and 0x81 (odd)
     * for ordinary client ECM requests and rejects every other table id. */
    if (ecm[0] != 0x80 && ecm[0] != 0x81) {
        tcmg_log_dbg(D_ECM, "ECM input rejected: invalid table_id=%02X caid=%04X",
                     ecm[0], caid);
        return false;
    }

    section_len = 3 + (((int32_t)ecm[1] & 0x0F) << 8) + (int32_t)ecm[2];
    if (section_len < 4 || section_len > TCMG_MAX_ECM_SIZE) {
        tcmg_log_dbg(D_ECM, "ECM input rejected: invalid section length=%d caid=%04X",
                     section_len, caid);
        return false;
    }
    if (section_len > *ecm_len) {
        tcmg_log_dbg(D_ECM,
                     "ECM input rejected: truncated section caid=%04X declared=%d received=%d",
                     caid, section_len, *ecm_len);
        return false;
    }
    if (section_len < *ecm_len) {
        tcmg_log_dbg(D_ECM,
                     "ECM section normalized caid=%04X received=%d section=%d (trailing bytes ignored)",
                     caid, *ecm_len, section_len);
        *ecm_len = section_len;
    }

    extracted = ecm_provider_from_section(caid, ecm, *ecm_len);
    if (extracted && extracted != *provid) {
        tcmg_log_dbg(D_ECM,
                     "ECM provider corrected caid=%04X protocol=%06X section=%06X",
                     caid, *provid, extracted);
        *provid = extracted;
    }
    return true;
}
