#define MODULE_LOG_PREFIX "ecm"
#include "pipeline.h"
#include "policy.h"
#include "account/account.h"
#include "request.h"
#include "core/config_state.h"
#include "core/client_state.h"
#include "core/utils.h"
#include "platform/platform.h"
#include "cache/cw_cache.h"
#include "log/log.h"
#include "reader/reader.h"
#include "stats/account_stats.h"
#include "srvid/srvid.h"
#include "crypto/crypto.h"
#include "security/antishare.h"
#include "emu/emu.h"

int32_t ecm_process(S_CLIENT *client, uint16_t caid, uint16_t sid, uint32_t provid,
                    const uint8_t *ecm, int32_t ecm_len, uint8_t cw[CW_LEN],
                    S_ECM_RESULT *result)
{
    S_ECM_REQUEST request;
    S_READER_RESULT reader_result;
    int32_t res = -1;
    bool cache_hit = false;
    E_TCMG_ECM_SOURCE source = TCMG_ECM_SOURCE_READER;
    int64_t start;
    long elapsed;
    reader_result_init(&reader_result);

    if (result) memset(result, 0, sizeof(*result));
    if (!client || !ecm || !cw)
        return -1;
    /* Recheck every caller here as a final guard. Protocol handlers also call
     * this before account/provider filtering so malformed requests never reach
     * reader_dispatch_ecm(). */
    if (!ecm_prepare_input(caid, &provid, ecm, &ecm_len))
        return -1;

    S_ACCOUNT *account = account_session_acquire(client);
    if (!account) return -1;

    pthread_mutex_lock(&client->state_mtx);
    int was_prepared = client->ecm.antishare_prepared;
    int anti_delay_ms = was_prepared ? client->ecm.antishare_delay_ms : 0;
    client->ecm.antishare_delay_ms = 0;
    client->ecm.antishare_prepared = 0;
    pthread_mutex_unlock(&client->state_mtx);
    if (account->anti_share && !was_prepared) {
        if (antishare_check_channel(account, client->identity.thread_id, caid, sid, &anti_delay_ms) != AS_CHECK_OK) {
            account_release(account);
            return -2;
        }
    }

    ecm_request_init(&request, client, caid, sid, provid, ecm, ecm_len, cw);
    request.account = account;
    pthread_mutex_lock(&client->state_mtx);
    client->ecm.last_ecm_time = time(NULL);
    client->ecm.last_caid = caid;
    client->ecm.last_srvid = sid;
    srvid_lookup_copy(caid, sid, client->ecm.last_channel, sizeof(client->ecm.last_channel));
    pthread_mutex_unlock(&client->state_mtx);

    if (D_ECM & g_dblevel)
        log_ecm_raw(caid, sid, ecm, ecm_len);

    crypt_md5_hash(ecm, (size_t)ecm_len, request.ecm_md5);
    request.ecm_md5_valid = true;
    memset(cw, 0, CW_LEN);
    start = tcmg_mono_ms();

    res = reader_dispatch_ecm(&request, &reader_result);
    source = reader_result.source;
    cache_hit = source == TCMG_ECM_SOURCE_CACHE;

    elapsed = (long)tcmg_elapsed_ms(start);
    E_ACCOUNT_ECM_RESULT stats_result =
        (res == EMU_OK) ? ACCOUNT_ECM_FOUND :
        (reader_result.status == READER_RESULT_REJECTED ? ACCOUNT_ECM_REJECTED : ACCOUNT_ECM_NOT_FOUND);
    E_LOG_ECM_RESULT log_result = LOG_ECM_NOT_FOUND;
    if (res == EMU_OK) log_result = LOG_ECM_FOUND;
    else if (reader_result.status == READER_RESULT_REJECTED) log_result = LOG_ECM_REJECTED;
    else if (reader_result.failure == READER_FAILURE_TRANSPORT_ERROR) log_result = LOG_ECM_TRANSPORT_ERROR;
    else if (reader_result.failure == READER_FAILURE_CARD_ERROR) log_result = LOG_ECM_CARD_ERROR;
    else if (reader_result.failure == READER_FAILURE_READER_ERROR) log_result = LOG_ECM_READER_ERROR;

    if (res == EMU_OK) {
        antishare_record_channel_success(request.account, client->identity.thread_id, caid, sid, cw);
        if (anti_delay_ms > 0) tcmg_sleep_ms(anti_delay_ms);
    } else if (stats_result == ACCOUNT_ECM_NOT_FOUND) {
        antishare_clear_pending(request.account, client->identity.thread_id, caid, sid);
    }
    account_stats_record_ecm_result(request.account, stats_result, elapsed);

    log_cw_result(caid, sid, ecm_len, cw, log_result, source,
                  (int32_t)elapsed, request.user);
    secure_zero(request.ecm_md5, sizeof(request.ecm_md5));
    account_release(account);
    if (result) {
        result->result = res;
        result->cache_hit = cache_hit;
        result->source = source;
        result->elapsed_ms = (int32_t)elapsed;
    }
    return res;
}
