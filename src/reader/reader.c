#define MODULE_LOG_PREFIX "reader"
#include "reader.h"
#include "core/config_state.h"
#include "ecm/request.h"
#include "account/account.h"
#include "core/utils.h"
#include "log/log.h"
#include "protocol.h"
#include "rules.h"
#include "result.h"
#include "stats.h"
#include "../platform/platform.h"
#include "../cache/cw_cache.h"
#include "../crypto/crypto.h"
#include "../security/antishare.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define READER_WORKER_COUNT MAX_READERS
#define READER_NEGATIVE_CACHE_SIZE 256
#define READER_NEGATIVE_CACHE_TTL_MS 1200

typedef struct s_reader_dispatch_ctx S_READER_DISPATCH_CTX;
typedef struct s_reader_job S_READER_JOB;

typedef struct {
    bool valid;
    int reader_index;
    uint16_t caid;
    uint16_t sid;
    uint32_t provid;
    int32_t ecm_len;
    uint32_t user_hash;
    int64_t expires_ms;
    uint8_t ecm_md5[TCMG_ECM_MD5_LEN];
} S_READER_NEGATIVE_ENTRY;

struct s_reader_job {
    S_READER_DISPATCH_CTX *ctx;
    S_READER_JOB *next;
    int index;
    S_READER reader;
    const S_READER_PROTOCOL *protocol;
    S_READER_STATS_SNAPSHOT stats;
    uint8_t cw[CW_LEN];
    E_READER_FAILURE failure;
};

struct s_reader_dispatch_ctx {
    S_ACCOUNT *account;
    S_ECM_REQUEST request;
    char user[CFGKEY_LEN];
    uint8_t ecm[TCMG_MAX_ECM_SIZE];
    uint8_t ecm_md5[TCMG_ECM_MD5_LEN];
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    _Atomic int refs;
    int active_jobs;
    bool winner;
    bool attempted;
    bool whitelist_rejected;
    E_READER_FAILURE failure_summary;
    S_READER_RESULT result;
    uint8_t cw[CW_LEN];
    int jobs_count;
    int lb_mode;
    int lb_nbest_readers;
    S_READER_JOB jobs[MAX_READERS];
};

static pthread_mutex_t s_reader_pool_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_reader_pool_cv = PTHREAD_COND_INITIALIZER;
static S_READER_JOB *s_reader_pool_head;
static S_READER_JOB *s_reader_pool_tail;
static pthread_t s_reader_pool_threads[READER_WORKER_COUNT];
static pthread_once_t s_reader_pool_once = PTHREAD_ONCE_INIT;
static int s_reader_pool_count;
static bool s_reader_pool_stop;
static pthread_mutex_t s_negative_cache_mtx = PTHREAD_MUTEX_INITIALIZER;
static S_READER_NEGATIVE_ENTRY s_negative_cache[READER_NEGATIVE_CACHE_SIZE];
static size_t s_negative_cache_next;

static uint32_t reader_user_hash(const char *user)
{
    uint32_t h = 2166136261u;
    if (!user) return h;
    while (*user) {
        h ^= (uint8_t)(unsigned char)*user++;
        h *= 16777619u;
    }
    return h;
}

static bool negative_entry_matches(const S_READER_NEGATIVE_ENTRY *e,
                                   const S_READER_DISPATCH_CTX *ctx, int reader_index)
{
    return e->valid && e->reader_index == reader_index &&
           e->caid == ctx->request.caid && e->sid == ctx->request.sid &&
           e->provid == ctx->request.provid && e->ecm_len == ctx->request.ecm_len &&
           e->user_hash == reader_user_hash(ctx->user) &&
           memcmp(e->ecm_md5, ctx->ecm_md5, TCMG_ECM_MD5_LEN) == 0;
}

static bool reader_negative_cache_hit(const S_READER_DISPATCH_CTX *ctx, int reader_index)
{
    bool hit = false;
    int64_t now = tcmg_mono_ms();
    pthread_mutex_lock(&s_negative_cache_mtx);
    for (size_t i = 0; i < READER_NEGATIVE_CACHE_SIZE; i++) {
        S_READER_NEGATIVE_ENTRY *e = &s_negative_cache[i];
        if (e->valid && e->expires_ms <= now) e->valid = false;
        if (negative_entry_matches(e, ctx, reader_index)) {
            hit = true;
            break;
        }
    }
    pthread_mutex_unlock(&s_negative_cache_mtx);
    return hit;
}

static void reader_negative_cache_forget(const S_READER_DISPATCH_CTX *ctx, int reader_index)
{
    pthread_mutex_lock(&s_negative_cache_mtx);
    for (size_t i = 0; i < READER_NEGATIVE_CACHE_SIZE; i++) {
        S_READER_NEGATIVE_ENTRY *e = &s_negative_cache[i];
        if (negative_entry_matches(e, ctx, reader_index)) e->valid = false;
    }
    pthread_mutex_unlock(&s_negative_cache_mtx);
}

static void reader_negative_cache_store(const S_READER_DISPATCH_CTX *ctx, int reader_index)
{
    S_READER_NEGATIVE_ENTRY *e;
    if (!ctx || reader_index < 0 || reader_index >= MAX_READERS) return;
    pthread_mutex_lock(&s_negative_cache_mtx);
    e = &s_negative_cache[s_negative_cache_next++ % READER_NEGATIVE_CACHE_SIZE];
    memset(e, 0, sizeof(*e));
    e->valid = true;
    e->reader_index = reader_index;
    e->caid = ctx->request.caid;
    e->sid = ctx->request.sid;
    e->provid = ctx->request.provid;
    e->ecm_len = ctx->request.ecm_len;
    e->user_hash = reader_user_hash(ctx->user);
    e->expires_ms = tcmg_mono_ms() + READER_NEGATIVE_CACHE_TTL_MS;
    memcpy(e->ecm_md5, ctx->ecm_md5, TCMG_ECM_MD5_LEN);
    pthread_mutex_unlock(&s_negative_cache_mtx);
}

static int reader_job_compare(const S_READER_JOB *a, const S_READER_JOB *b, int mode)
{
    /* A reader that has only returned NOT_FOUND should not outrank an
     * untried or proven-good reader merely because the negative reply was fast. */
    bool a_known_bad = a->stats.cw_ok == 0 && a->stats.cw_nok > 0;
    bool b_known_bad = b->stats.cw_ok == 0 && b->stats.cw_nok > 0;
    if (a_known_bad != b_known_bad) return a_known_bad ? 1 : -1;

    if (mode == 1) { /* fastest successful CW first; unseen readers warm up first */
        if ((a->stats.samples == 0) != (b->stats.samples == 0)) return a->stats.samples == 0 ? -1 : 1;
        if (a->stats.avg_ms != b->stats.avg_ms) return a->stats.avg_ms < b->stats.avg_ms ? -1 : 1;
    } else if (mode == 2) { /* longest time since last successful ECM first */
        if ((a->stats.last_ok_s == 0) != (b->stats.last_ok_s == 0)) return a->stats.last_ok_s == 0 ? -1 : 1;
        if (a->stats.last_ok_s != b->stats.last_ok_s) return a->stats.last_ok_s < b->stats.last_ok_s ? -1 : 1;
    } else if (mode == 3) { /* lowest live usage first, then successful latency */
        if (a->stats.busy != b->stats.busy) return a->stats.busy < b->stats.busy ? -1 : 1;
        if ((a->stats.samples == 0) != (b->stats.samples == 0)) return a->stats.samples == 0 ? -1 : 1;
        if (a->stats.avg_ms != b->stats.avg_ms) return a->stats.avg_ms < b->stats.avg_ms ? -1 : 1;
    }
    return a->index < b->index ? -1 : (a->index > b->index ? 1 : 0);
}

static void reader_sort_jobs(S_READER_DISPATCH_CTX *ctx)
{
    if (!ctx || ctx->lb_mode < 1 || ctx->lb_mode > 3 || ctx->jobs_count < 2) return;
    for (int i = 1; i < ctx->jobs_count; i++) {
        S_READER_JOB key = ctx->jobs[i];
        int j = i;
        while (j > 0 && reader_job_compare(&key, &ctx->jobs[j - 1], ctx->lb_mode) < 0) {
            ctx->jobs[j] = ctx->jobs[j - 1];
            j--;
        }
        ctx->jobs[j] = key;
    }
}

static int failure_rank(E_READER_FAILURE failure)
{
    switch (failure) {
    case READER_FAILURE_TRANSPORT_ERROR: return 3;
    case READER_FAILURE_CARD_ERROR:
    case READER_FAILURE_READER_ERROR: return 2;
    case READER_FAILURE_NOT_FOUND: return 1;
    default: return 0;
    }
}

static void reader_ctx_retain(S_READER_DISPATCH_CTX *ctx)
{
    if (ctx) atomic_fetch_add_explicit(&ctx->refs, 1, memory_order_relaxed);
}

static void reader_ctx_destroy(S_READER_DISPATCH_CTX *ctx)
{
    if (!ctx) return;
    account_release(ctx->account);
    pthread_cond_destroy(&ctx->cv);
    pthread_mutex_destroy(&ctx->mtx);
    secure_zero(ctx, sizeof(*ctx));
    free(ctx);
}

static void reader_ctx_release(S_READER_DISPATCH_CTX *ctx)
{
    if (!ctx) return;
    if (atomic_fetch_sub_explicit(&ctx->refs, 1, memory_order_acq_rel) == 1)
        reader_ctx_destroy(ctx);
}

static void reader_ctx_record_failure(S_READER_DISPATCH_CTX *ctx, E_READER_FAILURE failure)
{
    if (!ctx) return;
    pthread_mutex_lock(&ctx->mtx);
    if (failure_rank(failure) > failure_rank(ctx->failure_summary))
        ctx->failure_summary = failure;
    pthread_mutex_unlock(&ctx->mtx);
}

static void reader_job_publish_failure(S_READER_JOB *job)
{
    S_READER_DISPATCH_CTX *ctx = job->ctx;
    if (job->failure != READER_FAILURE_NONE)
        reader_ctx_record_failure(ctx, job->failure);
    pthread_mutex_lock(&ctx->mtx);
    if (ctx->active_jobs > 0) ctx->active_jobs--;
    pthread_cond_broadcast(&ctx->cv);
    pthread_mutex_unlock(&ctx->mtx);
}

static void reader_job_run(S_READER_JOB *job)
{
    S_READER_DISPATCH_CTX *ctx;
    S_ECM_REQUEST request;
    int32_t rc;
    int64_t started_ms;
    uint32_t elapsed_ms;

    if (!job || !job->ctx || !job->protocol || !job->protocol->do_ecm) {
        if (job) reader_job_publish_failure(job);
        return;
    }

    ctx = job->ctx;
    request = ctx->request;
    request.cw = job->cw;
    job->failure = READER_FAILURE_READER_ERROR;
    memset(job->cw, 0, sizeof(job->cw));

    pthread_mutex_lock(&ctx->mtx);
    bool already_done = ctx->winner;
    pthread_mutex_unlock(&ctx->mtx);
    if (already_done) {
        job->failure = READER_FAILURE_NONE;
        reader_job_publish_failure(job);
        return;
    }

    started_ms = tcmg_mono_ms();
    reader_stats_job_begin(job->index);
    rc = job->protocol->do_ecm(&(S_READER_ECM_REQUEST){
        .index = job->index,
        .reader = &job->reader,
        .request = &request,
        .failure = &job->failure,
    });
    elapsed_ms = (uint32_t)(tcmg_mono_ms() - started_ms);
    reader_stats_job_end(job->index);

    if (job->failure == READER_FAILURE_REJECTED) {
        pthread_mutex_lock(&ctx->mtx);
        ctx->whitelist_rejected = true;
        pthread_mutex_unlock(&ctx->mtx);
    } else {
        reader_stats_record_timed(job->index, rc == EMU_OK, elapsed_ms);
    }

    if (rc == EMU_OK) {
        reader_negative_cache_forget(ctx, job->index);
        int32_t cache_groups[MAX_GROUPS_PER_READER] = {0};
        int ngrp = job->reader.ngroups;
        if (ngrp <= 0) {
            cache_groups[0] = 1;
            ngrp = 1;
        } else {
            if (ngrp > MAX_GROUPS_PER_READER) ngrp = MAX_GROUPS_PER_READER;
            memcpy(cache_groups, job->reader.groups,
                   (size_t)ngrp * sizeof(cache_groups[0]));
        }
        cw_cache_store_groups(ctx->ecm_md5, job->cw, cache_groups, ngrp);
        pthread_mutex_lock(&ctx->mtx);
        if (!ctx->winner) {
            memcpy(ctx->cw, job->cw, sizeof(ctx->cw));
            ctx->result.status = EMU_OK;
            ctx->result.reader_index = job->index;
            ctx->result.cache_hit = 0;
            ctx->result.source = TCMG_ECM_SOURCE_READER;
            ctx->result.failure = READER_FAILURE_NONE;
            ctx->result.ngroups = ngrp;
            memcpy(ctx->result.groups, cache_groups,
                   (size_t)ngrp * sizeof(ctx->result.groups[0]));
            ctx->winner = true;
        }
        if (ctx->active_jobs > 0) ctx->active_jobs--;
        pthread_cond_broadcast(&ctx->cv);
        pthread_mutex_unlock(&ctx->mtx);
        secure_zero(cache_groups, sizeof(cache_groups));
        return;
    }

    if (ctx->lb_mode >= 1 && ctx->lb_mode <= 3 &&
        job->failure == READER_FAILURE_NOT_FOUND)
        reader_negative_cache_store(ctx, job->index);
    tcmg_log_dbg(D_READER,
                 "skip/failed index=%d label='%s' protocol=%s caid=%04X sid=%04X rc=%d",
                 job->index, job->reader.label, job->reader.protocol,
                 request.caid, request.sid, rc);
    reader_job_publish_failure(job);
}

static void reader_job_cancel(S_READER_JOB *job)
{
    if (!job || !job->ctx) return;
    job->failure = READER_FAILURE_NONE;
    reader_job_publish_failure(job);
}

static void *reader_pool_worker(void *arg)
{
    (void)arg;
    for (;;) {
        S_READER_JOB *job;
        pthread_mutex_lock(&s_reader_pool_mtx);
        while (!s_reader_pool_stop && !s_reader_pool_head)
            pthread_cond_wait(&s_reader_pool_cv, &s_reader_pool_mtx);
        if (s_reader_pool_stop) {
            pthread_mutex_unlock(&s_reader_pool_mtx);
            break;
        }
        job = s_reader_pool_head;
        s_reader_pool_head = job->next;
        if (!s_reader_pool_head) s_reader_pool_tail = NULL;
        job->next = NULL;
        pthread_mutex_unlock(&s_reader_pool_mtx);

        reader_job_run(job);
        reader_ctx_release(job->ctx);
    }
    return NULL;
}

static void reader_pool_start_once(void)
{
    for (int i = 0; i < READER_WORKER_COUNT; i++) {
        int trc = pthread_create(&s_reader_pool_threads[i], NULL, reader_pool_worker, NULL);
        if (trc != 0) {
            tcmg_log("reader pool worker %d failed rc=%d (%s); continuing with %d workers",
                     i, trc, strerror(trc), s_reader_pool_count);
            break;
        }
        s_reader_pool_count++;
    }
}

static bool reader_pool_available(void)
{
    pthread_once(&s_reader_pool_once, reader_pool_start_once);
    return s_reader_pool_count > 0;
}

static bool reader_pool_submit(S_READER_JOB *job)
{
    if (!job) return false;
    pthread_mutex_lock(&s_reader_pool_mtx);
    if (s_reader_pool_stop) {
        pthread_mutex_unlock(&s_reader_pool_mtx);
        return false;
    }
    job->next = NULL;
    if (s_reader_pool_tail)
        s_reader_pool_tail->next = job;
    else
        s_reader_pool_head = job;
    s_reader_pool_tail = job;
    pthread_cond_signal(&s_reader_pool_cv);
    pthread_mutex_unlock(&s_reader_pool_mtx);
    return true;
}

static void reader_pool_shutdown(void)
{
    S_READER_JOB *pending;
    if (s_reader_pool_count == 0) return;
    pthread_mutex_lock(&s_reader_pool_mtx);
    if (s_reader_pool_stop) {
        pthread_mutex_unlock(&s_reader_pool_mtx);
        return;
    }
    s_reader_pool_stop = true;
    pending = s_reader_pool_head;
    s_reader_pool_head = NULL;
    s_reader_pool_tail = NULL;
    pthread_cond_broadcast(&s_reader_pool_cv);
    pthread_mutex_unlock(&s_reader_pool_mtx);

    while (pending) {
        S_READER_JOB *next = pending->next;
        pending->next = NULL;
        reader_job_cancel(pending);
        reader_ctx_release(pending->ctx);
        pending = next;
    }

    for (int i = 0; i < s_reader_pool_count; i++)
        pthread_join(s_reader_pool_threads[i], NULL);
    s_reader_pool_count = 0;
}

static S_READER_DISPATCH_CTX *reader_ctx_create(const S_ECM_REQUEST *request,
                                                 const uint8_t *md5)
{
    S_READER_DISPATCH_CTX *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    if (pthread_mutex_init(&ctx->mtx, NULL) != 0) {
        free(ctx);
        return NULL;
    }
    if (pthread_cond_init(&ctx->cv, NULL) != 0) {
        pthread_mutex_destroy(&ctx->mtx);
        free(ctx);
        return NULL;
    }
    ctx->account = request->account;
    account_retain(ctx->account);
    ctx->request = *request;
    ctx->request.client = NULL;
    ctx->request.account = ctx->account;
    ctx->request.cw = NULL;
    ctx->request.ecm = ctx->ecm;
    ctx->request.ecm_len = request->ecm_len;
    tcmg_strlcpy(ctx->user, request->user ? request->user : "", sizeof(ctx->user));
    ctx->request.user = ctx->user;
    memcpy(ctx->ecm, request->ecm, (size_t)request->ecm_len);
    memcpy(ctx->ecm_md5, md5, sizeof(ctx->ecm_md5));
    reader_result_init(&ctx->result);
    atomic_init(&ctx->refs, 1);
    return ctx;
}

static void reader_fill_jobs(S_READER_DISPATCH_CTX *ctx)
{
    if (!ctx) return;

    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    ctx->lb_mode = g_cfg.lb_mode;
    ctx->lb_nbest_readers = g_cfg.lb_nbest_readers;
    if (ctx->lb_nbest_readers < 1) ctx->lb_nbest_readers = 1;
    if (ctx->lb_nbest_readers > MAX_READERS) ctx->lb_nbest_readers = MAX_READERS;
    for (int i = 0; i < MAX_READERS && ctx->jobs_count < MAX_READERS; i++) {
        const S_READER *reader = &g_cfg.readers[i];
        if (!reader->in_use || !reader->enabled) continue;

        E_READER_RULE_RESULT rule = reader_rule_check(reader, ctx->account,
                                                       ctx->request.caid, ctx->request.sid,
                                                       ctx->request.provid, ctx->request.ecm_len);
        if (rule != READER_RULE_ALLOW) {
            if (rule == READER_RULE_ECM_WHITELIST) {
                char whitelist_spec[CFGVAL_LEN];
                ctx->whitelist_rejected = true;
                reader_ecm_whitelist_get_spec(reader, whitelist_spec, sizeof(whitelist_spec));
                tcmg_log("ecm rejected label='%s' caid=%04X sid=%04X len=%d whitelist='%s'",
                         reader->label, ctx->request.caid, ctx->request.sid,
                         ctx->request.ecm_len, whitelist_spec);
            }
            continue;
        }

        if (ctx->lb_mode >= 1 && ctx->lb_mode <= 3 && reader_negative_cache_hit(ctx, i)) {
            tcmg_log_dbg(D_READER,
                         "short negative-cache skip index=%d label='%s' caid=%04X sid=%04X len=%d",
                         i, reader->label, ctx->request.caid, ctx->request.sid, ctx->request.ecm_len);
            continue;
        }

        const S_READER_PROTOCOL *protocol = reader_protocol_find(reader->protocol);
        if (!protocol || !protocol->do_ecm) {
            tcmg_log_dbg(D_READER, "index=%d label='%s' unknown protocol=%s",
                         i, reader->label, reader->protocol);
            continue;
        }

        S_READER_JOB *job = &ctx->jobs[ctx->jobs_count++];
        memset(job, 0, sizeof(*job));
        job->ctx = ctx;
        job->index = i;
        job->reader = *reader;
        job->protocol = protocol;
        job->failure = READER_FAILURE_NONE;
        reader_stats_snapshot(i, &job->stats);
        ctx->attempted = true;
    }
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    reader_sort_jobs(ctx);
}


int32_t reader_dispatch_ecm(const S_ECM_REQUEST *request, S_READER_RESULT *result)
{
    uint8_t local_md5[TCMG_ECM_MD5_LEN];
    const uint8_t *ecm_md5 = NULL;
    S_READER_DISPATCH_CTX *ctx = NULL;
    S_CW_INFLIGHT_WAIT inflight_wait = { .slot = -1, .generation = 0 };
    bool inflight_leader = false;

    if (result) reader_result_init(result);
    if (!request || !request->account || !request->ecm || !request->cw ||
        request->ecm_len <= 0 || request->ecm_len > TCMG_MAX_ECM_SIZE)
        return -1;

    if (request->ecm_md5_valid) {
        ecm_md5 = request->ecm_md5;
    } else {
        crypt_md5_hash(request->ecm, (size_t)request->ecm_len, local_md5);
        ecm_md5 = local_md5;
    }

    int32_t inflight_groups[MAX_GROUPS_PER_READER] = {0};
    int32_t inflight_ngroups = 0;

    for (;;) {
        inflight_ngroups = 0;
        E_CW_INFLIGHT_BEGIN inflight =
            cw_inflight_begin(ecm_md5, request->cw, request->account, true, &inflight_wait,
                              inflight_groups, &inflight_ngroups);

        if (inflight == CW_INFLIGHT_HIT) {
            if (result) {
                result->status = EMU_OK;
                result->reader_index = -1;
                result->cache_hit = 1;
                result->source = TCMG_ECM_SOURCE_CACHE;
                result->failure = READER_FAILURE_NONE;
                result->ngroups = inflight_ngroups;
                if (inflight_ngroups > 0)
                    memcpy(result->groups, inflight_groups,
                           (size_t)inflight_ngroups * sizeof(result->groups[0]));
            }
            secure_zero(local_md5, sizeof(local_md5));
            return EMU_OK;
        }

        if (inflight == CW_INFLIGHT_WAIT) {
            if (cw_inflight_wait(&inflight_wait, ecm_md5, request->cw, request->account, true,
                                 inflight_groups, &inflight_ngroups)) {
                if (result) {
                    result->status = EMU_OK;
                    result->reader_index = -1;
                    result->cache_hit = 0;
                    result->source = TCMG_ECM_SOURCE_SHARED;
                    result->failure = READER_FAILURE_NONE;
                    result->ngroups = inflight_ngroups;
                    if (inflight_ngroups > 0)
                        memcpy(result->groups, inflight_groups,
                               (size_t)inflight_ngroups * sizeof(result->groups[0]));
                }
                secure_zero(local_md5, sizeof(local_md5));
                return EMU_OK;
            }
            continue;
        }

        inflight_leader = true;
        break;
    }

    ctx = reader_ctx_create(request, ecm_md5);
    if (!ctx) {
        if (inflight_leader) cw_inflight_complete(ecm_md5, false);
        secure_zero(local_md5, sizeof(local_md5));
        return -1;
    }

    reader_fill_jobs(ctx);
    if (ctx->jobs_count == 0) {
        cw_inflight_complete(ecm_md5, false);
        pthread_mutex_lock(&ctx->mtx);
        int32_t final_result = ctx->whitelist_rejected ? READER_RESULT_REJECTED : READER_RESULT_NOT_FOUND;
        if (result) {
            result->status = final_result;
            result->failure = ctx->whitelist_rejected ? READER_FAILURE_REJECTED : READER_FAILURE_NOT_FOUND;
        }
        pthread_mutex_unlock(&ctx->mtx);
        reader_ctx_release(ctx);
        secure_zero(local_md5, sizeof(local_md5));
        return final_result;
    }

    if (antishare_begin_ecm(ctx->account) != AS_CHECK_OK) {
        tcmg_log("ecm rejected: anti-share rate limit user='%s' caid=%04X sid=%04X",
                 ctx->request.user ? ctx->request.user : "?",
                 ctx->request.caid, ctx->request.sid);
        antishare_clear_pending(request->account, request->thread_id, request->caid, request->sid);
        cw_inflight_complete(ecm_md5, false);
        pthread_mutex_lock(&ctx->mtx);
        if (result) {
            result->status = READER_RESULT_REJECTED;
            result->reader_index = -1;
            result->failure = READER_FAILURE_REJECTED;
        }
        pthread_mutex_unlock(&ctx->mtx);
        reader_ctx_release(ctx);
        secure_zero(local_md5, sizeof(local_md5));
        return READER_RESULT_REJECTED;
    }

    {
        bool use_lb = ctx->lb_mode >= 1 && ctx->lb_mode <= 3;
        int batch_size = use_lb ? ctx->lb_nbest_readers : ctx->jobs_count;
        bool pool_ok = ctx->jobs_count > 1 ? reader_pool_available() : false;
        if (batch_size < 1) batch_size = 1;

        for (int first = 0; first < ctx->jobs_count; first += batch_size) {
            int count = ctx->jobs_count - first;
            if (count > batch_size) count = batch_size;
            pthread_mutex_lock(&ctx->mtx);
            bool already_won = ctx->winner;
            pthread_mutex_unlock(&ctx->mtx);
            if (already_won) break;

            if (count == 1 || !pool_ok) {
                pthread_mutex_lock(&ctx->mtx);
                ctx->active_jobs = count;
                pthread_mutex_unlock(&ctx->mtx);
                for (int i = 0; i < count; i++)
                    reader_job_run(&ctx->jobs[first + i]);
            } else {
                pthread_mutex_lock(&ctx->mtx);
                ctx->active_jobs = count;
                pthread_mutex_unlock(&ctx->mtx);
                for (int i = 0; i < count; i++) {
                    S_READER_JOB *job = &ctx->jobs[first + i];
                    reader_ctx_retain(ctx);
                    if (!reader_pool_submit(job)) {
                        reader_job_cancel(job);
                        reader_ctx_release(ctx);
                    }
                }
                pthread_mutex_lock(&ctx->mtx);
                while (!ctx->winner && ctx->active_jobs > 0)
                    pthread_cond_wait(&ctx->cv, &ctx->mtx);
                pthread_mutex_unlock(&ctx->mtx);
            }

            if (!use_lb) break;
        }
    }

    pthread_mutex_lock(&ctx->mtx);
    bool success = ctx->winner;
    if (success) {
        if (result) *result = ctx->result;
        memcpy(request->cw, ctx->cw, CW_LEN);
        pthread_mutex_unlock(&ctx->mtx);
        antishare_end_ecm(ctx->account, true);
        cw_inflight_complete(ecm_md5, success);
        reader_ctx_release(ctx);
        secure_zero(local_md5, sizeof(local_md5));
        return EMU_OK;
    }

    int32_t final_result = (!ctx->attempted && ctx->whitelist_rejected)
                               ? READER_RESULT_REJECTED : READER_RESULT_NOT_FOUND;
    if (result) {
        result->status = final_result;
        result->failure = (!ctx->attempted && ctx->whitelist_rejected)
                              ? READER_FAILURE_REJECTED
                              : (ctx->failure_summary == READER_FAILURE_NONE
                                 ? READER_FAILURE_NOT_FOUND : ctx->failure_summary);
    }
    pthread_mutex_unlock(&ctx->mtx);
    antishare_end_ecm(ctx->account, false);
    cw_inflight_complete(ecm_md5, false);
    reader_ctx_release(ctx);
    secure_zero(local_md5, sizeof(local_md5));
    return final_result;
}


void reader_shutdown(void)
{
    reader_pool_shutdown();
    for (size_t i = 0; i < reader_protocol_count(); i++) {
        const S_READER_PROTOCOL *protocol = reader_protocol_at(i);
        if (protocol && protocol->shutdown) protocol->shutdown();
    }
}
