#define MODULE_LOG_PREFIX "stats"
#include "stats.h"
#include "../platform/platform.h"

#include <stdatomic.h>
#include <limits.h>

#define READER_ACTIVE_WINDOW_S 8

static _Atomic uint32_t s_cw_ok[MAX_READERS];
static _Atomic uint32_t s_cw_nok[MAX_READERS];
static _Atomic uint32_t s_last_ok_s[MAX_READERS];
static _Atomic uint32_t s_avg_ms[MAX_READERS];
static _Atomic uint32_t s_samples[MAX_READERS];
static _Atomic uint32_t s_busy[MAX_READERS];

static void note_success(int index, bool success)
{
    if (success) {
        atomic_fetch_add_explicit(&s_cw_ok[index], 1, memory_order_relaxed);
        atomic_store_explicit(&s_last_ok_s[index], (uint32_t)(tcmg_mono_ms32() / 1000u), memory_order_release);
    } else {
        atomic_fetch_add_explicit(&s_cw_nok[index], 1, memory_order_relaxed);
    }
}

void reader_stats_record(int index, bool success)
{
    if (index < 0 || index >= MAX_READERS) return;
    note_success(index, success);
}

void reader_stats_record_timed(int index, bool success, uint32_t elapsed_ms)
{
    uint32_t old_avg, new_avg;
    if (index < 0 || index >= MAX_READERS) return;
    note_success(index, success);
    /* Load-balancer latency is meaningful only for successful CWs. A quick
     * NOT_FOUND must not make a reader look like the fastest candidate. */
    if (!success) return;
    if (elapsed_ms == 0) elapsed_ms = 1;
    atomic_fetch_add_explicit(&s_samples[index], 1, memory_order_relaxed);
    old_avg = atomic_load_explicit(&s_avg_ms[index], memory_order_relaxed);
    do {
        /* A bounded EWMA reacts to changed reader performance without letting
         * a single timeout permanently dominate the order. */
        if (old_avg == 0) new_avg = elapsed_ms;
        else new_avg = (uint32_t)(((uint64_t)old_avg * 7u + elapsed_ms) / 8u);
    } while (!atomic_compare_exchange_weak_explicit(&s_avg_ms[index], &old_avg, new_avg,
                                                      memory_order_relaxed, memory_order_relaxed));
}

void reader_stats_job_begin(int index)
{
    if (index < 0 || index >= MAX_READERS) return;
    atomic_fetch_add_explicit(&s_busy[index], 1, memory_order_relaxed);
}

void reader_stats_job_end(int index)
{
    uint32_t current;
    if (index < 0 || index >= MAX_READERS) return;
    current = atomic_load_explicit(&s_busy[index], memory_order_relaxed);
    while (current > 0 && !atomic_compare_exchange_weak_explicit(&s_busy[index], &current, current - 1,
                                                                  memory_order_relaxed, memory_order_relaxed)) {}
}

void reader_stats_snapshot(int index, S_READER_STATS_SNAPSHOT *out)
{
    uint32_t last_ok, now;
    if (!out) return;
    out->cw_ok = 0;
    out->cw_nok = 0;
    out->active = 0;
    out->busy = 0;
    out->samples = 0;
    out->avg_ms = 0;
    out->last_ok_s = 0;
    if (index < 0 || index >= MAX_READERS) return;

    out->cw_ok = atomic_load_explicit(&s_cw_ok[index], memory_order_relaxed);
    out->cw_nok = atomic_load_explicit(&s_cw_nok[index], memory_order_relaxed);
    {
        uint32_t busy = atomic_load_explicit(&s_busy[index], memory_order_relaxed);
        out->busy = busy > (uint32_t)INT_MAX ? INT_MAX : (int)busy;
    }
    out->samples = atomic_load_explicit(&s_samples[index], memory_order_relaxed);
    out->avg_ms = atomic_load_explicit(&s_avg_ms[index], memory_order_relaxed);
    last_ok = atomic_load_explicit(&s_last_ok_s[index], memory_order_acquire);
    out->last_ok_s = last_ok;
    now = (uint32_t)(tcmg_mono_ms32() / 1000u);
    out->active = last_ok != 0 && (uint32_t)(now - last_ok) <= READER_ACTIVE_WINDOW_S;
}

void reader_stats_reset(int index)
{
    if (index < 0 || index >= MAX_READERS) return;
    atomic_store_explicit(&s_cw_ok[index], 0, memory_order_relaxed);
    atomic_store_explicit(&s_cw_nok[index], 0, memory_order_relaxed);
    atomic_store_explicit(&s_last_ok_s[index], 0, memory_order_release);
    atomic_store_explicit(&s_avg_ms[index], 0, memory_order_relaxed);
    atomic_store_explicit(&s_samples[index], 0, memory_order_relaxed);
    atomic_store_explicit(&s_busy[index], 0, memory_order_relaxed);
}
