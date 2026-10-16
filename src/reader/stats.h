#ifndef TCMG_READER_STATS_H_
#define TCMG_READER_STATS_H_

#include <stdbool.h>
#include <stdint.h>

#include "core/constants.h"

typedef struct {
    int64_t cw_ok;
    int64_t cw_nok;
    int active;                 /* successful ECM seen in the recent window */
    int busy;                   /* current ECM jobs in flight */
    uint32_t samples;           /* latency samples */
    uint32_t avg_ms;            /* exponentially smoothed response time */
    uint32_t last_ok_s;         /* monotonic seconds, zero if never successful */
} S_READER_STATS_SNAPSHOT;

void reader_stats_record(int index, bool success);
void reader_stats_record_timed(int index, bool success, uint32_t elapsed_ms);
void reader_stats_job_begin(int index);
void reader_stats_job_end(int index);
void reader_stats_snapshot(int index, S_READER_STATS_SNAPSHOT *out);
void reader_stats_reset(int index);

#endif
