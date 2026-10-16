#ifndef TCMG_CONFIG_RUNTIME_ACCESS_H_
#define TCMG_CONFIG_RUNTIME_ACCESS_H_

#include "../core/config_types.h"
#include <stdbool.h>
#include <stddef.h>

#define TCMG_RUNTIME_CONFIG_TEXT_MAX CFGVAL_LEN

typedef struct {
    bool enabled;
    int max_fails;
    int ban_secs;
    char allowlist[TCMG_RUNTIME_CONFIG_TEXT_MAX];
} S_CONFIG_FAILBAN_VIEW;

bool cfg_runtime_failban_snapshot(S_CONFIG_FAILBAN_VIEW *out);

typedef struct {
    int32_t sock_timeout;
    int32_t server_keepalive;
    int32_t server_keepalive_misses;
    int8_t  newcamd_keepalive;
    int8_t  newcamd_mgclient;
    uint8_t newcamd_key[14];
} S_CONFIG_NETWORK_VIEW;

bool cfg_runtime_network_snapshot(S_CONFIG_NETWORK_VIEW *out);

typedef struct {
    bool    enabled;
    char    user[CFGKEY_LEN];
    char    socket[CFGPATH_LEN];
    char    boxtype[16];
    int32_t delay_ms;
    int32_t max_services;
    int32_t pmt_mode;
    int32_t listen_port;
    char    serverip[MAXIPLEN];
} S_CONFIG_DVBAPI_VIEW;

bool cfg_runtime_dvbapi_snapshot(S_CONFIG_DVBAPI_VIEW *out);
int cfg_runtime_reader_snapshot(S_READER *out, size_t cap);
int cfg_runtime_reader_snapshot_indexed(S_READER *out, size_t cap);
bool cfg_runtime_reader_get(int index, S_READER *out);

bool cfg_runtime_reader_any(bool (*pred)(const S_READER *r, void *ctx), void *ctx);

#endif
