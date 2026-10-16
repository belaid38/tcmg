#ifndef TCMG_WEBIF_SERVICE_TYPES_H_
#define TCMG_WEBIF_SERVICE_TYPES_H_

#include "../../src/core/constants.h"
#include "../../src/core/ident_types.h"
#include "../../src/core/reader_types.h"
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define WEBIF_TEXT_64 64
#define WEBIF_TEXT_128 128
#define WEBIF_TEXT_256 256
#define WEBIF_TEXT_512 512
#define WEBIF_TEXT_1024 1024
#define WEBIF_GROUPS_LEN 128
#define WEBIF_CAID_LIST_LEN 64
#define WEBIF_IDENT_LIST_LEN 384
#define WEBIF_SID_LIST_LEN 384
#define WEBIF_ECMKEYS_LEN 1024

_Static_assert(WEBIF_GROUPS_LEN >= MAX_GROUPS_PER_READER * 6, "WEBIF_GROUPS_LEN too small");
_Static_assert(WEBIF_CAID_LIST_LEN >= MAX_CAIDS_PER_READER * 5, "WEBIF_CAID_LIST_LEN too small");
_Static_assert(WEBIF_SID_LIST_LEN >= MAX_SID_WHITELIST * 5, "WEBIF_SID_LIST_LEN too small");
_Static_assert(WEBIF_ECMKEYS_LEN >= MAX_ECMKEYS_PER_ACC * 70, "WEBIF_ECMKEYS_LEN too small");

#ifndef MAX_ACTIVE_CLIENTS
#define MAX_ACTIVE_CLIENTS 64
#endif

#ifndef MAX_READERS
#define MAX_READERS 16
#endif

typedef struct {
    char user[CFGKEY_LEN];
    char pass[CFGKEY_LEN];
    char groups[WEBIF_GROUPS_LEN];
    char caids[WEBIF_CAID_LIST_LEN];
    char idents[WEBIF_IDENT_LIST_LEN];
    int enabled;
    int max_connections;
    int active;
    int anti_share;
    int as_max_sids;
    int as_max_ecm;
    int as_ecm_window_s;
    int as_channel_timeout_s;
    int as_switch_delay_s;
    time_t expirationdate;
    int64_t cw_found;
    int64_t cw_not;
    uint64_t ecm_total;
    int64_t cw_time_total_ms;
    int64_t cw_time_min_ms;
    int64_t cw_time_max_ms;
    int64_t cw_last_60s;
    time_t first_login;
    time_t last_seen;
    char last_ip[MAXIPLEN];
} S_WEBIF_ACCOUNT_VIEW;

typedef struct {
    char label[READER_LABEL_LEN];
    char protocol[READER_PROTOCOL_LEN];
    char device[CFGVAL_LEN];
    char backend[32];
    char user[CFGKEY_LEN];
    char password[CFGKEY_LEN];
    char key[32];
    char groups[WEBIF_GROUPS_LEN];
    char caids[WEBIF_CAID_LIST_LEN];
    char idents[WEBIF_IDENT_LIST_LEN];
    char sid_whitelist[WEBIF_SID_LIST_LEN];
    char ecmkeys[WEBIF_ECMKEYS_LEN];
    int index;
    int enabled;
    int inactivitytimeout;
    int ecm_whitelist;
    char ecmwhitelist[CFGVAL_LEN];
    int deprecated;
    int fast_reset;
    int fast_reset_idle;
    int poll_ms;
    int maintenance_mode;
    int old_ecm_source;
    int old_ecm_successes;
    char old_ecm[TCMG_OLD_ECM_HEX_LEN + 1];
    int64_t cw_ok;
    int64_t cw_nok;
    int active;
} S_WEBIF_READER_VIEW;

typedef struct {
    char user[CFGKEY_LEN];
    char caids[WEBIF_CAID_LIST_LEN];
    int enabled;
    int64_t cw_found;
    int64_t cw_not;
    int64_t cw_time_total_ms;
    int64_t cw_last_60s;
    time_t last_seen;
    char last_ip[MAXIPLEN];
} S_WEBIF_USER_STATS_VIEW;

typedef struct {
    char label[READER_LABEL_LEN];
    char protocol[READER_PROTOCOL_LEN];
    char device[CFGVAL_LEN];
    char groups[WEBIF_GROUPS_LEN];
    char caids[WEBIF_CAID_LIST_LEN];
    int index;
    int enabled;
    int active;
    int64_t cw_ok;
    int64_t cw_nok;
} S_WEBIF_READER_LIST_VIEW;

typedef struct {
    char user[CFGKEY_LEN];
    char ip[MAXIPLEN];
    char proto[READER_PROTOCOL_LEN];
    char channel[80];
    uint16_t caid;
    uint16_t sid;
    uint32_t thread_id;
    time_t connect_time;
    time_t last_activity;
    int64_t cw_last_60s;
} S_WEBIF_CLIENT_VIEW;

typedef struct {
    int webif_enabled;
    int newcamd_port;
    int has_newcamd_bindaddr;
    char newcamd_bindaddr[MAXIPLEN];
    uint8_t newcamd_key[14];
    int newcamd_keepalive;
    int newcamd_mgclient;
    int cccam_port;
    int cs378x_port;
    char cs378x_bindaddr[MAXIPLEN];
    int camd35_port;
    char camd35_bindaddr[MAXIPLEN];
    int sock_timeout;
    int server_keepalive;
    int server_keepalive_misses;
    int ecm_log;
    int scheduled_restart_enabled;
    char scheduled_restart_time[6];
    char logfile[CFGPATH_LEN];
    int webif_port;
    int webif_refresh;
    char webif_user[CFGKEY_LEN];
    char webif_pass[CFGKEY_LEN];
    char webif_bindaddr[MAXIPLEN];
    int failban_enabled;
    char failban_allowlist[CFGVAL_LEN];
    int failban_max_fails;
    int failban_ban_secs;
    char seller_name[CFGVAL_LEN];
    char seller_type[16];
    char seller_host[CFGKEY_LEN];
    int seller_port;
    int dvbapi_enabled;
    char dvbapi_user[CFGKEY_LEN];
    char dvbapi_socket[CFGPATH_LEN];
    char dvbapi_boxtype[16];
    int dvbapi_delay_ms;
    int dvbapi_max_services;
} S_WEBIF_CONFIG_VIEW;

typedef struct {
    int has_newcamd_port;
    int newcamd_port;
    int has_newcamd_bindaddr;
    char newcamd_bindaddr[MAXIPLEN];
    int has_newcamd_key;
    uint8_t newcamd_key[14];
    int has_newcamd_keepalive;
    int newcamd_keepalive;
    int has_newcamd_mgclient;
    int newcamd_mgclient;
    int has_cccam_port;
    int cccam_port;
    int has_cs378x_port;
    int cs378x_port;
    int has_cs378x_bindaddr;
    char cs378x_bindaddr[MAXIPLEN];
    int has_camd35_port;
    int camd35_port;
    int has_camd35_bindaddr;
    char camd35_bindaddr[MAXIPLEN];
    int has_sock_timeout;
    int sock_timeout;
    int has_server_keepalive;
    int server_keepalive;
    int has_server_keepalive_misses;
    int server_keepalive_misses;
    int has_ecm_log;
    int ecm_log;
    int has_scheduled_restart;
    int scheduled_restart_enabled;
    int has_scheduled_restart_time;
    char scheduled_restart_time[6];
    int has_logfile;
    char logfile[CFGPATH_LEN];
    int has_webif_port;
    int webif_port;
    int has_webif_refresh;
    int webif_refresh;
    int has_webif_user;
    char webif_user[CFGKEY_LEN];
    int has_webif_pass;
    char webif_pass[CFGKEY_LEN];
    int has_webif_bindaddr;
    char webif_bindaddr[MAXIPLEN];
    int has_failban_enabled;
    int failban_enabled;
    int has_failban_allowlist;
    char failban_allowlist[CFGVAL_LEN];
    int has_failban_max_fails;
    int failban_max_fails;
    int has_failban_ban_secs;
    int failban_ban_secs;
    int has_seller_name;
    char seller_name[CFGVAL_LEN];
    int has_seller_type;
    char seller_type[16];
    int has_seller_host;
    char seller_host[CFGKEY_LEN];
    int has_seller_port;
    int seller_port;
    int has_dvbapi_enabled;
    int dvbapi_enabled;
    int has_dvbapi_user;
    char dvbapi_user[CFGKEY_LEN];
    int has_dvbapi_socket;
    char dvbapi_socket[CFGPATH_LEN];
    int has_dvbapi_boxtype;
    char dvbapi_boxtype[16];
    int has_dvbapi_delay;
    int dvbapi_delay_ms;
    int has_dvbapi_max_services;
    int dvbapi_max_services;
} S_WEBIF_CONFIG_PATCH;

typedef struct {
    char user[CFGKEY_LEN];
    char pass[CFGKEY_LEN];
    char groups[WEBIF_GROUPS_LEN];
    char caid[WEBIF_CAID_LIST_LEN];
    char ident[WEBIF_IDENT_LIST_LEN];
    int has_caid;
    int has_max_connections;
    int max_connections;
    int has_enabled;
    int enabled;
    int has_expiry;
    time_t expiry;
    int has_anti_share;
    int anti_share;
    int as_max_sids;
    int as_max_ecm;
    int as_ecm_window_s;
    int as_channel_timeout_s;
    int as_switch_delay_s;
    int32_t groupv[MAX_GROUPS_PER_ACC];
    int32_t ngroups;
    uint16_t caidv[MAX_CAIDS_PER_ACC + 1];
    int ncaidv;
    S_IDENT_FILTER identv[MAX_IDENT_FILTERS];
    int nidentv;
    int has_ident;
} S_WEBIF_ACCOUNT_EDIT;

typedef struct {
    char label[READER_LABEL_LEN];
    char protocol[READER_PROTOCOL_LEN];
    char device[CFGVAL_LEN];
    char user[CFGKEY_LEN];
    char password[CFGKEY_LEN];
    char key[32];
    char inactivitytimeout[16];
    char caid[WEBIF_CAID_LIST_LEN];
    char ident[WEBIF_IDENT_LIST_LEN];
    char sid_whitelist[WEBIF_SID_LIST_LEN];
    char ecmwhitelist[CFGVAL_LEN];
    char group[WEBIF_GROUPS_LEN];
    char ecmkeys[WEBIF_ECMKEYS_LEN];
    char enabled[8];
    char deprecated[8];
    char fast_reset[16];
    char fast_reset_idle[16];
    char poll_ms[16];
    char maintenance_mode[24];
    char old_ecm_source[16];
    char old_ecm_successes[16];
    char old_ecm[TCMG_OLD_ECM_HEX_LEN + 1];
    int index;
} S_WEBIF_READER_EDIT;

typedef struct {
    char ip[MAXIPLEN];
    time_t until;
} S_WEBIF_BAN_VIEW;

typedef struct {
    int active_bans;
    int max_fails;
    int ban_secs;
} S_WEBIF_BAN_STATS;

typedef struct {
    int64_t cw_found;
    int64_t cw_not;
    int64_t ecm_total;
    double hit_rate;
    int nbans;
    int naccounts;
    int active_conns;
    time_t uptime_s;
    char uptime_str[32];
} S_WEBIF_SERVER_STATS;

#endif
