#ifndef TCMG_DVBAPI_PRIV_H_
#define TCMG_DVBAPI_PRIV_H_

#include "core/client_types.h"
#include "core/constants.h"
#include "ecm/types.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int  (*demux_open)(int adapter, int demux);
    int  (*demux_filter)(int fd, uint16_t pid, uint8_t tid, uint8_t mask);
    int  (*demux_read)(int fd, uint8_t *buf, size_t len);
    void (*demux_close)(int fd);
    int  (*ca_open)(int adapter, int ca);
    int  (*ca_set_pid)(int fd, uint16_t pid, int idx);
    int  (*ca_set_descr)(int fd, int idx, int parity, const uint8_t cw[8]);
    void (*ca_close)(int fd);
    /* Optional: physical number of DVB-CSA descrambler slots; <=0 means unknown. */
    int  (*ca_descr_count)(int adapter, int ca);
} S_DVBAPI_BACKEND;

typedef int32_t (*T_DVBAPI_ECM_FN)(S_CLIENT *client, uint16_t caid, uint16_t sid,
                                   uint32_t provid, const uint8_t *ecm, int32_t ecm_len,
                                   uint8_t cw[CW_LEN], S_ECM_RESULT *result);

typedef struct {
    const char *socket_path;
    const char *user;
    int         ca_offset;
    int         delay_ms;
    int         max_services;
    int         pmt_mode;   /* 0=listen on camd.socket; 6=connect to Enigma2's listen socket */
    int         listen_port; /* OSCam DVBAPI TCP listener; 0 keeps local camd.socket mode */
    const char *serverip;    /* IPv4 bind address; secure default is 127.0.0.1 */
} S_DVBAPI_SETTINGS;

void    dvbapi_test_hooks(const S_DVBAPI_BACKEND *backend, T_DVBAPI_ECM_FN ecm_fn, int skip_account);
int32_t dvbapi_start_with(const S_DVBAPI_SETTINGS *settings);

#endif
