#ifndef TCMG_DVBAPI_CAPMT_H_
#define TCMG_DVBAPI_CAPMT_H_

#include <stddef.h>
#include <stdint.h>

#define DVBAPI_MAX_ECM      24 /* OSCam MAX_ECM_PIDS */
#define DVBAPI_MAX_STREAMS  32

#define CAPMT_LIST_MORE     0x00
#define CAPMT_LIST_FIRST    0x01
#define CAPMT_LIST_LAST     0x02
#define CAPMT_LIST_ONLY     0x03
#define CAPMT_LIST_ADD      0x04
#define CAPMT_LIST_UPDATE   0x05

#define CAPMT_CMD_OK_DESCRAMBLING 0x01
#define CAPMT_CMD_OK_MMI          0x02
#define CAPMT_CMD_QUERY           0x03
#define CAPMT_CMD_NOT_SELECTED    0x04

typedef enum {
    DVBAPI_MSG_NONE = 0,
    DVBAPI_MSG_CAPMT,
    DVBAPI_MSG_STOP
} E_DVBAPI_MSG;

typedef struct {
    uint16_t caid;
    uint16_t pid;
    uint32_t provid;
    uint32_t stream_mask;
} S_DVBAPI_ECMPID;

typedef struct {
    uint8_t  list_mgmt;
    uint8_t  cmd_id;
    uint16_t program;
    uint8_t  version;
    uint8_t  adapter;
    uint8_t  demux;
    uint32_t ca_mask;
    uint16_t pmt_pid;
    uint32_t service_type_mask;
    uint32_t ens;
    uint16_t tsid;
    uint16_t onid;
    int      n_ecm;
    S_DVBAPI_ECMPID ecm[DVBAPI_MAX_ECM];
    int      n_streams;
    uint16_t stream_pid[DVBAPI_MAX_STREAMS];
    uint8_t  stream_type[DVBAPI_MAX_STREAMS];
} S_DVBAPI_CAPMT;

int dvbapi_frame_next(const uint8_t *buf, size_t len, size_t *consumed,
                      E_DVBAPI_MSG *type, const uint8_t **body, size_t *body_len);
int dvbapi_capmt_parse(const uint8_t *body, size_t len, S_DVBAPI_CAPMT *out);
int dvbapi_stop_parse(const uint8_t *body, size_t len, int *demux);
uint32_t dvbapi_ecm_provid(uint16_t caid, const uint8_t *ecm, size_t len);

#endif
