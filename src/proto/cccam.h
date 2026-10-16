#ifndef TCMG_CCCAM_H_
#define TCMG_CCCAM_H_

#include <stdint.h>
#include "core/constants.h"

#define CCCAM_MSG_MAX       (TCMG_MAX_ECM_SIZE + 64)
#define CCCAM_SEED_LEN      16
#define CCCAM_HASH_LEN      20

#define CCCAM_CMD_CLI_DATA   0x00
#define CCCAM_CMD_ECM_REQ    0x01
#define CCCAM_CMD_EMM_REQ    0x02
#define CCCAM_CMD_CARD_REM   0x04
#define CCCAM_CMD_KEEPALIVE  0x06
#define CCCAM_CMD_NEW_CARD   0x07
#define CCCAM_CMD_SRV_DATA   0x08
#define CCCAM_CMD_ECM_NOK1   0xFE
#define CCCAM_CMD_ECM_NOK2   0xFF

typedef struct {
    uint8_t keytable[256];
    uint8_t state;
    uint8_t counter;
    uint8_t sum;
} S_CC_CRYPT;

typedef struct {
    int        fd;
    char       ip[MAXIPLEN];
    uint8_t    g_flag;
    uint8_t    node_id[8];
    uint8_t    peer_node_id[8];
    S_CC_CRYPT send_block;
    S_CC_CRYPT recv_block;
} S_CCCAM_CLIENT;

int32_t cccam_start(void);
void    cccam_stop(void);
void   *handle_cccam_client(void *arg);

#endif
