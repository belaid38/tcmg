#ifndef TCMG_CAMD35_H_
#define TCMG_CAMD35_H_

#include <stddef.h>
#include <stdint.h>

#define CS378X_CMD_ECM_REQ   0x00
#define CS378X_CMD_ECM_RSP   0x01
#define CS378X_CMD_EMM_REQ   0x02
#define CS378X_CMD_CASCADE_REQ 0x03
#define CS378X_CMD_CASCADE_RSP 0x04
#define CS378X_CMD_CARD_DATA 0x05
#define CS378X_CMD_EMM_DATA  0x06
#define CS378X_CMD_STOP      0x08
#define CS378X_CMD_ERROR     0x44
#define CS378X_CMD_KEEPALIVE 0x55

#define CS378X_HEADER_LEN 20
#define CS378X_UCRC_LEN 4
#define CS378X_BLOCK_LEN 16
#define CS378X_MAX_PAYLOAD 1024
#define CS378X_MAX_PLAIN (CS378X_HEADER_LEN + CS378X_MAX_PAYLOAD)
#define CS378X_MAX_CRYPT (CS378X_MAX_PLAIN + 15)

uint32_t cs378x_crc32(const uint8_t *data, size_t len);
int cs378x_payload_info(const uint8_t *plain, size_t available,
                        size_t *data_len, size_t *plain_len);
void cs378x_user_crc(const char *user, uint8_t out[4]);
void cs378x_password_key(const char *password, uint8_t out[16]);

int cs378x_build_frame(const uint8_t ucrc[4], const uint8_t key[16],
                       const uint8_t *plain, size_t plain_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

int cs378x_recv_ucrc(int fd, uint8_t ucrc[4]);
int cs378x_recv_payload(int fd, const uint8_t key[16],
                        uint8_t *plain, size_t plain_cap, size_t *plain_len);

int cs378x_send_payload(int fd, const uint8_t ucrc[4], const uint8_t key[16],
                        uint8_t *plain, size_t plain_len);

#endif
