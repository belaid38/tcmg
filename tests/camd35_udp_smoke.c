#include "core/constants.h"
#include "platform/platform.h"
#include "proto/camd35.h"
#include "crypto/aes128.h"
#include "crypto/crypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) printf("%02X", data[i]);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <host> <port> <username>\n", argv[0]);
        return 2;
    }
    char *end = NULL;
    long port_l = strtol(argv[2], &end, 10);
    if (!end || *end || port_l < 1 || port_l > 65535) return 2;

    static const uint8_t ecm[] = {
        0x80,0x00,0x34,0x00,0x32,0x64,0x00,
        0x7C,0x99,0xBB,0xE9,0x60,0x61,0x74,0x1D,0x82,0xC3,0x57,0x47,0xD5,0x26,0x2E,0x0A,0x0E,
        0x76,0x46,0xAB,0x26,0x35,0x50,0x1A,0xF2,0x63,0xD7,0x26,0x1D,0xC1,0x4F,0x0C,0xF2,
        0x63,0xD7,0x26,0x1D,0xC1,0x4F,0x0C,0x16,0x88,0x9C,0x7D,0x01,0x21,0x9A,0x20
    };
    static const uint8_t expected_cw[CW_LEN] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
    };

    uint8_t ucrc[CS378X_UCRC_LEN], key[16];
    cs378x_user_crc(argv[3], ucrc);
    /* The network test account has password "1234". */
    cs378x_password_key("1234", key);

    uint8_t request[CS378X_HEADER_LEN + sizeof(ecm)] = {0};
    request[0] = CS378X_CMD_ECM_REQ;
    request[1] = (uint8_t)sizeof(ecm);
    request[8] = 0x00; request[9] = 0x64;
    request[10] = 0x0B; request[11] = 0x00;
    memcpy(request + CS378X_HEADER_LEN, ecm, sizeof(ecm));

    uint8_t packet[CS378X_UCRC_LEN + CS378X_MAX_CRYPT];
    size_t packet_len = 0;
    if (cs378x_build_frame(ucrc, key, request, sizeof(request),
                           packet, sizeof(packet), &packet_len) < 0) {
        fprintf(stderr, "request frame creation failed\n");
        return 3;
    }

    int fd = (int)socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 4; }
    struct timeval timeout = {3, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, SO_CAST(&timeout), sizeof(timeout)) < 0) {
        perror("setsockopt"); close(fd); return 4;
    }
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((uint16_t)port_l);
    if (inet_pton(AF_INET, argv[1], &server.sin_addr) != 1) {
        fprintf(stderr, "invalid IPv4 host\n"); close(fd); return 2;
    }
    if (sendto(fd, packet, packet_len, 0,
               (const struct sockaddr *)&server, sizeof(server)) != (ssize_t)packet_len) {
        perror("sendto"); close(fd); return 5;
    }

    uint8_t response[CS378X_UCRC_LEN + CS378X_MAX_CRYPT];
    ssize_t n = recvfrom(fd, response, sizeof(response), 0, NULL, NULL);
    close(fd);
    if (n < (ssize_t)(CS378X_UCRC_LEN + CS378X_HEADER_LEN) ||
        memcmp(response, ucrc, sizeof(ucrc)) != 0) {
        fprintf(stderr, "no valid CAMD35-UDP response\n"); return 6;
    }
    size_t crypt_len = (size_t)n - CS378X_UCRC_LEN;
    if ((crypt_len % CS378X_BLOCK_LEN) != 0) return 7;
    aes128_ecb_decrypt(key, response + CS378X_UCRC_LEN, crypt_len);
    uint8_t *plain = response + CS378X_UCRC_LEN;
    if (plain[0] != CS378X_CMD_ECM_RSP || plain[1] != CW_LEN ||
        crypt_len < CS378X_HEADER_LEN + CW_LEN) {
        fprintf(stderr, "unexpected CAMD35-UDP response cmd=%02X len=%u\n", plain[0], plain[1]);
        return 8;
    }
    uint32_t expected_crc = ((uint32_t)plain[4] << 24) | ((uint32_t)plain[5] << 16) |
                            ((uint32_t)plain[6] << 8) | plain[7];
    uint32_t actual_crc = cs378x_crc32(plain + CS378X_HEADER_LEN, CW_LEN);
    if (expected_crc != actual_crc || memcmp(plain + CS378X_HEADER_LEN, expected_cw, CW_LEN) != 0) {
        fprintf(stderr, "CW or CRC mismatch: cw=");
        print_hex(plain + CS378X_HEADER_LEN, CW_LEN);
        fputc('\n', stderr);
        return 9;
    }
    printf("CAMD35_UDP_SMOKE: PASS cw=");
    print_hex(plain + CS378X_HEADER_LEN, CW_LEN);
    putchar('\n');
    secure_zero(key, sizeof(key));
    return 0;
}
