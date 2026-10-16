#define MODULE_LOG_PREFIX "camd35"
#include "../crypto/crypto.h"
#include "../net/net.h"
#include "../log/log.h"
#include "../crypto/aes128.h"
#include "camd35.h"

static uint32_t crc32_table[256];
static pthread_once_t crc_once = PTHREAD_ONCE_INIT;

static void crc_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) c = (c >> 1) ^ (c & 1 ? 0xEDB88320U : 0);
        crc32_table[i] = c;
    }
}

uint32_t cs378x_crc32(const uint8_t *data, size_t len)
{
    pthread_once(&crc_once, crc_init);
    uint32_t c = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; i++) c = (c >> 8) ^ crc32_table[(c ^ data[i]) & 0xFF];
    return c ^ 0xFFFFFFFFU;
}

void cs378x_user_crc(const char *user, uint8_t out[4])
{
    uint8_t md5[16];
    uint32_t c;
    if (!user || !out) return;
    crypt_md5_hash((const uint8_t *)user, strlen(user), md5);
    c = cs378x_crc32(md5, sizeof(md5));
    out[0] = (uint8_t)(c >> 24); out[1] = (uint8_t)(c >> 16);
    out[2] = (uint8_t)(c >> 8);  out[3] = (uint8_t)c;
    secure_zero(md5, sizeof(md5));
}

void cs378x_password_key(const char *password, uint8_t out[16])
{
    if (!password || !out) return;
    crypt_md5_hash((const uint8_t *)password, strlen(password), out);
}

static size_t round16(size_t n)
{
    return (n + 15U) & ~((size_t)15U);
}

int cs378x_payload_info(const uint8_t *p, size_t n, size_t *data_len, size_t *plain_len)
{
    if (!p || !data_len || !plain_len || n < CS378X_HEADER_LEN) return -1;
    uint8_t cmd = p[0];
    size_t dl;

    if (cmd == CS378X_CMD_ECM_REQ) {
        if (n < 23) return -1;
        dl = (((size_t)p[21] & 0x0F) << 8) | p[22];
        dl += 3;
    } else if (cmd == CS378X_CMD_CASCADE_REQ || cmd == CS378X_CMD_CASCADE_RSP) {
        dl = p[1];
        if (dl > CS378X_MAX_PAYLOAD) return -1;
        *data_len = dl;
        *plain_len = CS378X_HEADER_LEN + 0x34 + dl;
        return 0;
    } else if (cmd == 0x3D || cmd == 0x3E || cmd == 0x3F) {
        dl = (size_t)p[1] | ((size_t)p[2] << 8);
    } else {
        dl = p[1];
    }

    if (dl > CS378X_MAX_PAYLOAD || CS378X_HEADER_LEN + dl > CS378X_MAX_PLAIN) return -1;
    *data_len = dl;
    *plain_len = CS378X_HEADER_LEN + dl;
    return 0;
}

int cs378x_build_frame(const uint8_t ucrc[4], const uint8_t key[16],
                       const uint8_t *plain, size_t plain_len,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ucrc || !key || !plain || !out || !out_len) return -1;
    if (plain_len < CS378X_HEADER_LEN || plain_len > CS378X_MAX_PLAIN) return -1;
    size_t data_len, expected_plain;
    if (cs378x_payload_info(plain, plain_len, &data_len, &expected_plain) < 0) return -1;
    if (expected_plain != plain_len) return -1;
    if (data_len > plain_len - CS378X_HEADER_LEN) return -1;

    uint32_t crc = cs378x_crc32(plain + CS378X_HEADER_LEN, data_len);
    size_t crypt_len = round16(plain_len);
    size_t total = CS378X_UCRC_LEN + crypt_len;
    if (crypt_len > CS378X_MAX_CRYPT || total > out_cap) return -1;

    memcpy(out, ucrc, 4);
    memcpy(out + 4, plain, plain_len);
    memset(out + 4 + plain_len, 0xFF, crypt_len - plain_len);
    out[8]  = (uint8_t)(crc >> 24);
    out[9]  = (uint8_t)(crc >> 16);
    out[10] = (uint8_t)(crc >> 8);
    out[11] = (uint8_t)crc;
    aes128_ecb_encrypt(key, out + 4, crypt_len);
    *out_len = total;
    return 0;
}

int cs378x_recv_ucrc(int fd, uint8_t ucrc[4])
{
    if (!ucrc) return -1;
    int rc = net_recv_all(fd, ucrc, 4);
    if (rc == NET_RECV_TIMEOUT) return NET_RECV_TIMEOUT;
    return rc == 4 ? 0 : -1;
}

int cs378x_recv_payload(int fd, const uint8_t key[16],
                        uint8_t *plain, size_t plain_cap, size_t *plain_len)
{
    uint8_t first[32];
    if (!key || !plain || !plain_len || plain_cap < 32) return -1;
    int rr = net_recv_all(fd, first, sizeof(first));
    if (rr == NET_RECV_TIMEOUT) return NET_RECV_TIMEOUT;
    if (rr != (int)sizeof(first)) return -1;

    aes128_ecb_decrypt(key, first, sizeof(first));
    size_t data_len, expected_plain;
    if (cs378x_payload_info(first, sizeof(first), &data_len, &expected_plain) < 0) return -1;
    size_t crypt_len = round16(expected_plain);
    if (crypt_len < sizeof(first) || crypt_len > CS378X_MAX_CRYPT || crypt_len > plain_cap) return -1;

    memcpy(plain, first, sizeof(first));
    if (crypt_len > sizeof(first)) {
        rr = net_recv_all(fd, plain + sizeof(first), (int32_t)(crypt_len - sizeof(first)));
        if (rr == NET_RECV_TIMEOUT) return NET_RECV_TIMEOUT;
        if (rr != (int)(crypt_len - sizeof(first))) return -1;
        aes128_ecb_decrypt(key, plain + sizeof(first), crypt_len - sizeof(first));
    }

    if (cs378x_payload_info(plain, crypt_len, &data_len, &expected_plain) < 0) return -1;
    if (expected_plain > crypt_len || round16(expected_plain) != crypt_len) return -1;

    uint32_t want = ((uint32_t)plain[4] << 24) | ((uint32_t)plain[5] << 16) |
                    ((uint32_t)plain[6] << 8) | plain[7];
    uint32_t got = cs378x_crc32(plain + CS378X_HEADER_LEN, data_len);
    if (want != got) return -2;

    *plain_len = expected_plain;
    return 0;
}

int cs378x_send_payload(int fd, const uint8_t ucrc[4], const uint8_t key[16],
                        uint8_t *plain, size_t plain_len)
{
    uint8_t frame[CS378X_UCRC_LEN + CS378X_MAX_CRYPT];
    size_t frame_len;
    if (cs378x_build_frame(ucrc, key, plain, plain_len,
                           frame, sizeof(frame), &frame_len) < 0) return -1;
    return net_send_all(fd, frame, (int32_t)frame_len) == (int32_t)frame_len ? 0 : -1;
}
