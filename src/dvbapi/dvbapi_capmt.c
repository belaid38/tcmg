#define MODULE_LOG_PREFIX "dvbapi"
#include "dvbapi_capmt.h"
#include <string.h>

static uint32_t be(const uint8_t *p, unsigned n)
{
    uint32_t v = 0;
    for (unsigned i = 0; i < n; i++) v = (v << 8) | p[i];
    return v;
}

int dvbapi_frame_next(const uint8_t *buf, size_t len, size_t *consumed,
                      E_DVBAPI_MSG *type, const uint8_t **body, size_t *body_len)
{
    size_t hdr, blen;
    E_DVBAPI_MSG t;

    if (!buf || !consumed || !type || !body || !body_len) return -1;
    if (len < 4) return 0;
    if (buf[0] != 0x9F || buf[1] != 0x80) return -1;
    if (buf[2] == 0x32) t = DVBAPI_MSG_CAPMT;
    else if (buf[2] == 0x3F) t = DVBAPI_MSG_STOP;
    else return -1;

    if (buf[3] < 0x80) {
        hdr = 4;
        blen = buf[3];
    } else {
        /* Follow BER/ASN.1 long-form length as OSCam does. 0x80 (indefinite
         * length) is not valid for these framed CA_PMT/CA_STOP objects. */
        size_t nbytes = (size_t)(buf[3] & 0x7Fu);
        if (nbytes == 0 || nbytes > 4) return -1;
        if (len < 4 + nbytes) return 0;
        hdr = 4 + nbytes;
        blen = 0;
        for (size_t i = 0; i < nbytes; i++) {
            if (blen > (SIZE_MAX >> 8)) return -1;
            blen = (blen << 8) | buf[4 + i];
        }
    }
    if (blen > 8192) return -1;
    if (len < hdr + blen) return 0;
    *type = t;
    *body = buf + hdr;
    *body_len = blen;
    *consumed = hdr + blen;
    return 1;
}

uint32_t dvbapi_ecm_provid(uint16_t caid, const uint8_t *ecm, size_t len)
{
    if (!ecm) return 0;
    if ((caid >> 8) == 0x05 && len >= 8 && ecm[3] == 0x90 && ecm[4] == 0x03)
        return be(ecm + 5, 3) & 0xFFFFF0u;
    return 0;
}

static uint32_t cadesc_provid(uint16_t caid, const uint8_t *priv, size_t plen)
{
    if ((caid >> 8) == 0x01 && plen >= 2)
        return be(priv, 2);
    if ((caid >> 8) == 0x05 && plen >= 5 && priv[0] == 0x14 && priv[1] == 0x03)
        return be(priv + 2, 3) & 0xFFFFF0u;
    return 0;
}

static void add_ecm(S_DVBAPI_CAPMT *o, uint16_t caid, uint16_t pid, uint32_t provid, uint32_t smask)
{
    for (int i = 0; i < o->n_ecm; i++) {
        /* OSCam keeps alternatives separate when CAID/provider differs, even
         * if the receiver advertises the same ECM PID for several CA systems. */
        if (o->ecm[i].pid != pid || o->ecm[i].caid != caid || o->ecm[i].provid != provid)
            continue;
        if (smask == 0 || o->ecm[i].stream_mask == 0) o->ecm[i].stream_mask = 0;
        else o->ecm[i].stream_mask |= smask;
        return;
    }
    if (o->n_ecm >= DVBAPI_MAX_ECM) return;
    o->ecm[o->n_ecm].caid = caid;
    o->ecm[o->n_ecm].pid = pid;
    o->ecm[o->n_ecm].provid = provid;
    o->ecm[o->n_ecm].stream_mask = smask;
    o->n_ecm++;
}

static int parse_descs(const uint8_t *d, size_t len, S_DVBAPI_CAPMT *o, int stream_idx)
{
    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag = d[pos], dl = d[pos + 1];
        const uint8_t *p = d + pos + 2;
        if (pos + 2 + dl > len) return -1;
        switch (tag) {
        case 0x09:
            if (dl >= 4) {
                uint16_t caid = (uint16_t)be(p, 2);
                uint16_t pid = (uint16_t)(be(p + 2, 2) & 0x1FFF);
                uint32_t smask = stream_idx >= 0 ? (1u << (unsigned)stream_idx) : 0;
                add_ecm(o, caid, pid, cadesc_provid(caid, p + 4, (size_t)dl - 4), smask);
            }
            break;
        case 0x81:
            if (dl == 8 && stream_idx < 0) {
                o->ens = be(p, 4);
                o->tsid = (uint16_t)be(p + 4, 2);
                o->onid = (uint16_t)be(p + 6, 2);
            }
            break;
        case 0x82: /* deprecated: ca_mask + demux device */
            if (dl == 2 && stream_idx < 0) {
                uint8_t dmx = p[1];
                o->ca_mask = p[0];
                o->demux = dmx == 0xFF ? 0 : dmx;
            }
            break;
        case 0x83:
            if (dl == 1 && stream_idx < 0) o->adapter = p[0];
            break;
        case 0x84:
            if (dl == 2 && stream_idx < 0) o->pmt_pid = (uint16_t)(be(p, 2) & 0x1FFFu);
            break;
        case 0x85: /* optional service-type bit mask */
            if (dl == 4 && stream_idx < 0) o->service_type_mask = be(p, 4);
            break;
        case 0x86: /* demux device: does not describe the CA-device mask */
            if (dl == 1 && stream_idx < 0) o->demux = p[0];
            break;
        case 0x87: /* CA-device index, encoded as a bit in TCMG's mask */
            if (dl == 1 && stream_idx < 0) {
                if (p[0] >= 32) return -1; /* TCMG supports a 32-bit CA mask */
                o->ca_mask = 1u << p[0];
            }
            break;
        default:
            break;
        }
        pos += 2u + dl;
    }
    return pos == len ? 0 : -1;
}

int dvbapi_stop_parse(const uint8_t *body, size_t len, int *demux)
{
    if (!body || !demux || len != 4) return -1;
    if (body[0] != 0x83 || body[1] != 0x02) return -1;
    *demux = body[3];
    return 0;
}

int dvbapi_capmt_parse(const uint8_t *b, size_t len, S_DVBAPI_CAPMT *o)
{
    size_t pos, pil;
    if (!b || !o || len < 6) return -1;
    memset(o, 0, sizeof(*o));
    o->ca_mask = 1;

    o->list_mgmt = b[0];
    if (o->list_mgmt > CAPMT_LIST_UPDATE) return -1;
    o->program = (uint16_t)be(b + 1, 2);
    o->version = (uint8_t)((b[3] >> 1) & 0x1F);
    pil = be(b + 4, 2) & 0x0FFF;
    pos = 6;
    if (pos + pil > len) return -1;
    if (pil > 0) {
        o->cmd_id = b[pos];
        /* OSCam tolerates receivers that send command id zero. */
        if (o->cmd_id < CAPMT_CMD_OK_DESCRAMBLING)
            o->cmd_id = CAPMT_CMD_OK_DESCRAMBLING;
        if (parse_descs(b + pos + 1, pil - 1, o, -1) < 0) return -1;
    } else {
        o->cmd_id = CAPMT_CMD_OK_DESCRAMBLING;
    }
    pos += pil;

    while (pos + 5 <= len) {
        uint8_t stype = b[pos];
        uint16_t epid = (uint16_t)(be(b + pos + 1, 2) & 0x1FFF);
        size_t esl = be(b + pos + 3, 2) & 0x0FFF;
        int idx = -1;
        pos += 5;
        if (pos + esl > len) return -1;
        if (o->n_streams < DVBAPI_MAX_STREAMS) {
            idx = o->n_streams;
            o->stream_pid[idx] = epid;
            o->stream_type[idx] = stype;
            o->n_streams++;
        }
        if (esl > 0 && idx >= 0) {
            size_t desc_off = 0;
            uint8_t es_cmd = b[pos];
            /* Enigma2 follows EN 50221 and includes ca_pmt_cmd_id in each ES
             * info loop. Some older senders omit it; OSCam distinguishes a
             * command byte (0..4) from descriptor tags. */
            if (es_cmd <= CAPMT_CMD_NOT_SELECTED) {
                desc_off = 1;
                if (es_cmd < CAPMT_CMD_OK_DESCRAMBLING)
                    es_cmd = CAPMT_CMD_OK_DESCRAMBLING;
                o->cmd_id = es_cmd; /* Enigma2 sends the same command at both levels. */
            }
            if (es_cmd != CAPMT_CMD_NOT_SELECTED && esl >= desc_off && esl > desc_off) {
                if (parse_descs(b + pos + desc_off, esl - desc_off, o, idx) < 0) return -1;
            }
        }
        pos += esl;
    }
    if (pos != len) return -1;
    if (o->ca_mask == 0) {
        if (o->demux >= 32) return -1;
        o->ca_mask = 1u << o->demux;
    }
    return 0;
}
