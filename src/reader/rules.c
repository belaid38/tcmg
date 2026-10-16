#define MODULE_LOG_PREFIX "reader"
#include "rules.h"
#include "core/config_state.h"
#include "core/utils.h"
#include "core/constants.h"
#include "protocol.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *whitelist_trim(char *s)
{
    char *end;
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = '\0';
    return s;
}

static bool whitelist_hex(const char *s, size_t max_digits, uint32_t max_value,
                          uint32_t *out)
{
    if (!s || !*s || !out || strlen(s) > max_digits) return false;
    for (const char *p = s; *p; p++)
        if (!isxdigit((unsigned char)*p)) return false;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 16);
    if (end == s || !end || *end || v > max_value) return false;
    *out = (uint32_t)v;
    return true;
}

static bool whitelist_parse_entries(const char *spec,
                                    S_ECM_WHITELIST_ENTRY *entries,
                                    int32_t *count)
{
    char copy[CFGVAL_LEN];
    size_t n;
    int32_t used = 0;
    if (!spec || !entries || !count) return false;
    n = strlen(spec);
    if (n >= sizeof(copy)) return false;
    memcpy(copy, spec, n + 1);
    char *whole = whitelist_trim(copy);
    if (!*whole || !strcmp(whole, "00")) {
        *count = 0;
        return true; /* TCMG legacy: 00 means disabled, retained for compatibility. */
    }
    if (*whole == ';' || whole[strlen(whole) - 1] == ';' || strstr(whole, ";;"))
        return false;

    char *seg_save = NULL;
    for (char *seg = strtok_r(whole, ";", &seg_save); seg;
         seg = strtok_r(NULL, ";", &seg_save)) {
        seg = whitelist_trim(seg);
        if (!*seg) return false;
        uint16_t caid = 0;
        uint32_t provid = 0;
        char *lengths = seg;
        char *colon = strchr(seg, ':');
        if (colon) {
            if (strchr(colon + 1, ':')) return false;
            *colon = '\0';
            char *selector = whitelist_trim(seg);
            lengths = whitelist_trim(colon + 1);
            if (!*selector || !*lengths) return false;
            char *at = strchr(selector, '@');
            if (at) {
                if (strchr(at + 1, '@')) return false;
                *at++ = '\0';
                char *pv = whitelist_trim(at);
                selector = whitelist_trim(selector);
                if (!whitelist_hex(pv, 6, 0xFFFFFFu, &provid)) return false;
            }
            selector = whitelist_trim(selector);
            if (*selector) {
                uint32_t c;
                if (!whitelist_hex(selector, 4, 0xFFFFu, &c)) return false;
                caid = (uint16_t)c;
            } else if (!at) {
                return false;
            }
        } else {
            if (strchr(seg, '@') || !*lengths) return false;
        }

        int32_t before_lengths = used;
        if (!*lengths || strstr(lengths, ",,") || lengths[0] == ',' || lengths[strlen(lengths) - 1] == ',') return false;
        char *len_save = NULL;
        for (char *tok = strtok_r(lengths, ",", &len_save); tok;
             tok = strtok_r(NULL, ",", &len_save)) {
            uint32_t v;
            tok = whitelist_trim(tok);
            if (!whitelist_hex(tok, 4, TCMG_MAX_ECM_SIZE, &v) || used >= TCMG_MAX_ECM_WHITELIST_ENTRIES)
                return false;
            entries[used].len = (uint16_t)v;
            entries[used].caid = caid;
            entries[used].provid = provid;
            used++;
        }
        if (used == before_lengths) return false;
    }
    *count = used;
    return true;
}

bool reader_ecm_whitelist_parse(S_READER *reader, const char *spec)
{
    S_ECM_WHITELIST_ENTRY entries[TCMG_MAX_ECM_WHITELIST_ENTRIES];
    int32_t count = 0;
    char clean[CFGVAL_LEN];
    if (!reader || !spec || strlen(spec) >= sizeof(clean)) return false;
    tcmg_strlcpy(clean, spec, sizeof(clean));
    char *trimmed = whitelist_trim(clean);
    if (!whitelist_parse_entries(trimmed, entries, &count)) return false;

    memset(reader->ecm_whitelist_entries, 0, sizeof(reader->ecm_whitelist_entries));
    if (count > 0)
        memcpy(reader->ecm_whitelist_entries, entries, (size_t)count * sizeof(entries[0]));
    reader->ecm_whitelist_count = count;
    reader->ecm_whitelist = 0;
    if (count == 1 && entries[0].caid == 0 && entries[0].provid == 0)
        reader->ecm_whitelist = entries[0].len;
    tcmg_strlcpy(reader->ecm_whitelist_spec, trimmed, sizeof(reader->ecm_whitelist_spec));
    return true;
}

bool reader_ecm_whitelist_validate(const char *spec)
{
    S_ECM_WHITELIST_ENTRY entries[TCMG_MAX_ECM_WHITELIST_ENTRIES];
    int32_t count = 0;
    if (!spec || strlen(spec) >= CFGVAL_LEN) return false;
    return whitelist_parse_entries(spec, entries, &count);
}

bool reader_ecm_whitelist_allows(const S_READER *reader, uint16_t caid,
                                 uint32_t provid, int32_t ecm_len)
{
    if (!reader) return false;
    if (reader->ecm_whitelist_count > 0) {
        bool found_ident = false;
        for (int32_t i = 0; i < reader->ecm_whitelist_count; i++) {
            const S_ECM_WHITELIST_ENTRY *e = &reader->ecm_whitelist_entries[i];
            if ((e->caid == 0 || e->caid == caid) &&
                (e->provid == 0 || e->provid == provid)) {
                found_ident = true;
                if ((int32_t)e->len == ecm_len) return true;
            }
        }
        return !found_ident;
    }
    if (reader->ecm_whitelist > 0 && ecm_len != reader->ecm_whitelist)
        return false;
    return true;
}

void reader_ecm_whitelist_get_spec(const S_READER *reader, char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!reader) return;
    if (reader->ecm_whitelist_spec[0]) {
        tcmg_strlcpy(out, reader->ecm_whitelist_spec, out_sz);
    } else {
        snprintf(out, out_sz, "%02X", (unsigned)(reader->ecm_whitelist & 0xFF));
    }
}


bool reader_account_has_group(const S_ACCOUNT *acc, int32_t group)
{
    if (!acc || group < 1) return false;
    if (acc->ngroups > 0) {
        for (int i = 0; i < acc->ngroups; i++) {
            if (acc->groups[i] == group) return true;
        }
        return false;
    }
    return acc->group == group;
}

int reader_collect_account_caids(const S_ACCOUNT *acc, uint16_t *out, int32_t cap)
{
    int32_t count = 0;

    if (!acc || !out || cap <= 0) return 0;

    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    for (int32_t i = 0; i < MAX_READERS && count < cap; i++) {
        const S_READER *reader = &g_cfg.readers[i];
        if (!reader->in_use || !reader->enabled || reader->ncaids <= 0) continue;

        bool group_ok = false;
        for (int32_t j = 0; j < reader->ngroups && !group_ok; j++) {
            if (reader_account_has_group(acc, reader->groups[j]))
                group_ok = true;
        }
        if (!group_ok) continue;

        for (int32_t j = 0; j < reader->ncaids && count < cap; j++) {
            uint16_t caid = reader->caids[j];
            if (!caid) continue;

            bool exists = false;
            for (int32_t k = 0; k < count; k++) {
                if (out[k] == caid) {
                    exists = true;
                    break;
                }
            }
            if (!exists) out[count++] = caid;
        }
    }
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return count;
}

E_READER_RULE_RESULT reader_rule_check(const S_READER *reader, const S_ACCOUNT *acc,
                                        uint16_t caid, uint16_t sid, uint32_t provid, int32_t ecm_len)
{
    if (!reader || !acc || !reader->in_use || !reader->enabled)
        return READER_RULE_DISABLED;

    bool group_ok = false;
    if (reader->ngroups > 0) {
        for (int i = 0; i < reader->ngroups; i++) {
            if (reader_account_has_group(acc, reader->groups[i])) {
                group_ok = true;
                break;
            }
        }
    } else {
        group_ok = reader_account_has_group(acc, 1);
    }
    if (!reader_ecm_whitelist_allows(reader, caid, provid, ecm_len))
        return READER_RULE_ECM_WHITELIST;

    if (!group_ok) return READER_RULE_GROUP;

    if (reader->ncaids > 0) {
        bool caid_ok = false;
        for (int i = 0; i < reader->ncaids; i++) {
            if (reader->caids[i] == caid) {
                caid_ok = true;
                break;
            }
        }
        if (!caid_ok) return READER_RULE_CAID;
    }

    if (reader->nidents > 0) {
        bool ident_ok = false;
        for (int i = 0; i < reader->nidents; i++) {
            if (reader->idents[i].caid == caid && reader->idents[i].provid == provid) {
                ident_ok = true;
                break;
            }
        }
        if (!ident_ok) return READER_RULE_IDENT;
    }

    if (reader->nsid_whitelist > 0) {
        bool sid_ok = false;
        for (int i = 0; i < reader->nsid_whitelist; i++) {
            if (reader->sid_whitelist[i] == sid) {
                sid_ok = true;
                break;
            }
        }
        if (!sid_ok) return READER_RULE_SID;
    }

    return READER_RULE_ALLOW;
}

bool reader_allows(const S_READER *reader, const S_ACCOUNT *acc,
                   uint16_t caid, uint16_t sid, uint32_t provid, int32_t ecm_len)
{
    return reader_rule_check(reader, acc, caid, sid, provid, ecm_len) == READER_RULE_ALLOW;
}


/*
 * OSCam's DVBAPI checks matching_reader() before it starts an ECM filter for a
 * CAID/PID. TCMG receives the ECM length only after a section arrives, so this
 * preflight intentionally checks only static reader compatibility and leaves
 * ecmwhitelist validation to reader_dispatch_ecm(). A zero provider means that
 * the CA descriptor did not identify it; in that case an ident rule for the
 * same CAID is a possible match rather than a reason to discard the PID.
 */
bool reader_dvbapi_candidate(const S_ACCOUNT *acc, uint16_t caid, uint16_t sid, uint32_t provid)
{
    bool found = false;
    if (!acc) return false;

    pthread_rwlock_rdlock(&g_cfg.acc_lock);
    for (int i = 0; i < MAX_READERS; i++) {
        const S_READER *reader = &g_cfg.readers[i];
        const S_READER_PROTOCOL *proto;
        bool group_ok = false, caid_ok = true, ident_ok = true, sid_ok = true;

        if (!reader->in_use || !reader->enabled) continue;
        proto = reader_protocol_find(reader->protocol);
        if (!proto || !proto->do_ecm) continue;

        if (reader->ngroups > 0) {
            for (int j = 0; j < reader->ngroups; j++) {
                if (reader_account_has_group(acc, reader->groups[j])) {
                    group_ok = true;
                    break;
                }
            }
        } else {
            group_ok = reader_account_has_group(acc, 1);
        }
        if (!group_ok) continue;

        if (reader->ncaids > 0) {
            caid_ok = false;
            for (int j = 0; j < reader->ncaids; j++) {
                if (reader->caids[j] == caid) { caid_ok = true; break; }
            }
        }
        if (!caid_ok) continue;

        if (reader->nidents > 0) {
            ident_ok = false;
            for (int j = 0; j < reader->nidents; j++) {
                if (reader->idents[j].caid != caid) continue;
                if (provid == 0 || reader->idents[j].provid == provid) {
                    ident_ok = true;
                    break;
                }
            }
        }
        if (!ident_ok) continue;

        if (reader->nsid_whitelist > 0) {
            sid_ok = false;
            for (int j = 0; j < reader->nsid_whitelist; j++) {
                if (reader->sid_whitelist[j] == sid) { sid_ok = true; break; }
            }
        }
        if (!sid_ok) continue;

        found = true;
        break;
    }
    pthread_rwlock_unlock(&g_cfg.acc_lock);
    return found;
}
