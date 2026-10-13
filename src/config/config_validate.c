#define MODULE_LOG_PREFIX "conf"
#include "config_internal.h"
#include "../reader/protocol.h"
#include <ctype.h>

void cfg_path_sibling(char *out,size_t outsz,const char *global,const char *name)
{
    char dir[CFGPATH_LEN];tcmg_strlcpy(dir,global,sizeof(dir));char*p1=strrchr(dir,'/'),*p2=strrchr(dir,'\\'),*p=p1>p2?p1:p2;if(p)*p='\0';else tcmg_strlcpy(dir,".",sizeof(dir));tcmg_build_path(out,outsz,dir,name);
}

bool cfg_validate(S_CONFIG *c, char *err, size_t esz)
{
    int ports[4];
    int port_count = 0;

    if (!c) {
        snprintf(err, esz, "null configuration");
        return false;
    }

    if (c->newcamd_port) ports[port_count++] = c->newcamd_port;
    if (c->cccam_port) ports[port_count++] = c->cccam_port;
    if (c->cs378x_port) ports[port_count++] = c->cs378x_port;
    if (c->webif_enabled && c->webif_port) ports[port_count++] = c->webif_port;

    for (int i = 0; i < port_count; i++) {
        for (int j = i + 1; j < port_count; j++) {
            if (ports[i] == ports[j]) {
                snprintf(err, esz, "port conflict on %d", ports[i]);
                return false;
            }
        }
    }

    for (S_ACCOUNT *a = c->accounts; a; a = a->next) {
        if (!a->user[0]) {
            snprintf(err, esz, "account without user");
            return false;
        }
        if (!a->ngroups || a->ngroups > MAX_GROUPS_PER_ACC) {
            snprintf(err, esz, "account '%s' has invalid groups", a->user);
            return false;
        }
        if (a->ncaids > MAX_CAIDS_PER_ACC || a->nidents > MAX_IDENT_FILTERS) {
            snprintf(err, esz, "account '%s' has invalid filter sizes", a->user);
            return false;
        }
        for (S_ACCOUNT *b = a->next; b; b = b->next) {
            if (!strcmp(a->user, b->user)) {
                snprintf(err, esz, "duplicate account user '%s'", a->user);
                return false;
            }
        }
    }

    for (int i = 0; i < MAX_READERS; i++) {
        S_READER *r = &c->readers[i];
        if (!r->in_use) continue;

        if (!r->label[0]) {
            snprintf(err, esz, "reader[%d] has empty label", i);
            return false;
        }
        if (!r->ngroups || r->ngroups > MAX_GROUPS_PER_READER) {
            snprintf(err, esz, "reader[%d] '%s' has invalid groups", i, r->label);
            return false;
        }
        if (r->ncaids > MAX_CAIDS_PER_READER || r->nidents > MAX_IDENT_FILTERS || r->nsid_whitelist > MAX_SID_WHITELIST) {
            snprintf(err, esz, "reader[%d] '%s' has invalid list size", i, r->label);
            return false;
        }

        const S_READER_PROTOCOL *protocol = reader_protocol_find(r->protocol);
        if (!protocol) {
            snprintf(err, esz, "reader[%d] '%s': unsupported protocol '%s'", i, r->label, r->protocol);
            return false;
        }

        if (!strcasecmp(protocol->name, "emu")) {
            if (r->enabled && r->nkeys == 0) {
                snprintf(err, esz, "reader[%d] '%s': enabled emu reader requires ecmkey", i, r->label);
                return false;
            }
        }
        else if (!strcasecmp(protocol->name, "pcsc")) {
            if (r->enabled && !r->device[0]) {
                snprintf(err, esz, "reader[%d] '%s': PCSC reader requires a device/reader selector", i, r->label);
                return false;
            }
            if (r->fast_reset < 0 || r->fast_reset > 86400 ||
                r->fast_reset_idle < 0 || r->fast_reset_idle > 86400 ||
                r->poll_ms < 25 || r->poll_ms > 10000) {
                snprintf(err, esz, "reader[%d] '%s': invalid PCSC timing", i, r->label);
                return false;
            }
        }
        else if (!strcasecmp(protocol->name, "internal")) {
            if (r->enabled && !r->device[0]) {
                /* Empty internal device means automatic backend detection. */
            }
            if (r->fast_reset < 0 || r->fast_reset > 86400 ||
                r->fast_reset_idle < 0 || r->fast_reset_idle > 86400) {
                snprintf(err, esz, "reader[%d] '%s': invalid internal reader settings", i, r->label);
                return false;
            }
        }
        else if (!strcasecmp(protocol->name, "serial")) {
            if (r->enabled && !r->device[0]) {
                snprintf(err, esz, "reader[%d] '%s': serial port is required", i, r->label);
                return false;
            }
            if (r->fast_reset < 0 || r->fast_reset > 86400 ||
                r->fast_reset_idle < 0 || r->fast_reset_idle > 86400 ||
                r->poll_ms < 25 || r->poll_ms > 10000) {
                snprintf(err, esz, "reader[%d] '%s': invalid serial timing", i, r->label);
                return false;
            }
        }
        if (reader_protocol_kind(r->protocol) == READER_PROTOCOL_CARD) {
            if (r->maintenance_mode != TCMG_READER_MAINT_FAST_RESET && r->maintenance_mode != TCMG_READER_MAINT_OLD_ECM) {
                snprintf(err, esz, "reader[%d] '%s': invalid maintenance mode", i, r->label);
                return false;
            }
            if (r->maintenance_mode == TCMG_READER_MAINT_OLD_ECM) {
                if (r->old_ecm_source != TCMG_OLD_ECM_SOURCE_AUTO && r->old_ecm_source != TCMG_OLD_ECM_SOURCE_MANUAL) {
                    snprintf(err, esz, "reader[%d] '%s': invalid old ECM source", i, r->label);
                    return false;
                }
                if (r->old_ecm_successes < 1 || r->old_ecm_successes > 1000000) {
                    snprintf(err, esz, "reader[%d] '%s': invalid old ECM success count", i, r->label);
                    return false;
                }
                size_t old_len = strlen(r->old_ecm);
                if (old_len > TCMG_OLD_ECM_HEX_LEN || (old_len & 1u)) {
                    snprintf(err, esz, "reader[%d] '%s': invalid old ECM", i, r->label);
                    return false;
                }
                for (size_t z = 0; z < old_len; z++) {
                    if (!isxdigit((unsigned char)r->old_ecm[z])) {
                        snprintf(err, esz, "reader[%d] '%s': invalid old ECM", i, r->label);
                        return false;
                    }
                }
                if (r->old_ecm_source == TCMG_OLD_ECM_SOURCE_MANUAL) {
                    if (old_len < 2 || old_len / 2u > 249u) {
                        snprintf(err, esz, "reader[%d] '%s': manual old ECM is missing or too long", i, r->label);
                        return false;
                    }
                    if (r->ecm_whitelist > 0 && (int32_t)(old_len / 2u) != r->ecm_whitelist) {
                        snprintf(err, esz, "reader[%d] '%s': manual old ECM length does not match ecmwhitelist", i, r->label);
                        return false;
                    }
                }
            }
        }

        else if (reader_protocol_kind(r->protocol) == READER_PROTOCOL_NETWORK) {
            const char *comma;
            int32_t port;

            if (!r->enabled) continue;
            if (!r->device[0]) {
                snprintf(err, esz, "reader[%d] '%s': device is required", i, r->label);
                return false;
            }

            comma = strrchr(r->device, ',');
            if (!comma || comma == r->device || !comma[1]) {
                snprintf(err, esz, "reader[%d] '%s': invalid device '%s' (expected host,port)",
                         i, r->label, r->device);
                return false;
            }
            if (!cfg_parse_i32_range(comma + 1, 1, 65535, &port)) {
                snprintf(err, esz, "reader[%d] '%s': invalid port", i, r->label);
                return false;
            }

            if (!strcasecmp(r->protocol, "newcamd") || !strcasecmp(r->protocol, "mgcamd")) {
                bool nonzero = false;
                for (size_t j = 0; j < sizeof(r->newcamd_key); j++) {
                    if (r->newcamd_key[j]) {
                        nonzero = true;
                        break;
                    }
                }
                if (!nonzero) {
                    snprintf(err, esz, "reader[%d] '%s': key is required", i, r->label);
                    return false;
                }
                if (!r->user[0]) {
                    snprintf(err, esz, "reader[%d] '%s': user is required", i, r->label);
                    return false;
                }
            }
        }
    }

    return true;
}

bool cfg_listener_settings_changed(const S_CONFIG *old_cfg,
                                          const S_CONFIG *new_cfg,
                                          char *err, size_t errsz)
{
    if (old_cfg->webif_enabled != new_cfg->webif_enabled ||
        old_cfg->webif_port != new_cfg->webif_port ||
        strcmp(old_cfg->webif_bindaddr, new_cfg->webif_bindaddr) != 0) {
        snprintf(err, errsz,
                 "webif listener changed; restart TCMG to apply port/bind changes");
        return true;
    }
    if (old_cfg->newcamd_port != new_cfg->newcamd_port ||
        strcmp(old_cfg->newcamd_bindaddr, new_cfg->newcamd_bindaddr) != 0) {
        snprintf(err, errsz,
                 "newcamd listener changed; restart TCMG to apply port/bind changes");
        return true;
    }
    if (old_cfg->cccam_port != new_cfg->cccam_port ||
        strcmp(old_cfg->cccam_bindaddr, new_cfg->cccam_bindaddr) != 0) {
        snprintf(err, errsz,
                 "cccam listener changed; restart TCMG to apply port/bind changes");
        return true;
    }
    if (old_cfg->cs378x_port != new_cfg->cs378x_port ||
        strcmp(old_cfg->cs378x_bindaddr, new_cfg->cs378x_bindaddr) != 0) {
        snprintf(err, errsz,
                 "cs378x listener changed; restart TCMG to apply port/bind changes");
        return true;
    }
    return false;
}
