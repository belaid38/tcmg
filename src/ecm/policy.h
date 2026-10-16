#ifndef TCMG_ECM_POLICY_H_
#define TCMG_ECM_POLICY_H_

#include "types.h"
#include <stdbool.h>

/* Enforce the complete account policy for every network and DVBAPI ECM request.
 * Keeping this interface non-optional avoids per-protocol authorization gaps. */
T_ECM_ACCESS_STATUS ecm_access(S_CLIENT *client, uint16_t caid, uint16_t sid, uint32_t provid);

/* OSCam-style common ingress validation for client-protocol ECM sections.
 * Normalizes the byte count to SCT_LEN, rejects truncated/invalid sections,
 * and corrects a missing or inconsistent provider when it can be derived
 * safely from the ECM payload. */
bool ecm_prepare_input(uint16_t caid, uint32_t *provid,
                       const uint8_t *ecm, int32_t *ecm_len);

/* Protocols such as plain newcamd do not carry the provider id in the request.
 * Returns `provid` if set, else the provider found in the ECM (Viaccess), else the
 * first ident of the account for this CAID, else 0. */
uint32_t ecm_resolve_provid(S_CLIENT *client, uint16_t caid, uint32_t provid,
                            const uint8_t *ecm, int32_t ecm_len);

#endif
