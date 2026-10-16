#ifndef TCMG_LOG_TYPES_H_
#define TCMG_LOG_TYPES_H_

#include "compat.h"

#define D_WIRE      0x0001
#define D_ECM       0x0002
#define D_EMU       0x0004
#define D_NEWCAMD   0x0008
#define D_CCCAM     0x0010
#define D_HTTP      0x0020
#define D_CONN      0x0040
#define D_READER    0x0080
#define D_PROTOCOL  0x0100
#define D_DVBAPI    0x0200
#define D_ALL       0xFFFF

#define MAX_DEBUG_LEVELS 10

typedef struct {
    uint16_t mask;
    const char *name;
} S_DBLEVEL_NAME;

#endif
