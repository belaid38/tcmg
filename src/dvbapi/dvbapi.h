#ifndef TCMG_DVBAPI_H_
#define TCMG_DVBAPI_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool    enabled;
    bool    running;
    int32_t connections;
    int32_t services;
} S_DVBAPI_STATUS;

int32_t dvbapi_start(void);
void    dvbapi_stop(void);
void    dvbapi_get_status(S_DVBAPI_STATUS *out);

#endif
