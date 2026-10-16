#define MODULE_LOG_PREFIX "proto"
#include "registry.h"
#include "cccam.h"
#include "newcamd.h"
#include "camd35_server.h"
#include "camd35_udp_server.h"
#include <string.h>

static const S_PROTO_MODULE s_modules[] = {
    { "cccam",  cccam_start,  cccam_stop  },
    { "newcamd", newcamd_start, newcamd_stop },
    { "cs378x",  cs378x_start,  cs378x_stop  },
    { "camd35",  camd35_udp_start, camd35_udp_stop },
};

size_t proto_module_count(void)
{
    return sizeof(s_modules) / sizeof(s_modules[0]);
}

const S_PROTO_MODULE *proto_module_at(size_t index)
{
    return index < proto_module_count() ? &s_modules[index] : NULL;
}

const S_PROTO_MODULE *proto_module_find(const char *name)
{
    if (!name) return NULL;
    for (size_t i = 0; i < proto_module_count(); i++)
        if (strcasecmp(s_modules[i].name, name) == 0)
            return &s_modules[i];
    return NULL;
}

int32_t proto_start_all(void)
{
    int32_t started = 0;
    for (size_t i = 0; i < proto_module_count(); i++)
        if (s_modules[i].start() == 0)
            started++;
    return started;
}

void proto_stop_all(void)
{
    for (size_t i = proto_module_count(); i > 0; i--)
        s_modules[i - 1].stop();
}
