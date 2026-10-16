#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "proto/registry.h"

int main(void)
{
    static const char *names[] = {"cccam", "newcamd", "cs378x", "camd35"};
    assert(proto_module_count() == 4);

    for (size_t i = 0; i < proto_module_count(); i++) {
        const S_PROTO_MODULE *m = proto_module_at(i);
        assert(m != NULL);
        assert(m->name != NULL);
        assert(m->start != NULL);
        assert(m->stop != NULL);
        assert(strcmp(m->name, names[i]) == 0);
        assert(proto_module_find(names[i]) == m);
    }

    assert(proto_module_at(proto_module_count()) == NULL);
    assert(proto_module_find(NULL) == NULL);
    assert(proto_module_find("does-not-exist") == NULL);
    puts("PROTO_REGISTRY_SMOKE: PASS");
    return 0;
}
