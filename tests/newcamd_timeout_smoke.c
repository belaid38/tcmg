#include "net/net.h"
#include "core/client_types.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#if !defined(_WIN32) && !defined(TCMG_OS_WINDOWS)
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(void)
{
    int fd[2];
    S_CLIENT client;
    uint8_t data[NC_MSG_MAX];
    uint16_t sid = 0, mid = 0, caid = 0;
    uint32_t pid = 0;
    struct timeval timeout = {0, 100000};

    memset(&client, 0, sizeof(client));
    memset(data, 0, sizeof(data));
    assert(nc_recv(NULL, data, &sid, &mid, &pid, &caid) == -1);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    client.session.fd = fd[0];
    assert(setsockopt(fd[0], SOL_SOCKET, SO_RCVTIMEO,
                      &timeout, sizeof(timeout)) == 0);

    /* No frame bytes arrive before the deadline. This is a recoverable idle
     * timeout for Newcamd keepalive, not a corrupted/closed connection. */
    assert(nc_recv(&client, data, &sid, &mid, &pid, &caid) == NET_RECV_TIMEOUT);

    close(fd[0]);
    close(fd[1]);
    puts("newcamd_timeout_smoke: PASS");
    return 0;
}
#else
int main(void)
{
    puts("newcamd_timeout_smoke: SKIP (requires POSIX socketpair)");
    return 0;
}
#endif
