/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Test-only faults in the runtime process, below the WASI socket API. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__APPLE__)
#define HOOK(name) stalled_##name
#define REAL_CLOSE(fd) close(fd)
#define REAL_CONNECT(fd, addr, len) connect(fd, addr, len)
#define REAL_POLL(fds, count, timeout) poll(fds, count, timeout)
#define REAL_LOOKUP(node, service, hints, result) getaddrinfo(node, service, hints, result)
#else
#define HOOK(name) name
#define REAL_CLOSE(fd) syscall(SYS_close, fd)
#define REAL_CONNECT(fd, addr, len) syscall(SYS_connect, fd, addr, len)
#define REAL_POLL(fds, count, timeout) \
    ((int (*)(struct pollfd *, nfds_t, int))dlsym(RTLD_NEXT, "poll"))(fds, count, timeout)
#define REAL_LOOKUP(node, service, hints, result)                                       \
    ((int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **)) \
            dlsym(RTLD_NEXT, "getaddrinfo"))(node, service, hints, result)
#endif /* defined(__APPLE__) */

static int peers[4096];
static unsigned char interrupted[4096];
static int announced;

int HOOK(connect)(int fd, const struct sockaddr *addr, socklen_t len)
{
    int pair[2];
    char buffer[4096] = { 0 };

    if (addr == NULL || len < sizeof(struct sockaddr_in) || addr->sa_family != AF_INET
        || ((const struct sockaddr_in *)addr)->sin_addr.s_addr != htonl(INADDR_LOOPBACK))
        return REAL_CONNECT(fd, addr, len);
    if (ntohs(((const struct sockaddr_in *)addr)->sin_port) == 10) {
        static const char marker[] = "# forbidden-connect\n";

        write(STDERR_FILENO, marker, sizeof(marker) - 1);
        _exit(98);
    }
    if (ntohs(((const struct sockaddr_in *)addr)->sin_port) != 9)
        return REAL_CONNECT(fd, addr, len);
    if (!announced) {
        static const char marker[] = "# connect-pending\n";

        write(STDERR_FILENO, marker, sizeof(marker) - 1);
        announced = 1;
    }
    if (fd < 0 || fd >= 4096 || socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
        abort();
    /* Keep the runtime's connect future unready without a host TCP backlog. */
    if (fcntl(pair[0], F_SETFL, O_NONBLOCK) < 0)
        abort();
    while (write(pair[0], buffer, sizeof(buffer)) > 0)
        ;
    if (errno != EAGAIN || dup2(pair[0], fd) < 0)
        abort();
    REAL_CLOSE(pair[0]);
    peers[fd] = pair[1];
    interrupted[fd] = 0;
    errno = EINPROGRESS;
    return -1;
}

int HOOK(close)(int fd)
{
    if (fd >= 0 && fd < 4096 && peers[fd] != 0) {
        int peer = peers[fd];

        peers[fd] = 0;
        REAL_CLOSE(peer);
    }
    return REAL_CLOSE(fd);
}

int HOOK(poll)(struct pollfd *fds, nfds_t count, int timeout)
{
    nfds_t i;

    for (i = 0; timeout == 0 && i < count; i++) {
        int fd = fds[i].fd;

        if (fd >= 0 && fd < 4096 && peers[fd] != 0 && !interrupted[fd]) {
            static const char marker[] = "# interrupted-poll\n";

            interrupted[fd] = 1;
            write(STDERR_FILENO, marker, sizeof(marker) - 1);
            errno = EINTR;
            return -1;
        }
    }
    return REAL_POLL(fds, count, timeout);
}

int HOOK(getaddrinfo)(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **result)
{
    if (node != NULL && strcmp(node, "openssl-wasi-denied.invalid") == 0) {
        static const char marker[] = "# forbidden-resolver\n";

        write(STDERR_FILENO, marker, sizeof(marker) - 1);
        _exit(98);
    }
    if (node != NULL && strcmp(node, "openssl-wasi-pending.invalid") == 0) {
        static const char marker[] = "# resolver-pending\n";

        write(STDERR_FILENO, marker, sizeof(marker) - 1);
        for (;;)
            pause();
    }
    return REAL_LOOKUP(node, service, hints, result);
}

#if defined(__APPLE__)
#define INTERPOSE(name)                                                   \
    __attribute__((used)) static struct {                                 \
        const void *new_fn, *old_fn;                                      \
    } interpose_##name __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)stalled_##name,                          \
        (const void *)(uintptr_t)name                                     \
    }
INTERPOSE(connect);
INTERPOSE(close);
INTERPOSE(poll);
INTERPOSE(getaddrinfo);
#endif /* defined(__APPLE__) */
