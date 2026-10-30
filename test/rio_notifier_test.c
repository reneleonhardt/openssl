/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/rio_notifier.h"
#include <openssl/err.h>
#include "testutil.h"

#if defined(__wasip3__)
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

static int fail_pipe, short_read, interrupt_read;

ssize_t __real_read(int fd, void *buf, size_t len);
ssize_t __wrap_read(int fd, void *buf, size_t len);
ssize_t __wrap_read(int fd, void *buf, size_t len)
{
    if (interrupt_read) {
        interrupt_read = 0;
        errno = EINTR;
        return -1;
    }
    if (short_read && len > 1) {
        short_read = 0;
        len = 1;
    }
    return __real_read(fd, buf, len);
}

int __real_pipe2(int fds[2], int flags);
int __wrap_pipe2(int fds[2], int flags);
int __wrap_pipe2(int fds[2], int flags)
{
    if (fail_pipe) {
        errno = EMFILE;
        return -1;
    }
    return __real_pipe2(fds, flags);
}

static int test_rio_notifier_pipe_failure(void)
{
    RIO_NOTIFIER nfy = { -1, -1 };
    int ret;

    fail_pipe = 1;
    ret = ossl_rio_notifier_init(&nfy);
    fail_pipe = 0;
    return TEST_false(ret)
        && TEST_int_eq(nfy.rfd, -1) && TEST_int_eq(nfy.wfd, -1)
        && TEST_int_eq(ERR_GET_REASON(ERR_get_error()), EMFILE);
}
#endif /* defined(__wasip3__) */

static int test_rio_notifier_smoke(void)
{
    RIO_NOTIFIER nfy = { -1, -1 };
    int ret = 0;
    char buf;
#if defined(__wasip3__)
    struct stat st;
    int i, rfd, wfd, rflags, wflags;
#endif /* defined(__wasip3__) */

    if (!TEST_int_eq(ossl_rio_notifier_init(&nfy), 1))
        goto err;

#if defined(__wasip3__)
    rflags = fcntl(nfy.rfd, F_GETFL);
    wflags = fcntl(nfy.wfd, F_GETFL);
    if (!TEST_int_eq(fstat(nfy.rfd, &st), 0)
        || !TEST_true(S_ISFIFO(st.st_mode))
        || !TEST_int_ge(rflags, 0) || !TEST_int_ge(wflags, 0)
        || !TEST_true(rflags & O_NONBLOCK)
        || !TEST_true(wflags & O_NONBLOCK))
        goto err;
#endif /* defined(__wasip3__) */

    /* Winsock errors are independent of errno. */
    errno = EIO;
    if (!TEST_int_ne(ossl_rio_notifier_as_fd(&nfy), (int)INVALID_SOCKET)
        || !TEST_int_eq(BIO_socket_ready(nfy.rfd, 1), 0)
        || !TEST_true(ossl_rio_notifier_unsignal(&nfy))
        || !TEST_true(ossl_rio_notifier_signal(&nfy))
        || !TEST_int_eq(BIO_socket_wait(nfy.rfd, 1, time(NULL) + 10), 1)
        || !TEST_true(ossl_rio_notifier_unsignal(&nfy))
        || !TEST_true(ossl_rio_notifier_unsignal(&nfy))
        || !TEST_int_eq(BIO_socket_ready(nfy.rfd, 1), 0))
        goto err;

#if defined(__wasip3__)
    for (i = 0; i <= PIPE_BUF; i++)
        if (!TEST_true(ossl_rio_notifier_signal(&nfy)))
            goto err;
    short_read = 1;
    interrupt_read = 1;
    if (!TEST_int_eq(BIO_socket_ready(nfy.rfd, 1), 1)
        || !TEST_true(ossl_rio_notifier_unsignal(&nfy))
        || !TEST_int_eq(BIO_socket_ready(nfy.rfd, 1), 0))
        goto err;

    rfd = nfy.rfd;
    wfd = nfy.wfd;
#endif /* defined(__wasip3__) */

    if (!TEST_true(BIO_closesocket(nfy.wfd)))
        goto err;
    nfy.wfd = -1;
    /* EOF must ignore a stale error from an earlier failed read. */
    if (!TEST_int_eq(BIO_socket_wait(nfy.rfd, 1, time(NULL) + 10), 1)
        || !TEST_int_lt(readsocket(INVALID_SOCKET, &buf, 1), 0)
        || !TEST_true(ossl_rio_notifier_unsignal(&nfy)))
        goto err;
    ossl_rio_notifier_cleanup(&nfy);
#if defined(__wasip3__)
    if (!TEST_int_eq(fcntl(rfd, F_GETFD), -1)
        || !TEST_int_eq(errno, EBADF)
        || !TEST_int_eq(fcntl(wfd, F_GETFD), -1)
        || !TEST_int_eq(errno, EBADF))
        goto err;
#endif /* defined(__wasip3__) */

    if (!TEST_false(ossl_rio_notifier_unsignal(&nfy)))
        goto err;
    ret = 1;

err:
    ossl_rio_notifier_cleanup(&nfy);
    return ret;
}

int setup_tests(void)
{
#if defined(__wasip3__)
    ADD_TEST(test_rio_notifier_pipe_failure);
#endif /* defined(__wasip3__) */
    ADD_TEST(test_rio_notifier_smoke);
    return 1;
}
