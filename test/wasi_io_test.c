/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "internal/sockets.h"
#include "testutil.h"

static const char *mode, *port;

static size_t memory_pages(void)
{
#if defined(__wasi__)
    return __builtin_wasm_memory_size(0);
#else
    return 0;
#endif /* defined(__wasi__) */
}

static int fd_count(void)
{
    int fd, count = 0;

    for (fd = 0; fd < 1024; fd++)
        count += fcntl(fd, F_GETFD) >= 0;
    return count;
}

static BIO *connection(void)
{
    BIO *bio = BIO_new_connect("127.0.0.1");

    if (bio != NULL && !BIO_set_conn_port(bio, port)) {
        BIO_free(bio);
        bio = NULL;
    }
    return bio;
}

static int pending(BIO *bio)
{
    return TEST_true(BIO_set_nbio(bio, 1))
        && TEST_int_le(BIO_do_connect(bio), 0)
        && TEST_true(BIO_should_retry(bio))
        && TEST_int_eq(BIO_get_retry_reason(bio), BIO_RR_CONNECT);
}

static int test_io(void)
{
    BIO *bio = NULL;
    BIO_ADDRINFO *addresses = NULL;
    int i, fd, before = 0, ret = 0;
    const int rounds = 1056;
    size_t pages = 0;
    time_t start;
    char byte;

    if (strcmp(mode, "dns-pending") == 0) {
        BIO_lookup("openssl-wasi-pending.invalid", "443", BIO_LOOKUP_CLIENT,
            AF_INET, SOCK_STREAM, &addresses);
        BIO_ADDRINFO_free(addresses);
        TEST_error("Pending DNS unexpectedly returned");
        return 0;
    }
    if (strcmp(mode, "pending") == 0) {
        if (!TEST_ptr(bio = connection()) || !pending(bio))
            goto end;
        start = time(NULL);
        if (!TEST_int_le(BIO_do_connect(bio), 0)
            || !TEST_true(BIO_should_retry(bio))
            || !TEST_int_eq(BIO_do_connect_retry(bio, 1, 10), 0)
            || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()), BIO_R_CONNECT_TIMEOUT)
            || !TEST_long_ge(time(NULL) - start, 1))
            goto end;
        ERR_clear_error();
        ret = 1;
        goto end;
    }

    for (i = 0; i < rounds; i++) {
        if (strcmp(mode, "dns-denied") == 0) {
            if (!TEST_false(BIO_lookup("openssl-wasi-denied.invalid", "443",
                    BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, &addresses)))
                goto end;
        } else if (strcmp(mode, "files") == 0) {
            static const char *paths[] = { "/allowed/probe", "/allowed/alias" };
            size_t j;

            for (j = 0; j < sizeof(paths) / sizeof(*paths); j++) {
                if (!TEST_ptr(bio = BIO_new_file(paths[j], "r"))
                    || !TEST_int_eq(BIO_read(bio, &byte, 1), 1)
                    || !TEST_char_eq(byte, 'x'))
                    goto end;
                BIO_free(bio);
                bio = NULL;
            }
            if (!TEST_ptr_null(bio = BIO_new_file("/allowed/../secret", "r"))
                || !TEST_ptr_null(bio = BIO_new_file("/allowed/escape", "r")))
                goto end;
        } else if (strcmp(mode, "files-denied") == 0) {
            if (!TEST_ptr_null(bio = BIO_new_file(port, "r")))
                goto end;
        } else {
            if (!TEST_ptr(bio = connection()))
                goto end;
            if (strcmp(mode, "cancel") == 0) {
                struct pollfd wait;

                if (!pending(bio))
                    goto end;
                fd = BIO_get_fd(bio, NULL);
                wait.fd = fd;
                wait.events = POLLOUT;
                if (!TEST_int_eq(poll(&wait, 1, 1), 0)
                    || !TEST_int_eq(BIO_reset(bio), 0)
                    || !TEST_int_eq(BIO_get_fd(bio, NULL), -1)
                    || !TEST_false(BIO_should_retry(bio))
                    || !TEST_int_eq(fcntl(fd, F_GETFD), -1)
                    || !TEST_int_eq(errno, EBADF))
                    goto end;
                if (!pending(bio))
                    goto end;
            } else if (strcmp(mode, "denied") == 0) {
                if (!TEST_int_le(BIO_do_connect(bio), 0)
                    || !TEST_false(BIO_should_retry(bio)))
                    goto end;
            } else if (!TEST_int_eq(BIO_do_connect_retry(bio, 5, 1), 1)) {
                goto end;
            }
            fd = BIO_get_fd(bio, NULL);
            if (strcmp(mode, "connections") == 0 || strcmp(mode, "borrowed") == 0) {
                if (!TEST_int_eq(BIO_socket_wait(fd, 1, time(NULL) + 5), 1)
                    || !TEST_int_eq(BIO_read(bio, &byte, 1), 1)
                    || !TEST_char_eq(byte, 'x'))
                    goto end;
            }
            if (strcmp(mode, "borrowed") == 0)
                BIO_set_close(bio, BIO_NOCLOSE);
            BIO_free(bio);
            bio = NULL;
            if (strcmp(mode, "borrowed") == 0) {
                if (!TEST_int_ge(fcntl(fd, F_GETFD), 0)
                    || !TEST_int_eq(send(fd, "y", 1, 0), 1))
                    goto end;
                BIO_closesocket(fd);
            }
            if (!TEST_int_eq(fcntl(fd, F_GETFD), -1))
                goto end;
        }
        ERR_clear_error();
        if (i == 31 || i == rounds - 1) {
            printf("# checkpoint %d\n", i);
            fflush(stdout);
            if (!TEST_int_eq(getchar(), '\n'))
                goto end;
            if (i == 31) {
                before = fd_count();
                pages = memory_pages();
            } else if (!TEST_int_eq(fd_count(), before)
                || !TEST_size_t_le(memory_pages(), pages + 2)) {
                goto end;
            }
        }
    }
    ret = 1;
end:
    BIO_free(bio);
    BIO_ADDRINFO_free(addresses);
    return ret;
}

int setup_tests(void)
{
    if (!test_skip_common_options()
        || !TEST_ptr(mode = test_get_argument(0))
        || !TEST_ptr(port = test_get_argument(1)))
        return 0;
    ADD_TEST(test_io);
    return 1;
}
