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
#if defined(__wasi__)
#include "../crypto/bio/bio_local.h"
#endif /* defined(__wasi__) */
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

#if defined(__wasi__)
    if (strcmp(mode, "lookup-contracts") == 0) {
        static const struct {
            const char *host, *service, *numeric;
            int family;
        } cases[] = {
            { "::1", "443", "::1", AF_INET6 },
            { "openssl-wasi-ipv6.invalid", "443", "2001:db8::1", AF_INET6 },
            { "openssl-wasi-ipv6.invalid", "443", NULL, AF_INET },
            { "openssl-wasi-resolver-error.invalid", "443", NULL, AF_INET },
            { "server.example", "invalid-service", NULL, AF_INET },
            { NULL, "443", "127.0.0.1", AF_INET },
            { "server.example", "443", "127.0.0.1", AF_INET }
        };
        OSSL_WASI_LOOKUP *lookup = NULL;
        size_t j;

        for (j = 0; j < sizeof(cases) / sizeof(*cases); j++) {
            char numeric[INET6_ADDRSTRLEN];
            unsigned char raw[16];
            size_t rawlen = sizeof(raw);
            time_t deadline = time(NULL) + 5;

            do {
                i = ossl_bio_lookup_wasi(&lookup, cases[j].host, cases[j].service,
                    cases[j].family, SOCK_STREAM, &addresses);
                if (i < 0)
                    OSSL_sleep(1);
            } while (i < 0 && time(NULL) < deadline);
            ossl_bio_lookup_wasi_free(&lookup);
            if (!TEST_int_eq(i, cases[j].numeric != NULL))
                goto end;
            if (cases[j].numeric != NULL) {
                if (!TEST_ptr(addresses)
                    || !TEST_int_eq(BIO_ADDRINFO_family(addresses), cases[j].family))
                    goto end;
                i = TEST_true(BIO_ADDR_rawaddress(BIO_ADDRINFO_address(addresses), raw, &rawlen))
                    && TEST_ptr(inet_ntop(cases[j].family, raw, numeric, sizeof(numeric)))
                    && TEST_str_eq(numeric, cases[j].numeric)
                    && TEST_int_eq(ntohs(BIO_ADDR_rawport(BIO_ADDRINFO_address(addresses))), 443);
                if (!i)
                    goto end;
            }
            BIO_ADDRINFO_free(addresses);
            addresses = NULL;
            ERR_clear_error();
        }
        if (!TEST_ptr(bio = BIO_new_connect("openssl-wasi-deadline.invalid:443"))
            || !pending(bio)
            || !TEST_ptr(((BIO_CONNECT *)BIO_get_data(bio))->lookup)
            || !TEST_true(BIO_set_conn_mode(bio, BIO_SOCK_NONBLOCK))
            || !TEST_ptr(((BIO_CONNECT *)BIO_get_data(bio))->lookup)
            || !TEST_true(BIO_set_conn_mode(bio, 0))
            || !TEST_ptr_null(((BIO_CONNECT *)BIO_get_data(bio))->lookup)
            || !TEST_false(BIO_should_retry(bio))
            || !TEST_int_eq(BIO_get_fd(bio, NULL), -1))
            goto end;
        ret = 1;
        goto end;
    }
    if (strcmp(mode, "lookup-timeout") == 0) {
        struct timespec before, after;

        if (!TEST_ptr(bio = connection())
            || !TEST_true(BIO_set_conn_hostname(bio, "openssl-wasi-deadline.invalid")))
            goto end;
        clock_gettime(CLOCK_MONOTONIC, &before);
        i = BIO_do_connect_retry(bio, 1, 1);
        clock_gettime(CLOCK_MONOTONIC, &after);
        if (!TEST_int_eq(i, 0)
            || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()), BIO_R_CONNECT_TIMEOUT)
            || !TEST_long_lt((after.tv_sec - before.tv_sec) * 1000
                    + (after.tv_nsec - before.tv_nsec) / 1000000,
                2000)
            || !TEST_false(BIO_should_retry(bio))
            || !TEST_int_eq(BIO_get_fd(bio, NULL), -1)
            || !TEST_str_eq(BIO_get_conn_hostname(bio), "openssl-wasi-deadline.invalid")
            || !TEST_true(BIO_set_conn_hostname(bio, "127.0.0.1"))
            || !TEST_int_eq(BIO_do_connect_retry(bio, 5, 1), 1)
            || !TEST_int_eq(BIO_socket_wait(BIO_get_fd(bio, NULL), 1, time(NULL) + 5), 1)
            || !TEST_int_eq(BIO_read(bio, &byte, 1), 1))
            goto end;
        ERR_clear_error();
        ret = 1;
        goto end;
    }
#endif /* defined(__wasi__) */
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
            if (strcmp(mode, "lookup-denied") == 0) {
                if (!TEST_true(BIO_set_conn_hostname(bio, "openssl-wasi-denied.invalid"))
                    || !TEST_true(BIO_set_nbio(bio, 1))
                    || !TEST_int_le(BIO_do_connect(bio), 0)
                    || !TEST_false(BIO_should_retry(bio)))
                    goto end;
            } else if (strcmp(mode, "lookup-cancel") == 0) {
#if defined(__wasi__)
                int had_lookup;
#endif /* defined(__wasi__) */
                if (!TEST_true(BIO_set_conn_hostname(bio, "openssl-wasi-cancel.invalid"))
                    || !pending(bio))
                    goto end;
                OSSL_sleep(1);
                if (!TEST_int_eq(BIO_reset(bio), 0)
                    || !TEST_false(BIO_should_retry(bio))
                    || !TEST_int_eq(BIO_get_fd(bio, NULL), -1)
                    || !pending(bio))
                    goto end;
                OSSL_sleep(10);
#if defined(__wasi__)
                had_lookup = ((BIO_CONNECT *)BIO_get_data(bio))->lookup != NULL;
#endif /* defined(__wasi__) */
                if (i % 5 == 1) {
                    if (!TEST_true(BIO_set_conn_hostname(bio, "127.0.0.1")))
                        goto end;
                } else if (i % 5 == 2) {
                    if (!TEST_true(BIO_set_conn_port(bio, "443")))
                        goto end;
                } else if (i % 5 == 3) {
                    if (!TEST_true(BIO_set_nbio(bio, 0)))
                        goto end;
                } else if (i % 5 == 4) {
                    if (!TEST_true(BIO_set_conn_ip_family(bio, BIO_FAMILY_IPV6)))
                        goto end;
                }
#if defined(__wasi__)
                if (i % 5 != 0 && had_lookup) {
                    if (!TEST_false(BIO_should_retry(bio))
                        || !TEST_ptr_null(((BIO_CONNECT *)BIO_get_data(bio))->lookup))
                        goto end;
                }
#endif /* defined(__wasi__) */
                BIO_set_close(bio, BIO_NOCLOSE);
            } else if (strcmp(mode, "cancel") == 0) {
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
            if (strcmp(mode, "borrowed") == 0
                || (strcmp(mode, "lookup-cancel") == 0 && fd >= 0)) {
                if (!TEST_int_ge(fcntl(fd, F_GETFD), 0)
                    || (strcmp(mode, "borrowed") == 0
                        && !TEST_int_eq(send(fd, "y", 1, 0), 1)))
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
