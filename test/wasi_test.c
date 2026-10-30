/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <time.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "internal/cryptlib.h"
#include "internal/sockets.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"

static char *certfile, *keyfile, *cafile;

#if !defined(OPENSSL_NO_SOCK)
static int test_connect_timeout(void)
{
    struct sockaddr_in addr = { 0 };
    socklen_t addrlen = sizeof(addr);
    char port[6];
    int fd = -1, ret = 0;
    BIO *bio = NULL;
    time_t start;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (!TEST_int_ge(fd = BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0), 0)
        || !TEST_int_eq(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), 0)
        || !TEST_int_eq(getsockname(fd, (struct sockaddr *)&addr, &addrlen), 0)
        || !TEST_ptr(bio = BIO_new_connect("127.0.0.1")))
        goto end;
    snprintf(port, sizeof(port), "%u", ntohs(addr.sin_port));
    if (!TEST_true(BIO_set_conn_port(bio, port)))
        goto end;
    start = time(NULL);
    ret = TEST_int_eq(BIO_do_connect_retry(bio, 1, 10), 0)
        && TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()), BIO_R_CONNECT_TIMEOUT)
        && TEST_long_ge(time(NULL) - start, 1);
end:
    ERR_clear_error();
    BIO_free(bio);
    BIO_closesocket(fd);
    return ret;
}

static int test_half_close(void)
{
    int cfd = -1, sfd = -1, ret = 0, n, i;
    BIO *client = NULL, *server = NULL;
    char buf;
    time_t deadline = time(NULL) + 5;

    if (!TEST_true(create_test_sockets(&cfd, &sfd, SOCK_STREAM, NULL))
        || !TEST_ptr(client = BIO_new_socket(cfd, BIO_NOCLOSE))
        || !TEST_ptr(server = BIO_new_socket(sfd, BIO_NOCLOSE))
        || !TEST_int_eq(shutdown(sfd, SHUT_WR), 0))
        goto end;
    for (i = 0; i < 100; i++) {
        n = BIO_read(client, &buf, 1);
        if (n >= 0)
            break;
        if (!TEST_true(BIO_should_read(client))
            || !TEST_int_eq(BIO_socket_wait(cfd, 1, deadline), 1))
            goto end;
    }
    if (!TEST_int_lt(i, 100) || !TEST_int_eq(n, 0)
        || !TEST_false(BIO_should_retry(client))
        || !TEST_int_eq(BIO_write(client, "x", 1), 1))
        goto end;
    for (i = 0; i < 100; i++) {
        n = BIO_read(server, &buf, 1);
        if (n >= 0)
            break;
        if (!TEST_true(BIO_should_read(server))
            || !TEST_int_eq(BIO_socket_wait(sfd, 1, deadline), 1))
            goto end;
    }
    ret = TEST_int_lt(i, 100) && TEST_int_eq(n, 1) && TEST_char_eq(buf, 'x');
end:
    BIO_free(client);
    BIO_free(server);
    BIO_closesocket(cfd);
    BIO_closesocket(sfd);
    return ret;
}

static int test_backpressure(SSL *client, SSL *server)
{
    unsigned char out[16384], in[16384];
    const size_t total = 2 * 1024 * 1024;
    size_t sent = 0, received = 0, n, offset, len, i;
    int blocked = 0, draining = 0, rc, err, progress, sndbuf = 4096;
    time_t deadline = time(NULL) + 15;

    if (!TEST_int_eq(setsockopt(SSL_get_fd(client), SOL_SOCKET, SO_SNDBUF,
                         (const void *)&sndbuf, sizeof(sndbuf)),
            0)
        || !TEST_true(BIO_set_tcp_ndelay(SSL_get_fd(client), 1)))
        return 0;
    for (i = 0; i < sizeof(out); i++)
        out[i] = (unsigned char)i;
    while (received < total && time(NULL) < deadline) {
        progress = 0;
        if (sent < total) {
            offset = sent % sizeof(out);
            len = sizeof(out) - offset;
            if (len > total - sent)
                len = total - sent;
            rc = SSL_write_ex(client, out + offset, len, &n);
            if (rc > 0) {
                sent += n;
                progress = 1;
            } else {
                err = SSL_get_error(client, rc);
                if (!TEST_int_eq(err, SSL_ERROR_WANT_WRITE))
                    return 0;
                blocked = draining = 1;
            }
        }
        if (draining) {
            offset = received % sizeof(out);
            rc = SSL_read_ex(server, in, sizeof(out) - offset, &n);
            if (rc > 0) {
                if (!TEST_mem_eq(in, n, out + offset, n))
                    return 0;
                received += n;
                progress = 1;
            } else if (!TEST_int_eq(SSL_get_error(server, rc), SSL_ERROR_WANT_READ)) {
                return 0;
            }
        }
        if (!progress && draining) {
            struct pollfd fds[2] = {
                { sent < total ? SSL_get_fd(client) : -1, POLLOUT, 0 },
                { SSL_get_fd(server), POLLIN, 0 }
            };

            if (!TEST_int_ge(poll(fds, 2, 1000), 0))
                return 0;
        }
        if (!draining && sent == total)
            break;
    }
    return TEST_true(blocked) && TEST_size_t_eq(sent, total)
        && TEST_size_t_eq(received, total);
}
static long retry_io_once(BIO *bio, int oper, const char *argp, size_t len,
    int argi, long argl, int ret, size_t *processed)
{
    int *attempts = (int *)BIO_get_callback_arg(bio);
    int index = oper == BIO_CB_WRITE ? 0 : 1;

    if ((oper == BIO_CB_WRITE || oper == BIO_CB_READ) && attempts[index]++ == 0) {
        BIO_clear_retry_flags(bio);
        if (index == 0)
            BIO_set_retry_write(bio);
        else
            BIO_set_retry_read(bio);
        return -1;
    }
    return ret;
}

static int shutdown_tls(SSL *ssl)
{
    int rc, err, i;
    time_t deadline = time(NULL) + 5;

    for (i = 0; i < 100; i++) {
        rc = SSL_shutdown(ssl);
        if (rc >= 0)
            return rc;
        err = SSL_get_error(ssl, rc);
        if ((err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
            || !TEST_int_eq(BIO_socket_wait(SSL_get_fd(ssl),
                                err == SSL_ERROR_WANT_READ, deadline),
                1))
            break;
    }
    return -1;
}
#endif /* !defined(OPENSSL_NO_SOCK) */

static int read_tls(SSL *ssl, char *buf, size_t size, size_t *len)
{
    int rc, err, i;
#if !defined(OPENSSL_NO_SOCK)
    time_t deadline = time(NULL) + 5;
#endif /* !defined(OPENSSL_NO_SOCK) */

    for (i = 0; i < 100; i++) {
        rc = SSL_read_ex(ssl, buf, size, len);
        if (rc > 0)
            return SSL_ERROR_NONE;
        err = SSL_get_error(ssl, rc);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
            return err;
#if !defined(OPENSSL_NO_SOCK)
        if (!TEST_int_eq(BIO_socket_wait(SSL_get_fd(ssl),
                             err == SSL_ERROR_WANT_READ, deadline),
                1))
            break;
#endif /* !defined(OPENSSL_NO_SOCK) */
    }
    return -1;
}

static int test_nonblocking_accept(void)
{
#if defined(OPENSSL_NO_SOCK)
    return TEST_skip("Sockets disabled");
#else
    struct sockaddr_in addr = { 0 };
    int fd = -1, peer = -1, ret = 0;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (!TEST_int_ge(fd = BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0), 0)
        || !TEST_int_eq(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), 0)
        || !TEST_int_eq(listen(fd, 1), 0)
        || !TEST_true(BIO_socket_nbio(fd, 1))
        || !TEST_int_ne(fcntl(fd, F_GETFL, 0) & O_NONBLOCK, 0))
        goto end;
    errno = 0;
    peer = accept(fd, NULL, NULL);
    if (!TEST_int_eq(peer, -1)
        || !TEST_true(errno == EAGAIN || errno == EWOULDBLOCK)
        || !TEST_int_eq(BIO_socket_ready(fd, 1), 0)
        || !TEST_true(BIO_socket_nbio(fd, 0))
        || !TEST_int_eq(fcntl(fd, F_GETFL, 0) & O_NONBLOCK, 0)
        || !TEST_false(BIO_socket_nbio(-1, 1)))
        goto end;
    ERR_clear_error();
    ret = 1;
end:
    if (peer != -1)
        BIO_closesocket(peer);
    if (fd != -1)
        BIO_closesocket(fd);
    return ret;
#endif /* defined(OPENSSL_NO_SOCK) */
}

static int test_crypto(void)
{
    static const unsigned char sha256[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    unsigned char md[EVP_MAX_MD_SIZE], random[32];
    size_t mdlen;

    return TEST_int_eq(openssl_get_fork_id(), 0)
        && TEST_false(CRYPTO_secure_malloc_init(4096, 16))
        && TEST_true(EVP_Q_digest(NULL, "SHA256", NULL, "abc", 3, md, &mdlen))
        && TEST_mem_eq(md, mdlen, sha256, sizeof(sha256))
        && TEST_int_eq(RAND_bytes(random, sizeof(random)), 1)
        && TEST_int_eq(RAND_priv_bytes(random, sizeof(random)), 1)
        && TEST_int_eq(EVP_RAND_reseed(RAND_get0_primary(NULL), 1,
                           NULL, 0, NULL, 0),
            1);
}

static int pause_cert_lookup(SSL *ssl, void *arg)
{
    (void)ssl;
    return ++*(int *)arg == 1 ? -1 : 1;
}

/* Require peer progress before retrying a blocked handshake write. */
static long wait_for_peer(BIO *bio, int oper, const char *argp, size_t len,
    int argi, long argl, int ret, size_t *processed)
{
    int *state = (int *)BIO_get_callback_arg(bio);

    if (oper != BIO_CB_READ && oper != BIO_CB_WRITE)
        return ret;
    if (state[0] >= 16) {
        BIO_clear_retry_flags(bio);
        return -1;
    }
    if (oper == BIO_CB_READ)
        state[1] = 1;
    if (oper == BIO_CB_WRITE && !state[1]) {
        state[0]++;
        BIO_set_retry_write(bio);
        return -1;
    }
    return ret;
}

enum {
    TLS_IO_EOF,
    TLS_IO_ALERT_ERROR,
    TLS_IO_ALERT_RETRY,
    TLS_IO_WRITE_ZERO,
    TLS_IO_READ_ERROR,
    TLS_IO_WRITE_ERROR
};

static long fail_io(BIO *bio, int oper, const char *argp, size_t len,
    int argi, long argl, int ret, size_t *processed)
{
    int *fault = (int *)BIO_get_callback_arg(bio);

    if (oper != (fault[0] == TLS_IO_READ_ERROR ? BIO_CB_READ : BIO_CB_WRITE))
        return ret;
    fault[1]++;
    BIO_clear_retry_flags(bio);
    errno = fault[0] == TLS_IO_READ_ERROR ? ECONNRESET : EPIPE;
    if (fault[0] == TLS_IO_ALERT_RETRY) {
        BIO_set_retry_write(bio);
        errno = EAGAIN;
    } else if (fault[0] == TLS_IO_WRITE_ZERO) {
        errno = 0;
        return 0;
    }
    return -1;
}

#if !defined(OPENSSL_NO_SOCK)
static int test_lookup_tls(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *cbio = NULL, *sbio = NULL;
    int ret = 0, i, lfd = -1, sfd = -1, kind = idx / 2;
    int version = idx % 2 == 0 ? TLS1_2_VERSION : TLS1_3_VERSION;
    struct sockaddr_in address = { 0 };
    socklen_t addrlen = sizeof(address);
    char port[6];
    time_t deadline = time(NULL) + 5;

#if defined(OPENSSL_NO_TLS1_2)
    if (version == TLS1_2_VERSION)
        return TEST_skip("TLS 1.2 disabled");
#endif /* defined(OPENSSL_NO_TLS1_2) */
#if defined(OPENSSL_NO_TLS1_3)
    if (version == TLS1_3_VERSION)
        return TEST_skip("TLS 1.3 disabled");
#endif /* defined(OPENSSL_NO_TLS1_3) */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (!create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
            version, version, &sctx, &cctx, certfile, keyfile)
        || (kind != 2 && !TEST_true(SSL_CTX_load_verify_locations(cctx, cafile, NULL)))
        || !TEST_ptr(client = SSL_new(cctx))
        || !TEST_ptr(server = SSL_new(sctx)))
        goto end;
    SSL_set_verify(client, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_set1_dnsname(client, "server.example"))
        || !TEST_true(SSL_set_tlsext_host_name(client, "server.example"))
        || (kind == 1 && !TEST_true(X509_VERIFY_PARAM_set1_host(SSL_get0_param(client), "wrong.example", 0)))
        || !TEST_int_ge(lfd = BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, BIO_SOCK_NONBLOCK), 0)
        || !TEST_int_eq(bind(lfd, (struct sockaddr *)&address, sizeof(address)), 0)
        || !TEST_int_eq(listen(lfd, 1), 0)
        || !TEST_int_eq(getsockname(lfd, (struct sockaddr *)&address, &addrlen), 0)
        || !TEST_ptr(cbio = BIO_new_connect("server.example")))
        goto end;
    snprintf(port, sizeof(port), "%u", ntohs(address.sin_port));
    if (!TEST_true(BIO_set_conn_port(cbio, port))
        || !TEST_int_eq(BIO_do_connect_retry(cbio, 5, 1), 1)
        || !TEST_str_eq(BIO_get_conn_hostname(cbio), "server.example"))
        goto end;
    for (i = 0; i < 100; i++) {
        sfd = accept(lfd, NULL, NULL);
        if (sfd >= 0)
            break;
        if (!TEST_int_eq(errno, EAGAIN)
            || !TEST_int_eq(BIO_socket_wait(lfd, 1, deadline), 1))
            goto end;
    }
    if (!TEST_int_lt(i, 100)
        || !TEST_true(BIO_socket_nbio(sfd, 1))
        || !TEST_ptr(sbio = BIO_new_socket(sfd, BIO_CLOSE)))
        goto end;
    sfd = -1;
    SSL_set_bio(client, cbio, cbio);
    cbio = NULL;
    SSL_set_bio(server, sbio, sbio);
    sbio = NULL;
    if (kind != 0) {
        ret = TEST_false(create_ssl_connection(server, client, SSL_ERROR_SSL))
            && TEST_long_eq(SSL_get_verify_result(client), kind == 1 ? X509_V_ERR_HOSTNAME_MISMATCH : X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    } else {
        ret = TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE))
            && TEST_str_eq(SSL_get0_peername(client), "server.example")
            && TEST_str_eq(SSL_get_servername(server, TLSEXT_NAMETYPE_host_name), "server.example");
    }
end:
    if (lfd >= 0)
        BIO_closesocket(lfd);
    if (sfd >= 0)
        BIO_closesocket(sfd);
    BIO_free(cbio);
    BIO_free(sbio);
    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return ret;
}
#endif /* !defined(OPENSSL_NO_SOCK) */

static int test_tls(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    const int version = idx % 2 == 0 ? TLS1_2_VERSION : TLS1_3_VERSION;
    const int use_sockets = idx == 2 || idx == 3 || (idx >= 8 && idx < 14);
    const int wrong_host = idx == 4 || idx == 5;
    const int untrusted = idx == 6 || idx == 7;
    const int io_case = idx / 2 - 8;
    const char message[] = "WASI TLS";
    char buf[sizeof(message)];
    size_t len;
    int ret = 0, lookups = 0, rc, err, saved_errno;
    int state[2] = { 0, 0 };
    int fault[2] = { io_case, 0 };
#if !defined(OPENSSL_NO_SOCK)
    int cfd = -1, sfd = -1;
    int client_attempts[2] = { 0, 0 }, server_attempts[2] = { 0, 0 };
#endif /* !defined(OPENSSL_NO_SOCK) */

#if defined(OPENSSL_NO_TLS1_2)
    if (version == TLS1_2_VERSION)
        return TEST_skip("TLS 1.2 disabled");
#endif /* defined(OPENSSL_NO_TLS1_2) */
#if defined(OPENSSL_NO_TLS1_3)
    if (version == TLS1_3_VERSION)
        return TEST_skip("TLS 1.3 disabled");
#endif /* defined(OPENSSL_NO_TLS1_3) */
#if defined(OPENSSL_NO_SOCK)
    if (use_sockets)
        return TEST_skip("Sockets disabled");
#endif /* defined(OPENSSL_NO_SOCK) */
    if (!create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
            version, version, &sctx, &cctx, certfile, keyfile))
        goto end;
    if (!untrusted
        && !TEST_true(use_sockets ? SSL_CTX_set_default_verify_paths(cctx)
                                  : SSL_CTX_load_verify_locations(cctx, cafile, NULL)))
        goto end;
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);

#if !defined(OPENSSL_NO_SOCK)
    if (use_sockets) {
        if (!TEST_true(create_test_sockets(&cfd, &sfd, SOCK_STREAM, NULL))
            || !TEST_true(create_ssl_objects2(sctx, cctx, &server, &client,
                sfd, cfd)))
            goto end;
    } else
#endif /* !defined(OPENSSL_NO_SOCK) */
        if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL)))
            goto end;

    if (!TEST_true(SSL_set1_dnsname(client,
            wrong_host ? "wrong.example" : "server.example")))
        goto end;
    if (idx == 8 || idx == 9)
        SSL_set_cert_cb(server, pause_cert_lookup, &lookups);
    if (idx == 14 || idx == 15) {
        BIO_set_callback_arg(SSL_get_wbio(client), (char *)state);
        BIO_set_callback_ex(SSL_get_wbio(client), wait_for_peer);
    }
    if (wrong_host || untrusted) {
        ret = TEST_false(create_ssl_connection(server, client, SSL_ERROR_SSL))
            && TEST_long_eq(SSL_get_verify_result(client),
                wrong_host ? X509_V_ERR_HOSTNAME_MISMATCH
                           : X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
        goto end;
    }
    if (!TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE))
        || ((idx == 8 || idx == 9) && !TEST_int_ge(lookups, 2))
        || ((idx == 14 || idx == 15) && !TEST_int_eq(state[0], 1))
        || !TEST_int_eq(SSL_version(client), version)
        || !TEST_long_eq(SSL_get_verify_result(client), X509_V_OK)
        || !TEST_true(SSL_write_ex(client, message, sizeof(message), &len))
        || !TEST_size_t_eq(len, sizeof(message)))
        goto end;
    if (!TEST_int_eq(read_tls(server, buf, sizeof(buf), &len), SSL_ERROR_NONE)
        || !TEST_mem_eq(buf, len, message, sizeof(message)))
        goto end;
    if (io_case >= 0) {
        BIO *bio = io_case == TLS_IO_READ_ERROR ? SSL_get_rbio(server) : SSL_get_wbio(server);

        if (io_case < TLS_IO_WRITE_ZERO)
            BIO_set_mem_eof_return(SSL_get_rbio(server), 0);
        /* A hard read error must not look like an empty memory BIO. */
        if (io_case == TLS_IO_READ_ERROR
            && !TEST_int_eq(BIO_write(bio, "x", 1), 1))
            goto end;
        if (io_case != TLS_IO_EOF) {
            BIO_set_callback_arg(bio, (char *)fault);
            BIO_set_callback_ex(bio, fail_io);
        }
        rc = io_case == TLS_IO_WRITE_ZERO || io_case == TLS_IO_WRITE_ERROR
            ? SSL_write_ex(server, message, sizeof(message), &len)
            : SSL_read_ex(server, buf, sizeof(buf), &len);
        saved_errno = errno;
        err = SSL_get_error(server, rc);
        if (!TEST_false(rc)
            || (io_case != TLS_IO_EOF && !TEST_int_ge(fault[1], 1)))
            goto end;
        if (io_case >= TLS_IO_WRITE_ZERO) {
            int io_errno = 0;

            if (io_case == TLS_IO_READ_ERROR)
                io_errno = ECONNRESET;
            else if (io_case == TLS_IO_WRITE_ERROR)
                io_errno = EPIPE;
            ret = TEST_int_eq(err, SSL_ERROR_SYSCALL)
                && TEST_int_eq(saved_errno, io_errno)
                && (io_case == TLS_IO_WRITE_ERROR
                        ? TEST_int_eq(ERR_GET_LIB(ERR_peek_error()), ERR_LIB_SYS)
                            && TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), EPIPE)
                        : TEST_ulong_eq(ERR_peek_error(), 0));
            ERR_clear_error();
            goto end;
        }
    }
#if !defined(OPENSSL_NO_SOCK)
    if ((idx == 12 || idx == 13) && !test_backpressure(client, server))
        goto end;
    if (idx == 10 || idx == 11) {
        BIO_closesocket(cfd);
        cfd = -1;
    }
#endif /* !defined(OPENSSL_NO_SOCK) */
    if (idx == 10 || idx == 11 || io_case >= 0) {
        /* Sending the fatal alert may append a system error. */
        if (!TEST_int_eq(io_case >= 0 ? err : read_tls(server, buf, sizeof(buf), &len), SSL_ERROR_SSL)
            || !TEST_int_eq(ERR_GET_LIB(ERR_peek_error()), ERR_LIB_SSL)
            || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()),
                SSL_R_UNEXPECTED_EOF_WHILE_READING)
            || (io_case == TLS_IO_ALERT_ERROR
                && (!TEST_int_eq(ERR_GET_LIB(ERR_peek_last_error()), ERR_LIB_SYS)
                    || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()), EPIPE))))
            goto end;
        ERR_clear_error();
#if !defined(OPENSSL_NO_SOCK)
    } else if (use_sockets) {
        BIO_set_callback_arg(SSL_get_wbio(client), (char *)client_attempts);
        BIO_set_callback_ex(SSL_get_wbio(client), retry_io_once);
        BIO_set_callback_arg(SSL_get_wbio(server), (char *)server_attempts);
        BIO_set_callback_ex(SSL_get_wbio(server), retry_io_once);
        if (!TEST_int_eq(shutdown_tls(client), 0)
            || !TEST_int_eq(read_tls(server, buf, sizeof(buf), &len), SSL_ERROR_ZERO_RETURN)
            || !TEST_int_eq(shutdown_tls(server), 1)
            || !TEST_int_eq(shutdown_tls(client), 1)
            || !TEST_int_ge(client_attempts[0], 2)
            || !TEST_int_ge(client_attempts[1], 2)
            || !TEST_int_ge(server_attempts[0], 2)
            || !TEST_int_ge(server_attempts[1], 2))
            goto end;
#endif /* !defined(OPENSSL_NO_SOCK) */
    } else if (idx < 2) {
        if (!TEST_int_eq(SSL_shutdown(client), 0)
            || !TEST_int_eq(read_tls(server, buf, sizeof(buf), &len), SSL_ERROR_ZERO_RETURN)
            || !TEST_int_eq(SSL_shutdown(server), 1)
            || !TEST_int_eq(SSL_shutdown(client), 1))
            goto end;
    }
    ret = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
#if !defined(OPENSSL_NO_SOCK)
    if (cfd != -1)
        BIO_closesocket(cfd);
    if (sfd != -1)
        BIO_closesocket(sfd);
#endif /* !defined(OPENSSL_NO_SOCK) */
    return ret;
}

int setup_tests(void)
{
    if (!test_skip_common_options()
        || !TEST_ptr(certfile = test_get_argument(0))
        || !TEST_ptr(keyfile = test_get_argument(1))
        || !TEST_ptr(cafile = test_get_argument(2))
        || !TEST_int_eq(setenv("SSL_CERT_FILE", cafile, 1), 0)
        || !TEST_int_eq(setenv("SSL_CERT_DIR", "/openssl-wasi-no-ca-directory", 1), 0))
        return 0;
#if !defined(OPENSSL_NO_SOCK)
    if (getenv("OPENSSL_TEST_WASI_LOOKUP_TLS") != NULL) {
        ADD_ALL_TESTS(test_lookup_tls, 6);
        return 1;
    }
#endif /* !defined(OPENSSL_NO_SOCK) */
    ADD_TEST(test_crypto);
    ADD_TEST(test_nonblocking_accept);
#if !defined(OPENSSL_NO_SOCK)
    ADD_TEST(test_connect_timeout);
    ADD_TEST(test_half_close);
#endif /* !defined(OPENSSL_NO_SOCK) */
    ADD_ALL_TESTS(test_tls, 28);
    return 1;
}
