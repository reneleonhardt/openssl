/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#undef NDEBUG
#include "../crypto/bio/bio_local.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#if defined(__wasip2__)
#include <wasi/wasip2.h>
#else
#include <wasi/wasip3.h>
#endif /* defined(__wasip2__) */

enum { RESOURCE = 0x700,
    SET,
    POLLABLE };
static int active, subscribed, ready, lookup_error, empty, race;
static const char *host_bytes;
static void *owned;
static struct addrinfo *nodes[4];
static int fail_alloc, progress, network_live, closes, connecting, wait_result;
static time_t fake_time;
static int jump_time, resolve_calls, format_failed, freeze_time;
static void *lookup_memory;
static int capture_alloc;

void *__real_CRYPTO_zalloc(size_t size, const char *file, int line);
char *__real_CRYPTO_strdup(const char *text, const char *file, int line);
int __real_getaddrinfo(const char *host, const char *service,
    const struct addrinfo *hints, struct addrinfo **result);
const char *__real_inet_ntop(int af, const void *src, char *dst, socklen_t size);
time_t __real_time(time_t *result);

void *__wrap_CRYPTO_zalloc(size_t size, const char *file, int line);
void *__wrap_CRYPTO_zalloc(size_t size, const char *file, int line)
{
    void *result = fail_alloc == 1 ? NULL : __real_CRYPTO_zalloc(size, file, line);

    if (capture_alloc && result != NULL) {
        lookup_memory = result;
        capture_alloc = 0;
    }
    return result;
}

char *__wrap_CRYPTO_strdup(const char *text, const char *file, int line);
char *__wrap_CRYPTO_strdup(const char *text, const char *file, int line)
{
    return fail_alloc == 2 ? NULL : __real_CRYPTO_strdup(text, file, line);
}

int __wrap_getaddrinfo(const char *host, const char *service,
    const struct addrinfo *hints, struct addrinfo **result);
int __wrap_getaddrinfo(const char *host, const char *service,
    const struct addrinfo *hints, struct addrinfo **result)
{
    struct addrinfo *item;
    size_t i;
    int ret;

    assert(!format_failed);
    if (hints == NULL || (hints->ai_flags & AI_NUMERICHOST) == 0)
        return EAI_FAIL;
    if (fail_alloc == 3 && host != NULL && strchr(host, ':') != NULL)
        return EAI_MEMORY;
    ret = __real_getaddrinfo(host, service, hints, result);
    if (ret == 0)
        for (item = *result; item != NULL; item = item->ai_next) {
            for (i = 0; i < OSSL_NELEM(nodes) && nodes[i] != NULL; i++)
                ;
            assert(i < OSSL_NELEM(nodes));
            nodes[i] = item;
        }
    return ret;
}

const char *__wrap_inet_ntop(int af, const void *src, char *dst, socklen_t size);
const char *__wrap_inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
    if (fail_alloc == 4) {
        format_failed = 1;
        return NULL;
    }
    return __real_inet_ntop(af, src, dst, size);
}

time_t __wrap_time(time_t *result);
time_t __wrap_time(time_t *result)
{
    if (jump_time && fake_time == 102)
        fake_time++;
    if (freeze_time)
        return fake_time;
    return fake_time != 0 ? fake_time++ : __real_time(result);
}

void __wrap_OSSL_sleep(uint64_t milliseconds);
void __wrap_OSSL_sleep(uint64_t milliseconds) { }

int __wrap_BIO_socket(int domain, int type, int protocol, int options);
int __wrap_BIO_socket(int domain, int type, int protocol, int options)
{
    assert(connecting);
    return 42;
}

int __wrap_BIO_connect(int fd, const BIO_ADDR *address, int options);
int __wrap_BIO_connect(int fd, const BIO_ADDR *address, int options)
{
    assert(connecting && fd == 42);
    if (connecting == 2) {
        errno = EINPROGRESS;
        return 0;
    }
    return 1;
}

int __wrap_BIO_socket_wait(int fd, int for_read, time_t deadline);
int __wrap_BIO_socket_wait(int fd, int for_read, time_t deadline)
{
    assert(fd == 42 && !for_read);
    if (deadline == 0)
        return 1;
    if (deadline < fake_time)
        return 0;
    return wait_result;
}

int __wrap_BIO_sock_error(int fd);
int __wrap_BIO_sock_error(int fd)
{
    assert(fd == 42 && wait_result == 1);
    return 0;
}

int __wrap_BIO_closesocket(int fd);
int __wrap_BIO_closesocket(int fd)
{
    assert(fd == 42);
    closes++;
    return 1;
}

void __real_free(void *ptr);
void __wrap_free(void *ptr);
void __wrap_free(void *ptr)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(nodes); i++)
        if (ptr == nodes[i])
            nodes[i] = NULL;
    if (ptr == owned)
        owned = NULL;
    if (ptr == lookup_memory)
        lookup_memory = NULL;
    if (ptr != NULL && ptr == host_bytes) {
        assert(!active);
        host_bytes = NULL;
    }
    __real_free(ptr);
}

static ip_name_lookup_ip_address_t address(int index)
{
    ip_name_lookup_ip_address_t ip = { 0 };

    ip.tag = index;
    if (index == 0) {
        ip.val.ipv4.f0 = 127;
        ip.val.ipv4.f1 = 10;
        ip.val.ipv4.f2 = 20;
        ip.val.ipv4.f3 = 30;
    } else {
        ip.val.ipv6.f0 = 0x1234;
        ip.val.ipv6.f1 = 0x5678;
        ip.val.ipv6.f2 = 0x9abc;
        ip.val.ipv6.f3 = 0xdef0;
        ip.val.ipv6.f4 = 0x1122;
        ip.val.ipv6.f5 = 0x3344;
        ip.val.ipv6.f6 = 0x5566;
        ip.val.ipv6.f7 = 0x7788;
    }
    return ip;
}

#if defined(__wasip2__)
static int step;

network_own_network_t __wrap_instance_network_instance_network(void);
network_own_network_t __wrap_instance_network_instance_network(void)
{
    assert(!network_live);
    network_live = 1;
    return (network_own_network_t) { SET };
}

void __wrap_network_network_drop_own(network_own_network_t network);
void __wrap_network_network_drop_own(network_own_network_t network)
{
    assert(network_live && network.__handle == SET);
    network_live = 0;
}

bool __wrap_ip_name_lookup_resolve_addresses(ip_name_lookup_borrow_network_t network,
    wasip2_string_t *name, ip_name_lookup_own_resolve_address_stream_t *stream,
    ip_name_lookup_error_code_t *error);
bool __wrap_ip_name_lookup_resolve_addresses(ip_name_lookup_borrow_network_t network,
    wasip2_string_t *name, ip_name_lookup_own_resolve_address_stream_t *stream,
    ip_name_lookup_error_code_t *error)
{
    assert(!active && !subscribed);
    assert(name->len == 14 && memcmp(name->ptr, "lookup.invalid", 14) == 0);
    resolve_calls++;
    host_bytes = (const char *)name->ptr;
    if (fail_alloc == 5)
        return false;
    active = 1;
    step = 0;
    stream->__handle = RESOURCE;
    return true;
}

bool __wrap_ip_name_lookup_method_resolve_address_stream_resolve_next_address(
    ip_name_lookup_borrow_resolve_address_stream_t stream,
    ip_name_lookup_option_ip_address_t *result, ip_name_lookup_error_code_t *error);
bool __wrap_ip_name_lookup_method_resolve_address_stream_resolve_next_address(
    ip_name_lookup_borrow_resolve_address_stream_t stream,
    ip_name_lookup_option_ip_address_t *result, ip_name_lookup_error_code_t *error)
{
    assert(active && stream.__handle == RESOURCE);
    assert(strcmp(host_bytes, "lookup.invalid") == 0);
    if (!ready || lookup_error) {
        *error = ready ? NETWORK_ERROR_CODE_TEMPORARY_RESOLVER_FAILURE
                       : NETWORK_ERROR_CODE_WOULD_BLOCK;
        return false;
    }
    result->is_some = !empty && step < 2;
    result->val = address(step++ % 2);
    return true;
}

ip_name_lookup_own_pollable_t __wrap_ip_name_lookup_method_resolve_address_stream_subscribe(
    ip_name_lookup_borrow_resolve_address_stream_t stream);
ip_name_lookup_own_pollable_t __wrap_ip_name_lookup_method_resolve_address_stream_subscribe(
    ip_name_lookup_borrow_resolve_address_stream_t stream)
{
    assert(active && !subscribed && stream.__handle == RESOURCE);
    subscribed = 1;
    return (ip_name_lookup_own_pollable_t) { POLLABLE };
}

bool __wrap_poll_method_pollable_ready(poll_borrow_pollable_t pollable);
bool __wrap_poll_method_pollable_ready(poll_borrow_pollable_t pollable)
{
    assert(active && subscribed && pollable.__handle == POLLABLE);
    progress++;
    return false;
}

void __wrap_poll_pollable_drop_own(poll_own_pollable_t pollable);
void __wrap_poll_pollable_drop_own(poll_own_pollable_t pollable)
{
    assert(active && subscribed && pollable.__handle == POLLABLE);
    subscribed = 0;
}

void __wrap_ip_name_lookup_resolve_address_stream_drop_own(
    ip_name_lookup_own_resolve_address_stream_t stream);
void __wrap_ip_name_lookup_resolve_address_stream_drop_own(
    ip_name_lookup_own_resolve_address_stream_t stream)
{
    assert(active && !subscribed && stream.__handle == RESOURCE);
    active = 0;
}
#else
static ip_name_lookup_result_list_ip_address_error_code_t *output;
static int joined, terminal, event_code = WASIP3_SUBTASK_RETURNED;

static void complete(void)
{
    assert(!owned);
    terminal = 1;
    *output = (ip_name_lookup_result_list_ip_address_error_code_t) { 0 };
    if (lookup_error) {
        output->is_err = true;
        output->val.err.tag = lookup_error > 2 ? IP_NAME_LOOKUP_ERROR_CODE_ACCESS_DENIED
                                               : IP_NAME_LOOKUP_ERROR_CODE_OTHER;
        output->val.err.val.other.is_some = lookup_error != 2;
        if (lookup_error == 1) {
            owned = malloc(4);
            assert(owned);
            memcpy(owned, "oops", 4);
            output->val.err.val.other.val = (wasip3_string_t) { owned, 4 };
        } else {
            /* Unused variant payloads need not contain valid pointers. */
            output->val.err.val.other.val = (wasip3_string_t) { (uint8_t *)1, 4 };
        }
    } else if (!empty) {
        owned = malloc(2 * sizeof(ip_name_lookup_ip_address_t));
        assert(owned);
        output->val.ok = (ip_name_lookup_list_ip_address_t) { owned, 2 };
        output->val.ok.ptr[0] = address(0);
        output->val.ok.ptr[1] = address(1);
    }
}

wasip3_subtask_status_t __wrap_ossl_wasi_resolve_addresses(const char *name,
    size_t size, ip_name_lookup_result_list_ip_address_error_code_t *result);
wasip3_subtask_status_t __wrap_ossl_wasi_resolve_addresses(const char *name,
    size_t size, ip_name_lookup_result_list_ip_address_error_code_t *result)
{
    assert(!active && !subscribed);
    assert(size == 14 && memcmp(name, "lookup.invalid", 14) == 0);
    resolve_calls++;
    host_bytes = name;
    output = result;
    if (ready) {
        complete();
        return WASIP3_SUBTASK_RETURNED;
    }
    active = 1;
    terminal = 0;
    /* Pending output is not owned by the caller until completion. */
    *output = (ip_name_lookup_result_list_ip_address_error_code_t) { 0 };
    output->val.ok = (ip_name_lookup_list_ip_address_t) { (void *)1, 1 };
    return (RESOURCE << 4) | WASIP3_SUBTASK_STARTED;
}

wasip3_waitable_set_t __wrap_wasip3_waitable_set_new(void);
wasip3_waitable_set_t __wrap_wasip3_waitable_set_new(void)
{
    assert(active && !subscribed);
    subscribed = 1;
    return SET;
}

void __wrap_wasip3_waitable_join(uint32_t task, wasip3_waitable_set_t set);
void __wrap_wasip3_waitable_join(uint32_t task, wasip3_waitable_set_t set)
{
    assert(active && subscribed && task == RESOURCE && (set == SET || set == 0));
    joined = set;
}

void __wrap_wasip3_waitable_set_poll(wasip3_waitable_set_t set, wasip3_event_t *event);
void __wrap_wasip3_waitable_set_poll(wasip3_waitable_set_t set, wasip3_event_t *event)
{
    assert(active && subscribed && joined == SET && set == SET);
    assert(strcmp(host_bytes, "lookup.invalid") == 0);
    *event = (wasip3_event_t) { WASIP3_EVENT_NONE, 0, 0 };
    if (ready) {
        if (event_code == WASIP3_SUBTASK_RETURNED)
            complete();
        *event = (wasip3_event_t) { WASIP3_EVENT_SUBTASK, RESOURCE, event_code };
    }
}

void __wrap_wasip3_thread_yield(void);
void __wrap_wasip3_thread_yield(void) { progress++; }

wasip3_subtask_status_t __wrap_wasip3_subtask_cancel(wasip3_subtask_t task);
wasip3_subtask_status_t __wrap_wasip3_subtask_cancel(wasip3_subtask_t task)
{
    assert(active && !joined && task == RESOURCE);
    terminal = 1;
    if (race) {
        complete();
        return WASIP3_SUBTASK_RETURNED;
    }
    return WASIP3_SUBTASK_STARTED_CANCELLED;
}

void __wrap_wasip3_subtask_drop(wasip3_subtask_t task);
void __wrap_wasip3_subtask_drop(wasip3_subtask_t task)
{
    assert(active && !joined && terminal && task == RESOURCE);
    active = 0;
}

void __wrap_wasip3_waitable_set_drop(wasip3_waitable_set_t set);
void __wrap_wasip3_waitable_set_drop(wasip3_waitable_set_t set)
{
    assert(!active && subscribed && set == SET);
    subscribed = 0;
}
#endif /* defined(__wasip2__) */

static void check_destroyed(void *parent, void *ptr, CRYPTO_EX_DATA *data,
    int index, long argl, void *argp)
{
    BIO *bio = parent;

    if (ptr != NULL) {
        assert(BIO_get_data(bio) == NULL && !BIO_get_init(bio));
        assert(BIO_test_flags(bio, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) == 0);
    }
}

static void check_lookup(int family)
{
    OSSL_WASI_LOOKUP *lookup = NULL;
    BIO_ADDRINFO *result = NULL;
    const BIO_ADDRINFO *item;
    int index = family == AF_INET6, count = 0;
    int saved_ready = ready;

    format_failed = 0;
    assert(!lookup_memory);
    capture_alloc = 1;
    if (!ready) {
        int i;

        progress = 0;
        for (i = 0; i < 2; i++)
            assert(ossl_bio_lookup_wasi(&lookup, "lookup.invalid", "443", family,
                       SOCK_STREAM, &result)
                == -1);
        assert(progress > 0);
        assert(lookup && !result);
        ready = 1;
#if defined(__wasip3__)
        event_code = WASIP3_SUBTASK_STARTED;
        assert(ossl_bio_lookup_wasi(&lookup, "lookup.invalid", "443", family,
                   SOCK_STREAM, &result)
            == -1);
        event_code = WASIP3_SUBTASK_RETURNED;
#endif /* defined(__wasip3__) */
    }
    assert(ossl_bio_lookup_wasi(&lookup, "lookup.invalid", "443", family,
               SOCK_STREAM, &result)
        == (!lookup_error && !empty && !fail_alloc));
    if ((lookup_error || empty || fail_alloc) && fail_alloc != 1)
        assert(ERR_GET_REASON(ERR_peek_last_error()) == ERR_R_SYS_LIB);
    if (!lookup_error && !empty && !fail_alloc) {
        for (item = result; item != NULL; item = BIO_ADDRINFO_next(item)) {
            char numeric[INET6_ADDRSTRLEN];
            unsigned char raw[16];
            size_t size = sizeof(raw);
            int af = index ? AF_INET6 : AF_INET;

            assert(BIO_ADDRINFO_family(item) == af);
            assert(BIO_ADDRINFO_socktype(item) == SOCK_STREAM);
            assert(BIO_ADDRINFO_protocol(item) == IPPROTO_TCP);
            assert(BIO_ADDR_rawaddress(BIO_ADDRINFO_address(item), raw, &size));
            assert(inet_ntop(af, raw, numeric, sizeof(numeric)));
            assert(strcmp(numeric, index ? "1234:5678:9abc:def0:1122:3344:5566:7788" : "127.10.20.30") == 0);
            assert(ntohs(BIO_ADDR_rawport(BIO_ADDRINFO_address(item))) == 443);
            count++;
            index++;
        }
        assert(count == (family == AF_UNSPEC ? 2 : 1));
    }
    BIO_ADDRINFO_free(result);
    assert(!lookup && !active && !subscribed && !host_bytes && !network_live);
    assert(!owned);
    assert(!lookup_memory);
    capture_alloc = 0;
    assert(!nodes[0] && !nodes[1] && !nodes[2] && !nodes[3]);
    ossl_bio_lookup_wasi_free(&lookup);
    ERR_clear_error();
    ready = saved_ready;
    format_failed = 0;
}

int main(void)
{
    int kind, i, ex_index;
    BIO *bio;
    BIO_ADDRINFO *result = NULL;
    OSSL_WASI_LOOKUP *lookup = NULL;

    for (i = 0; i < 2; i++) {
        ready = i;
        check_lookup(AF_UNSPEC);
        check_lookup(AF_INET);
        check_lookup(AF_INET6);
        lookup_error = 1;
        check_lookup(AF_INET);
        lookup_error = 2;
        check_lookup(AF_INET);
        lookup_error = 3;
        check_lookup(AF_INET);
        lookup_error = 0;
    }
    empty = 1;
    check_lookup(AF_INET);
    empty = 0;
    for (fail_alloc = 1; fail_alloc <= 4; fail_alloc++)
        check_lookup(AF_UNSPEC);
#if defined(__wasip2__)
    fail_alloc = 5;
    check_lookup(AF_UNSPEC);
#endif /* defined(__wasip2__) */
    fail_alloc = 0;
    assert(ossl_bio_lookup_wasi(&lookup, "127.0.0.1", "443", AF_INET,
               SOCK_STREAM, &result)
        == 1);
    BIO_ADDRINFO_free(result);
    result = NULL;
    assert(!lookup);
    kind = resolve_calls;
    assert(ossl_bio_lookup_wasi(&lookup, NULL, "invalid-service", AF_INET,
               SOCK_STREAM, &result)
        == 0);
    assert(ossl_bio_lookup_wasi(&lookup, "lookup.invalid", "443", -1,
               SOCK_STREAM, &result)
        == 0);
    assert(resolve_calls == kind);
    ERR_clear_error();
    for (kind = 0; kind < 8; kind++) {
        bio = BIO_new_connect("lookup.invalid:443");

        ready = 0;
        race = kind >= 6;
        lookup_error = kind == 7;
        assert(bio && BIO_set_nbio(bio, 1));
        assert(BIO_do_connect(bio) <= 0 && BIO_should_retry(bio));
        assert(BIO_get_fd(bio, NULL) == -1);
        assert(BIO_get_retry_reason(bio) == BIO_RR_CONNECT);
        assert(BIO_set_nbio(bio, 1) && active);
        assert(BIO_set_conn_mode(bio, BIO_SOCK_NONBLOCK) && active);
        if (kind == 0)
            assert(BIO_reset(bio) == 0);
        if (kind == 1)
            assert(BIO_set_conn_hostname(bio, "127.0.0.1"));
        if (kind == 2)
            assert(BIO_set_conn_port(bio, "80"));
        if (kind == 3)
            assert(BIO_set_nbio(bio, 0));
        if (kind == 4)
            assert(BIO_set_conn_ip_family(bio, BIO_FAMILY_IPV6));
        if (kind == 5)
            assert(BIO_set_conn_mode(bio, 0));
        if (kind < 6)
            assert(!active && !subscribed && !owned && !host_bytes
                && !BIO_should_retry(bio));
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free(bio);
        assert(!active && !subscribed && !owned && !host_bytes);
    }
    bio = BIO_new(BIO_s_mem());
    assert(bio);
    ossl_bio_wasi_cancel_lookup(bio);
    BIO_free(bio);
    race = 0;
    lookup_error = 1;
    ready = 0;
    bio = BIO_new_connect("lookup.invalid:443");
    assert(bio && BIO_set_nbio(bio, 1));
    assert(BIO_do_connect(bio) <= 0 && BIO_should_retry(bio));
    ready = 1;
    assert(BIO_do_connect(bio) <= 0 && !BIO_should_retry(bio));
    assert(ERR_GET_REASON(ERR_peek_last_error()) == ERR_R_SYS_LIB);
    BIO_free(bio);
    ERR_clear_error();
    lookup_error = 0;
    fake_time = 100;
    freeze_time = 1;
    ex_index = BIO_get_ex_new_index(0, NULL, NULL, NULL, check_destroyed);
    assert(ex_index >= 0);
    for (i = 0; i < 2; i++) {
        closes = 0;
        ready = 1;
        connecting = 2;
        bio = BIO_new_connect("lookup.invalid:443");
        assert(bio && BIO_set_nbio(bio, 1));
        assert(BIO_set_ex_data(bio, ex_index, bio));
        BIO_set_close(bio, i);
        assert(BIO_do_connect(bio) <= 0 && BIO_should_retry(bio));
        for (wait_result = -1; wait_result <= 0; wait_result++) {
            assert(BIO_do_connect(bio) <= 0);
            assert(BIO_should_retry(bio));
        }
        assert(BIO_do_connect(bio) == 1);
        assert(BIO_set_conn_mode(bio, 0));
        assert(BIO_get_fd(bio, NULL) == 42);
        BIO_free(bio);
        assert(closes == i);
        assert(!nodes[0] && !nodes[1] && !nodes[2] && !nodes[3]);
    }
    fake_time = freeze_time = 0;
    bio = BIO_new_connect("lookup.invalid:443");
    assert(bio && BIO_do_connect(bio) <= 0 && !BIO_should_retry(bio));
    BIO_free(bio);
    for (i = 1; i <= 2; i++) {
        ready = lookup_error = race = 0;
        bio = BIO_new_connect("lookup.invalid:443");
        assert(bio && BIO_set_nbio(bio, 1));
        assert(BIO_do_connect(bio) <= 0 && active);
        connecting = 1;
        ready = i == 1;
        fake_time = 100;
        jump_time = i == 2;
        assert(BIO_do_connect_retry(bio, i, 1) == 0);
        fake_time = 0;
        jump_time = 0;
        assert(ERR_GET_REASON(ERR_peek_last_error()) == BIO_R_CONNECT_TIMEOUT);
        assert(!active && !subscribed && !owned && !host_bytes);
        BIO_free(bio);
        ERR_clear_error();
    }
    for (i = -1; i <= 5; i += 6) {
        ready = 1;
        bio = BIO_new_connect(i < 0 ? "127.0.0.1:443" : "lookup.invalid:443");
        assert(bio);
        fake_time = 100;
        assert(BIO_do_connect_retry(bio, i, 1) == 1);
        fake_time = 0;
        BIO_free(bio);
    }
    return 0;
}
