/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "bio_local.h"

#if defined(__wasi__) && !defined(OPENSSL_NO_SOCK)
#include <string.h>
#if defined(__wasip2__)
#include <wasi/wasip2.h>
#else
#include <wasi/wasip3.h>

/* Async form of the SDK's synchronous wrapper for this WASI operation. */
__attribute__((__import_module__("wasi:sockets/ip-name-lookup@0.3.2"),
    __import_name__("[async-lower]resolve-addresses"))) extern wasip3_subtask_status_t
ossl_wasi_resolve_addresses(const char *name, size_t name_len,
    ip_name_lookup_result_list_ip_address_error_code_t *result);
#endif /* defined(__wasip2__) */

/** State owned by one nonblocking WASI lookup. */
struct ossl_wasi_lookup_st {
    char *host; /**< Stable input until completion or cancellation. */
    BIO_ADDRINFO *addresses; /**< Partial result list owned by this lookup. */
    BIO_ADDRINFO **tail; /**< Append cursor for libc address lists. */
#if defined(__wasip2__)
    ip_name_lookup_own_resolve_address_stream_t stream;
    poll_own_pollable_t pollable;
#else
    wasip3_subtask_t task; /**< Pending resolver operation, or zero. */
    wasip3_waitable_set_t set; /**< Receives events for task. */
    int ready; /**< The SDK result is initialised and must be freed. */
    ip_name_lookup_result_list_ip_address_error_code_t result; /**< Owned when ready is set. */
#endif /* defined(__wasip2__) */
};

void ossl_bio_lookup_wasi_free(OSSL_WASI_LOOKUP **lookup)
{
    OSSL_WASI_LOOKUP *state = *lookup;

    if (state == NULL)
        return;
#if defined(__wasip2__)
    if (state->pollable.__handle != 0)
        poll_pollable_drop_own(state->pollable);
    if (state->stream.__handle != 0)
        ip_name_lookup_resolve_address_stream_drop_own(state->stream);
#else
    if (state->task != 0) {
        wasip3_subtask_status_t status;

        wasip3_waitable_join(state->task, 0);
        status = wasip3_subtask_cancel(state->task);
        state->ready = WASIP3_SUBTASK_STATE(status) == WASIP3_SUBTASK_RETURNED;
        wasip3_subtask_drop(state->task);
    }
    if (state->set != 0)
        wasip3_waitable_set_drop(state->set);
    if (state->ready) {
        /* Some generated bindings omit cleanup of optional error text. */
        if (state->result.is_err && state->result.val.err.tag == IP_NAME_LOOKUP_ERROR_CODE_OTHER)
            wasip3_option_string_free(&state->result.val.err.val.other);
        else
            ip_name_lookup_result_list_ip_address_error_code_free(&state->result);
    }
#endif /* defined(__wasip2__) */
    BIO_ADDRINFO_free(state->addresses);
    OPENSSL_free(state->host);
    OPENSSL_free(state);
    *lookup = NULL;
}

/** Append a matching address using libc-owned list nodes. */
static int add_address(OSSL_WASI_LOOKUP *state,
    const ip_name_lookup_ip_address_t *ip, const char *service,
    const struct addrinfo *hints)
{
    unsigned char raw[16];
    char numeric[INET6_ADDRSTRLEN];
    int family, i;
    BIO_ADDRINFO *addresses;

    if (ip->tag == 0) {
        family = AF_INET;
        raw[0] = ip->val.ipv4.f0;
        raw[1] = ip->val.ipv4.f1;
        raw[2] = ip->val.ipv4.f2;
        raw[3] = ip->val.ipv4.f3;
    } else {
        uint16_t words[] = { ip->val.ipv6.f0, ip->val.ipv6.f1,
            ip->val.ipv6.f2, ip->val.ipv6.f3, ip->val.ipv6.f4,
            ip->val.ipv6.f5, ip->val.ipv6.f6, ip->val.ipv6.f7 };

        family = AF_INET6;
        for (i = 0; i < 8; i++) {
            raw[2 * i] = words[i] >> 8;
            raw[2 * i + 1] = words[i];
        }
    }
    if (hints->ai_family != AF_UNSPEC && hints->ai_family != family)
        return 1;
    if (inet_ntop(family, raw, numeric, sizeof(numeric)) == NULL
        || getaddrinfo(numeric, service, hints, &addresses) != 0)
        return 0;
    *state->tail = addresses;
    for (; *state->tail != NULL; state->tail = &(*state->tail)->ai_next)
        ;
    return 1;
}

int ossl_bio_lookup_wasi(OSSL_WASI_LOOKUP **lookup, const char *host,
    const char *service, int family, int socktype, BIO_ADDRINFO **res)
{
    OSSL_WASI_LOOKUP *state = *lookup;
    struct addrinfo hints = { 0 };
    int error;

    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_flags = AI_NUMERICHOST;
    if (state == NULL) {
        error = getaddrinfo(host, service, &hints, res);
        if (error == 0)
            return 1;
        if (error != EAI_NONAME || host == NULL)
            goto err;
        if ((state = OPENSSL_zalloc(sizeof(*state))) == NULL)
            return 0;
        *lookup = state;
        state->tail = &state->addresses;
        if ((state->host = OPENSSL_strdup(host)) == NULL)
            goto err;
#if defined(__wasip2__)
        {
            network_own_network_t network = instance_network_instance_network();
            wasip2_string_t name = { (uint8_t *)state->host, strlen(state->host) };
            ip_name_lookup_error_code_t code;
            int ok = ip_name_lookup_resolve_addresses(network_borrow_network(network),
                &name, &state->stream, &code);

            network_network_drop_own(network);
            if (!ok)
                goto err;
        }
#else
        {
            wasip3_subtask_status_t status = ossl_wasi_resolve_addresses(
                state->host, strlen(state->host), &state->result);

            state->ready = WASIP3_SUBTASK_STATE(status) == WASIP3_SUBTASK_RETURNED;
            if (!state->ready) {
                state->task = WASIP3_SUBTASK_HANDLE(status);
                state->set = wasip3_waitable_set_new();
                wasip3_waitable_join(state->task, state->set);
            }
        }
#endif /* defined(__wasip2__) */
    }
#if defined(__wasip2__)
    for (;;) {
        ip_name_lookup_option_ip_address_t address;
        ip_name_lookup_error_code_t code;
        ip_name_lookup_borrow_resolve_address_stream_t stream = ip_name_lookup_borrow_resolve_address_stream(state->stream);

        if (!ip_name_lookup_method_resolve_address_stream_resolve_next_address(
                stream, &address, &code)) {
            if (code != NETWORK_ERROR_CODE_WOULD_BLOCK)
                goto err;
            if (state->pollable.__handle == 0)
                state->pollable = ip_name_lookup_method_resolve_address_stream_subscribe(stream);
            (void)poll_method_pollable_ready(poll_borrow_pollable(state->pollable));
            return -1;
        }
        if (!address.is_some)
            break;
        if (!add_address(state, &address.val, service, &hints))
            goto err;
    }
#else
    if (!state->ready) {
        wasip3_event_t event;

        wasip3_waitable_set_poll(state->set, &event);
        if (event.event == WASIP3_EVENT_NONE) {
            wasip3_thread_yield();
            wasip3_waitable_set_poll(state->set, &event);
        }
        if (event.event == WASIP3_EVENT_NONE || event.code != WASIP3_SUBTASK_RETURNED)
            return -1;
        wasip3_waitable_join(state->task, 0);
        wasip3_subtask_drop(state->task);
        state->task = 0;
        state->ready = 1;
    }
    if (state->result.is_err)
        goto err;
    {
        size_t i;

        for (i = 0; i < state->result.val.ok.len; i++)
            if (!add_address(state, &state->result.val.ok.ptr[i], service, &hints))
                goto err;
    }
#endif /* defined(__wasip2__) */
    if (state->addresses == NULL)
        goto err;
    *res = state->addresses;
    state->addresses = NULL;
    ossl_bio_lookup_wasi_free(lookup);
    return 1;
err:
    ossl_bio_lookup_wasi_free(lookup);
    ERR_raise_data(ERR_LIB_BIO, ERR_R_SYS_LIB, "WASI name lookup failed");
    return 0;
}
#endif /* defined(__wasi__) && !defined(OPENSSL_NO_SOCK) */
