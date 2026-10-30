/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/rand.h>

static int entropy_calls;

/* Replace the host entropy source to verify that failure stays fatal. */
int getentropy(void *buf, size_t len)
{
    (void)buf;
    (void)len;
    entropy_calls++;
    errno = EIO;
    return -1;
}

int main(void)
{
    unsigned char byte;
    int ok = RAND_bytes(&byte, 1) == 0 && entropy_calls > 0;

    printf("1..1\n%s 1 - host entropy failure\n", ok ? "ok" : "not ok");
    return !ok;
}
