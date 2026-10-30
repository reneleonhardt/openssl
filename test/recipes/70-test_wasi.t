#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec::Functions qw/rel2abs/;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_wasi");
plan skip_all => "WASI targets only" unless config('target') =~ /^wasm32-wasip/;
plan skip_all => "TLS disabled" if disabled('tls');
plan tests => disabled('sock') ? 2 : 3;

my @certs = map { rel2abs(srctop_file("test", "certs", $_)) }
            qw(servercert.pem serverkey.pem rootcert.pem);
ok(run(test(["wasi_test", @certs])), "WASI crypto and TLS");
ok(run(test(["wasi_entropy_test"])), "WASI rejects host entropy failure");
ok(run(test(["wasi_bio_test"])), "WASI BIO unit contracts") unless disabled('sock');
