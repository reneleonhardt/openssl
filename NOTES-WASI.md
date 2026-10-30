Notes for WASI platforms
=======================

Build static `libcrypto.a` and `libssl.a` for server-side WebAssembly.
Use the same SDK and target to link applications. Native libraries and pointers
cannot cross the Wasm boundary. Other languages need a component wrapper.

* `wasm32-wasip1` supports cryptography and TLS over memory BIOs.
* `wasm32-wasip2` and `wasm32-wasip3` also support TCP through wasi-libc.

The tests use WASI SDK 34 and Wasmtime 50.0.1. Crypto performance and timing
behaviour depend on the compiler and runtime.

Build and test
--------------

Add the SDK's `bin` directory and the runtime directory to `PATH`. From the
source root, run:

```sh
mkdir -p build-wasip2
cd build-wasip2
perl ../Configure wasm32-wasip2
make build_libs test/wasi_test.wasm test/wasi_entropy_test.wasm \
    test/rio_notifier_test.wasm
```

Use a fresh build directory for each target. For Preview 3, select
`wasm32-wasip3`. For Preview 1, select `wasm32-wasip1` and omit the notifier test.
Clear native `CC`, `AR`, `RANLIB`, `CPPFLAGS` and `LDFLAGS`, or supply WASI values.

The targets disable assembly, shared libraries, dynamic providers, threads,
OpenSSL async jobs, the secure heap and console password prompts.
The default, base and enabled legacy providers are built in. Host entropy
comes from `getentropy()`, with no `/dev/urandom` fallback. AES uses upstream's
constant-time C implementation.

Set `OPENSSL_SOURCE` to the absolute source path. From the build directory, run:

```sh
make run_tests TESTS="test_wasi test_rio_notifier" \
    EXE_SHELL="wasmtime run -W timeout=60s -S inherit-network=y --dir $OPENSSL_SOURCE"
```

The tests cover hashing, random bytes, reseeding, entropy failure, certificate
loading, peer verification and TLS 1.2 and TLS 1.3. Socket tests cover nonblocking
connect and accept, deadlines, half-close, EOF, shutdown and write backpressure.
The notifier and deferred certificate callback tests also check readiness.
Preview 1 skips socket tests. The runtime timeout replaces the `alarm()` watchdog.

From the source root, build and test the client demo against native TLS:

```sh
wasm32-wasip3-clang -Ibuild-wasip3/include -Iinclude \
    demos/guide/tls-client-block.c build-wasip3/libssl.a build-wasip3/libcrypto.a \
    -o build-wasip3/tls-client-block.wasm
python3 test/wasi_interop_test.py wasmtime build-wasip3/tls-client-block.wasm
```

For Preview 2, change the target and build directory. This test needs Python
with TLS 1.3 support and a native `openssl` command. It uses loopback and a test CA.
CI pins the SDK, runtime and checkout action, and runs all three target builds.

Runtime access
--------------

Grant access to certificate and configuration directories explicitly.
For DNS in Wasmtime, pass `-S allow-ip-name-lookup=y`.
Use one execution thread per instance and keep its OpenSSL objects inside it.
Separate instances can run in parallel.
WASI async I/O does not enable OpenSSL's native async-job API.

Preview 3 uses a nonblocking pipe for notifier wakeups, without network access.
Preview 2 uses a loopback TCP notifier and needs permission to bind and connect
on loopback. HTTP/2 does not need UNIX `socketpair()`.

Signal and process-clock emulation lets applications and tests compile.
It does not provide native signals, fork or process CPU clocks. Full command-line support is outside
this prototype.

Pending I/O and cancellation
---------------------------

Nonblocking operations can return `EAGAIN` until the guest waits for readiness.
Wait for the direction requested by `SSL_ERROR_WANT_READ` or
`SSL_ERROR_WANT_WRITE`. When driving both peers in one guest, poll both peers.
In SDK 34, nonblocking accept checks readiness without suspending the guest.
A readiness wait lets pending host I/O advance.

Keep the original DNS name for SNI and verification. Set both on the SSL object
with `SSL_set_tlsext_host_name()` and `SSL_set1_dnsname()`. Use resolved IP addresses
only for transport.

`BIO_reset()` cancels pending TCP connections. `BIO_free()` also cancels them
when the BIO owns the socket. `BIO_NOCLOSE` leaves the socket for its owner to
close. The BIO still releases its lookup resources and connection metadata.

Name lookup uses synchronous `getaddrinfo()`. A BIO timeout cannot
interrupt it. Hosts need a command timeout or a bounded resolver.

The I/O tests cover deadlines, cancellation, borrowed descriptors, denied
access and filesystem escapes. They compare descriptor counts and guest memory
over 1024 operations, with limits of 64 host resources and 128 component handles.
These tests need a dynamically linked Wasmtime, a native C compiler and Linux `/proc`
or macOS `lsof`:

```sh
# From the Preview 2 or Preview 3 build directory:
make test/wasi_io_test.wasm
# From the source root:
python3 test/wasi_io_test.py wasmtime \
    build-wasip3/test/wasi_io_test.wasm
```

Certificate stores
------------------

Supply trust roots from the deployment host. The build host can have different
roots. WASI does not expose them automatically. The host updates bundles. Applications
reload certificates already loaded into a context, as on native platforms.

Host OpenSSL reports its defaults through `X509_get_default_cert_file()` and
`X509_get_default_cert_dir()`. Python linked to OpenSSL can print these paths:

```sh
python3 -c 'import ssl; print(ssl.get_default_verify_paths())'
```

Select an existing PEM bundle and resolve symlinks before granting access.
The guest cannot follow symlinks outside its granted directories.

```sh
CA_BUNDLE=$(realpath /host/path/to/ca-bundle.pem)
wasmtime run -S inherit-network=y -S allow-ip-name-lookup=y \
    --dir "$(dirname "$CA_BUNDLE")::/trust" \
    --env "SSL_CERT_FILE=/trust/$(basename "$CA_BUNDLE")" application.wasm
```

Protect the bundle with host permissions or a read-only mount. The CLI's `--dir`
grant permits writes. Embedded hosts can use `FsPerms::ReadOnly` with
`WasiCtxBuilder::preopened_dir()`. Applications must load the trust roots and
enable peer and hostname verification.

Export macOS Keychain and Windows roots with their trust policy intact. Copying
every certificate loses that policy. Supply the server's certificate chain and
key separately. Servers typically trust a specific CA for client authentication.

Limits
------

SDK 34's `getnameinfo()` is unsupported. Numeric BIO address-to-string helpers
need a libc with numeric `getnameinfo()` support. Reverse lookup is unavailable.
UNIX sockets, UDP, DTLS, QUIC and kernel TLS are outside this port.
Dynamic providers and FIPS validation remain deferred.

`CRYPTO_secure_malloc_init()` returns zero. Secure allocations use the ordinary
heap, as on native platforms with an uninitialised secure heap. There are no locked
or guard pages. Other C code in the instance and host dumps can expose secrets.
The Wasm boundary cannot protect against a malicious host.

`OPENSSL_secure_clear_free()` clears the supplied length before freeing.
`OPENSSL_secure_free()` alone does not promise clearing in ordinary-heap mode.
Clear secrets explicitly, keep key lifetimes short, and configure host memory policies.
The native secure heap needs mapping, guard pages and locking. wasi-libc's
emulated `mprotect()` rejects `PROT_NONE`. A configuration flag cannot supply
these protections. A guest arena can clear memory. It cannot lock pages or add guard pages.
