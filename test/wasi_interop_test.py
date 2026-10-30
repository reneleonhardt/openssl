#!/usr/bin/env python3
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""Run the WASI TLS client demo against a native TLS 1.3 server."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile


def serve(listener, context):
    connection, _ = listener.accept()
    connection.settimeout(10)
    with context.wrap_socket(connection, server_side=True) as stream:
        request = b""
        while b"\r\n\r\n" not in request:
            data = stream.recv(4096)
            if not data or len(request) + len(data) > 16384:
                raise RuntimeError("Incomplete or oversized HTTP request")
            request += data
        if not request.startswith(b"GET / HTTP/1.1\r\n"):
            raise RuntimeError("Unexpected HTTP request")
        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                       b"Connection: close\r\n\r\nhello")
        stream.unwrap().close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wasmtime")
    parser.add_argument("client", type=Path)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    key = Path(__file__).resolve().parent / "certs/serverkey.pem"

    with tempfile.TemporaryDirectory() as directory:
        cert = Path(directory) / "ca.pem"
        config = Path(directory) / "openssl.cnf"
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\n"
                          "prompt=no\n[dn]\nCN=localhost\n[ext]\n"
                          "subjectAltName=DNS:localhost\n"
                          "basicConstraints=critical,CA:TRUE\n")
        subprocess.run([args.openssl, "req", "-new", "-x509", "-days", "1",
                        "-config", str(config), "-key", str(key), "-out", str(cert)],
                       check=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(cert, key)
        with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as pool:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(15)
            task = pool.submit(serve, listener, context)
            result = subprocess.run([
                args.wasmtime, "run", "-W", "timeout=20s", "-S", "inherit-network=y",
                "-S", "allow-ip-name-lookup=y", "--dir", f"{directory}::/trust",
                "--env", "SSL_CERT_FILE=/trust/ca.pem", str(args.client.resolve()),
                "localhost", str(listener.getsockname()[1])],
                capture_output=True, text=True, timeout=25)
            if result.returncode or "hello" not in result.stdout:
                raise RuntimeError(result.stdout + result.stderr)
            task.result(timeout=15)
    print("PASS: WASI client verified a native TLS 1.3 server and exchanged HTTP data")


if __name__ == "__main__":
    main()
