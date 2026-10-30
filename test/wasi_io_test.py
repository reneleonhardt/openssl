#!/usr/bin/env python3
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""Test pending I/O, host cancellation and resource limits in WASI."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
MODES = ["pending", "cancel", "denied", "dns-denied", "dns-pending",
         "connections", "borrowed", "files", "files-denied"]


def host_fds(pid):
    if sys.platform == "linux":
        return len(list(Path(f"/proc/{pid}/fd").iterdir()))
    output = subprocess.check_output(["lsof", "-a", "-p", str(pid), "-Ff"], text=True)
    return sum(line[1:].isdigit() for line in output.splitlines() if line.startswith("f"))


def drive(process):
    output, counts = [], []
    for line in process.stdout:
        output.append(line)
        if line.startswith("# checkpoint "):
            time.sleep(0.05)
            try:
                counts.append(host_fds(process.pid))
                if counts[-1] == 0:
                    raise RuntimeError("Host descriptor inspection returned no descriptors")
            except Exception:
                process.kill()
                raise
            process.stdin.write("\n")
            process.stdin.flush()
    if len(counts) != 2 or counts[1] > counts[0]:
        raise RuntimeError(f"Host descriptor counts: {counts}\n" + "".join(output))
    return "".join(output)


def run(args, mode, port, faults=None):
    timeout = "1s" if mode == "dns-pending" else "5s" if mode == "pending" else "30s"
    command = [args.wasmtime, "run", "-W", f"timeout={timeout}",
               "-S", "max-resources=64", "-S", "max-component-handles=128"]
    if mode not in ("denied", "dns-denied", "files", "files-denied"):
        command += ["-S", "inherit-network=y"]
    if mode == "files":
        command += ["--dir", f"{port}::/allowed"]
    if mode == "dns-pending":
        command += ["-S", "allow-ip-name-lookup=y"]
    elif mode == "dns-denied":
        command += ["-S", "allow-ip-name-lookup=n"]
    command += [str(args.guest.resolve()), mode, str(port)]
    if args.wasmtime == "native":
        command = [str(args.guest.resolve()), mode, str(port)]
    env = dict(os.environ)
    if faults:
        key = "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
        env[key] = str(faults)
    if mode in ("pending", "dns-pending"):
        result = subprocess.run(command, env=env, capture_output=True,
                                text=True, timeout=8)
        if mode == "dns-pending":
            if (not result.returncode or "# resolver-pending" not in result.stderr
                    or "timed out" not in result.stderr):
                raise RuntimeError(result.stdout + result.stderr)
        elif (result.returncode or "# connect-pending" not in result.stderr
                or (args.wasmtime == "native" and "# interrupted-poll" not in result.stderr)):
            raise RuntimeError(result.stdout + result.stderr)
    else:
        with subprocess.Popen(command, env=env, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True) as process, ThreadPoolExecutor(max_workers=1) as pool:
            task = pool.submit(drive, process)
            try:
                code = process.wait(timeout=45)
                output = task.result(timeout=5)
                if code:
                    raise RuntimeError(output)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    print(f"PASS: {mode}", flush=True)


def accept_connections(listener, stop):
    while not stop.is_set():
        try:
            peer, _ = listener.accept()
        except socket.timeout:
            continue
        with peer:
            peer.settimeout(5)
            try:
                peer.sendall(b"x")
                while peer.recv(4096):
                    pass
            except ConnectionResetError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wasmtime", help="runtime executable, or native for direct execution")
    parser.add_argument("guest", type=Path)
    parser.add_argument("--mode", nargs="+", choices=MODES)
    args = parser.parse_args()
    native_modes = ["pending", "cancel", "connections", "borrowed"]
    if args.wasmtime == "native" and args.mode and not set(args.mode) <= set(native_modes):
        parser.error("native execution supports pending, cancel, connections and borrowed")
    with tempfile.TemporaryDirectory() as directory:
        faults = Path(directory) / ("faults.dylib" if sys.platform == "darwin" else "faults.so")
        flags = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC", "-ldl"]
        subprocess.run(["cc", str(ROOT / "test/wasi_io_faults.c"), *flags,
                        "-o", str(faults)], check=True)
        modes = args.mode or (native_modes if args.wasmtime == "native" else MODES)
        for mode in modes:
            if mode in ("connections", "borrowed"):
                with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as pool:
                    listener.bind(("127.0.0.1", 0))
                    listener.listen()
                    listener.settimeout(0.1)
                    stop = threading.Event()
                    task = pool.submit(accept_connections, listener, stop)
                    try:
                        run(args, mode, listener.getsockname()[1])
                    finally:
                        stop.set()
                        task.result(timeout=5)
            elif mode in ("files", "files-denied"):
                allowed = Path(directory) / "allowed"
                allowed.mkdir(exist_ok=True)
                (allowed / "probe").write_text("x")
                if not (allowed / "alias").exists():
                    (allowed / "alias").symlink_to("probe")
                secret = Path(directory) / "secret"
                secret.write_text("private fixture")
                if not (allowed / "escape").exists():
                    (allowed / "escape").symlink_to(secret)
                run(args, mode, allowed if mode == "files" else secret)
            else:
                run(args, mode, 10 if mode == "denied" else 9, faults)


if __name__ == "__main__":
    main()
