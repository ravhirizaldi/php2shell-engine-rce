#!/usr/bin/env python3
"""TCP-level TLS terminator for the local lab.

Accepts TLS on 127.0.0.1:18444 and forwards the decrypted byte stream to the
plain-HTTP target on 127.0.0.1:18110. Unlike an HTTP reverse proxy this does
not parse, buffer, or rewrite requests or responses, so the exploit's
connection behavior is identical to the plain-HTTP path. It exists to test
the tool's TLS bridge against a raw TLS endpoint.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import threading


def pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client: socket.socket, ctx: ssl.SSLContext,
           target: tuple[str, int], timeout: float) -> None:
    remote: socket.socket | None = None
    tls: socket.socket | None = None
    try:
        tls = ctx.wrap_socket(client, server_side=True)
        remote = socket.create_connection(target, timeout=timeout)
        up = threading.Thread(target=pump, args=(tls, remote), daemon=True)
        up.start()
        pump(remote, tls)
        up.join(timeout=1.0)
    except Exception:
        pass
    finally:
        for sock in (tls, client, remote):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18444)
    ap.add_argument("--target-host", default="127.0.0.1")
    ap.add_argument("--target-port", type=int, default=18110)
    ap.add_argument("--cert", default="docker/tls/cert.pem")
    ap.add_argument("--key", default="docker/tls/key.pem")
    ap.add_argument("--timeout", type=float, default=600.0)
    args = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((args.listen, args.port))
    ls.listen(128)
    print("tls tcp forward: %s:%d -> %s:%d"
          % (args.listen, args.port, args.target_host, args.target_port),
          flush=True)
    while True:
        client, _ = ls.accept()
        threading.Thread(target=handle,
                         args=(client, ctx,
                               (args.target_host, args.target_port),
                               args.timeout),
                         daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(main())
