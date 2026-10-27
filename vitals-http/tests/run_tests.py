#!/usr/bin/env python3
"""Runs the host tests: makes the certificates with openssl, starts tests/server.py (HTTP on a
port, HTTPS on the next) and runs the test binary against it."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent


def openssl(directory, *arguments):
    subprocess.run(["openssl", *arguments], cwd=directory, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)


def free_port():
    # Five ports in a row: plain, HTTPS, HTTPS with a client certificate, old-style TLS 1.2, and one
    # that keeps the ClientHello
    for _ in range(50):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        sockets = [socket.socket() for _ in range(4)]
        try:
            for offset, other in enumerate(sockets, 1):
                other.bind(("127.0.0.1", port + offset))
            return port
        except OSError:
            continue
        finally:
            for other in sockets:
                other.close()
    raise RuntimeError("no five free ports in a row")


def main():
    binary = sys.argv[1]
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        # The server's own certificate, self-signed and not a CA
        openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
                "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", "server.key", "-out", "server.pem")
        # The bundle has an unrelated root only, so the server is unknown until the test loads it
        openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=vitals-http test root", "-keyout", "root.key", "-out", "root.pem")
        # A client certificate, PEM, and its key as DER, as an app may give either
        openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=vitals-http client", "-keyout", "client.key", "-out", "client.pem")
        openssl(directory, "pkey", "-in", "client.key", "-outform", "DER", "-out", "client.der")
        # Host redirects: a host that doesn't exist, sent to this machine
        (directory / "redirects.txt").write_text("# test list\nold.vitals.test localhost\n")
        # A User-Agent suffix, after a comment and a blank line, with spaces and CRLF to trim
        (directory / "useragent.txt").write_text("# suffix\n\n  Custom/1.0 (Test) \r\nnot this\n")
        port = free_port()
        server = subprocess.Popen([sys.executable, "-I", str(HERE / "server.py"), str(port),
                                   str(directory / "server.pem"), str(directory / "server.key"),
                                   str(directory / "client.pem"), str(directory / "hello.hex")],
                                  stdout=subprocess.PIPE, text=True)
        try:
            if server.stdout.readline().strip() != "ready":
                raise RuntimeError("the test server didn't start")
            time.sleep(0.1)
            return subprocess.run([binary, str(port), str(directory / "server.pem"),
                                   str(directory / "root.pem"), str(directory / "client.pem"),
                                   str(directory / "client.der"), str(directory / "hello.hex"),
                                   str(directory / "redirects.txt"), str(directory / "useragent.txt")],
                                  timeout=150).returncode
        finally:
            server.kill()
            server.wait()


sys.exit(main())
