#!/usr/bin/env python3
"""Runs vitals-ssl's host tests: makes certificates with openssl (a self-signed server, an unrelated
root, and a CA with a server certificate it signed), starts tests/server.py (TLS on a port, a server
that never answers on the next, the CA's chain on the one after) and runs the test binary against
it."""
import pathlib
import random
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
    # Three ports in a row, below the ephemeral range, where the tests' own sockets go
    for _ in range(50):
        port = random.randrange(20000, 32000 - 3)
        sockets = [socket.socket() for _ in range(3)]
        try:
            for offset, other in enumerate(sockets):
                other.bind(("127.0.0.1", port + offset))
            return port
        except OSError:
            continue
        finally:
            for other in sockets:
                other.close()
    raise RuntimeError("no two free ports in a row")


def main():
    binary = sys.argv[1]
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        # The server's certificate, self-signed, for a name and the address
        openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
                "-subj", "/CN=vitals-ssl.test", "-addext",
                "subjectAltName=DNS:vitals-ssl.test,IP:127.0.0.1",
                "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", "server.key", "-out", "server.pem")
        # A bundle without it, so the server is unknown
        openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=vitals-ssl test root", "-keyout", "root.key", "-out", "root.pem")
        # A CA, and a server certificate it signed, served with it
        openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
                "-subj", "/O=vitals-ssl/CN=vitals-ssl test CA", "-addext",
                "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", "ca.key", "-out", "ca.pem")
        openssl(directory, "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=chain.test",
                "-keyout", "chain.key", "-out", "chain.csr")
        (directory / "chain.ext").write_text(
            "subjectAltName=DNS:chain.test\nbasicConstraints=critical,CA:FALSE\n")
        openssl(directory, "x509", "-req", "-in", "chain.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-sha256", "-days", "2", "-extfile", "chain.ext", "-out", "leaf.pem")
        (directory / "chain.pem").write_text((directory / "leaf.pem").read_text() +
                                             (directory / "ca.pem").read_text())
        # A bundle with the unrelated root and the CA
        (directory / "bundle.pem").write_text((directory / "root.pem").read_text() +
                                              (directory / "ca.pem").read_text())
        for _ in range(5):
            port = free_port()
            server = subprocess.Popen([sys.executable, "-I", str(HERE / "server.py"), str(port),
                                       str(directory / "server.pem"), str(directory / "server.key"),
                                       str(directory / "chain.pem"), str(directory / "chain.key")],
                                      stdout=subprocess.PIPE, text=True)
            if server.stdout.readline().strip() == "ready":
                break
            server.kill()
            server.wait()
        else:
            raise RuntimeError("the test server didn't start")
        try:
            time.sleep(0.1)
            return subprocess.run([binary, str(port), str(directory / "server.pem"),
                                   str(directory / "root.pem"), str(directory / "chain.pem"),
                                   str(directory / "bundle.pem")], timeout=120).returncode
        finally:
            server.kill()
            server.wait()


sys.exit(main())
