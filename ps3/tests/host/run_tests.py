#!/usr/bin/env python3
"""Runs vitals' libssl's host tests: makes certificates with openssl (a self-signed server, a CA
with a server certificate it signed for chain.test, and a client certificate the CA signed),
starts ../shared/tests/server.py (TLS on a port, a server that never answers on the next, the CA's chain on the
one after) and runs the test binary against it. Sony's CA files go in sony/: the console's own when
ps3-dumps/cert is next to the vitals repository (or VITALS_PS3_CERTS names them), else two stand-ins
that aren't what Sony's table says; Mozilla's bundle is bundle.pem, two of the certificates made here:

    tests/host/run_tests.py <test binary>

As vitals' vitals-ssl/tests/run_tests.py, for what the PS3's tests use so far."""
import os
import pathlib
import random
import shutil
import socket
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SONY_CERTS = pathlib.Path(os.environ.get("VITALS_PS3_CERTS", HERE.parents[3] / "ps3-dumps" / "cert"))


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
    raise RuntimeError("no free ports in a row")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    binary = sys.argv[1]
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
                "-subj", "/CN=vitals-ssl.test", "-addext",
                "subjectAltName=DNS:vitals-ssl.test,IP:127.0.0.1",
                "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", "server.key", "-out", "server.pem")
        # A CA, a server certificate it signed (served with it), and a client certificate it signed
        openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
                "-subj", "/O=vitals-ssl/CN=vitals-ssl test CA", "-addext",
                "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", "ca.key", "-out", "ca.pem")
        openssl(directory, "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/C=GB/O=vitals-ssl/CN=chain.test",
                "-keyout", "chain.key", "-out", "chain.csr")
        (directory / "chain.ext").write_text(
            "subjectAltName=DNS:other.test,DNS:chain.test\nbasicConstraints=critical,CA:FALSE\n")
        openssl(directory, "x509", "-req", "-in", "chain.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-sha256", "-days", "2", "-extfile", "chain.ext", "-out", "leaf.pem")
        (directory / "chain.pem").write_text((directory / "leaf.pem").read_text() +
                                             (directory / "ca.pem").read_text())
        openssl(directory, "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=vitals-ssl client",
                "-keyout", "client.key", "-out", "client.csr")
        openssl(directory, "x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-sha256", "-days", "2", "-out", "client.pem")
        # The CA store's files: Sony's, and a bundle with a comment, a root with CRLF lines and one without
        sony = directory / "sony"
        sony.mkdir()
        if (SONY_CERTS / "CA_LIST.cer").is_file():
            for certificate in SONY_CERTS.glob("CA*.cer"):
                shutil.copy(certificate, sony / certificate.name)
        else:
            (sony / "CA02.cer").write_bytes(b"not CA02\n")
            (sony / "CA05.cer").write_bytes(b"not CA05\n")
        server_crlf = (directory / "server.pem").read_bytes().replace(b"\n", b"\r\n")
        (directory / "server-crlf.pem").write_bytes(server_crlf)
        (directory / "bundle.pem").write_bytes(b"# Mozilla's roots\r\n\r\n" + server_crlf + b"\n" +
                                               (directory / "ca.pem").read_bytes())
        # cellSsl_597BE64A's: data the CA's key signed, with SHA-256 and SHA-1
        (directory / "signed.txt").write_bytes(b"signed by the vitals-ssl test CA\n")
        for digest in ("sha256", "sha1"):
            openssl(directory, "dgst", f"-{digest}", "-sign", "ca.key", "-out", f"signed.{digest}", "signed.txt")
        # SSLCERT_NAME_hash's, as OpenSSL 0.9.8 computed it
        ca_hash = subprocess.run(["openssl", "x509", "-in", str(directory / "ca.pem"), "-noout",
                                  "-subject_hash_old"], check=True, capture_output=True,
                                 text=True).stdout.strip()
        for _ in range(5):
            port = free_port()
            server = subprocess.Popen([sys.executable, "-I", str(HERE.parents[2] / "shared" / "tests" / "server.py"), str(port),
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
            return subprocess.run([binary, str(port), str(directory), ca_hash], timeout=120).returncode
        finally:
            server.kill()
            server.wait()


sys.exit(main())
