"""Test server for the host tests: plain HTTP on one port, HTTPS (self-signed) on the next."""
import base64
import hashlib
import socket
import gzip
import http.server
import socketserver
import ssl
import sys
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send_body(self, code, body, headers=()):
        self.send_response(code)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_chunked(self, parts, headers=()):
        self.send_response(200)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for part in parts:
            self.wfile.write(b"%x;ext=1\r\n" % len(part) + part + b"\r\n")
        self.wfile.write(b"0\r\nX-Trailer: yes\r\n\r\n")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path
        if path == "/hello":
            self.send_body(200, b"hello world", [("Content-Type", "text/plain")])
        elif path == "/conn":
            # Which socket the request came on, to see keep-alive reuse
            self.send_body(200, str(self.client_address[1]).encode())
        elif path == "/chunked":
            self.send_chunked([b"first ", b"second ", b"x" * 5000, b" end"])
        elif path == "/gzip":
            body = b"compressed " * 2000
            if "gzip" in (self.headers.get("Accept-Encoding") or ""):
                self.send_body(200, gzip.compress(body), [("Content-Encoding", "gzip")])
            else:
                self.send_body(200, body)
        elif path == "/gzip-chunked":
            data = gzip.compress(b"chunky " * 3000)
            self.send_chunked([data[i:i + 700] for i in range(0, len(data), 700)], [("Content-Encoding", "gzip")])
        elif path == "/redirect":
            self.send_body(302, b"moved", [("Location", "/hello")])
        elif path == "/redirect-chain":
            self.send_body(301, b"", [("Location", "redirect")])
        elif path == "/redirect-loop":
            self.send_body(302, b"", [("Location", "/redirect-loop")])
        elif path == "/cookie/set":
            self.send_body(200, b"set", [("Set-Cookie", "session=abc123; Path=/"),
                                         ("Set-Cookie", "other=xyz; Path=/cookie; Max-Age=3600"),
                                         ("Set-Cookie", "gone=1; Max-Age=0")])
        elif path.startswith("/cookie/echo") or path == "/echo-cookie":
            self.send_body(200, (self.headers.get("Cookie") or "").encode())
        elif path in ("/digest", "/digest-sess"):
            # RFC 2617 with qop=auth, checked for user:pass
            algorithm = "MD5-sess" if path == "/digest-sess" else "MD5"
            header = self.headers.get("Authorization") or ""
            fields = dict(part.strip().split("=", 1) for part in header[7:].split(",") if "=" in part)
            fields = {k: v.strip('"') for k, v in fields.items()}
            def md5(text):
                return hashlib.md5(text.encode()).hexdigest()
            ok = False
            if header.startswith("Digest ") and fields.get("nonce") == "n0nce" and fields.get("opaque") == "0paque":
                ha1 = md5("user:digest realm:pass")
                if algorithm == "MD5-sess":
                    ha1 = md5("%s:%s:%s" % (ha1, fields["nonce"], fields.get("cnonce", "")))
                ha2 = md5("GET:" + fields.get("uri", ""))
                expected = md5(":".join([ha1, fields["nonce"], fields.get("nc", ""), fields.get("cnonce", ""), "auth", ha2]))
                ok = fields.get("response") == expected and fields.get("qop") == "auth" and fields.get("uri") == path
            if ok:
                self.send_body(200, b"digest welcome")
            else:
                self.send_body(401, b"no", [("WWW-Authenticate",
                    'Digest realm="digest realm", nonce="n0nce", algorithm=%s, qop="auth,auth-int", opaque="0paque"' % algorithm)])
        elif path == "/auth":
            expected = "Basic " + base64.b64encode(b"user:pass").decode()
            if self.headers.get("Authorization") == expected:
                self.send_body(200, b"welcome")
            else:
                self.send_body(401, b"no", [("WWW-Authenticate", 'Basic realm="test realm"')])
        elif path == "/close":
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"until close " * 100)
            self.close_connection = True
        elif path == "/split":
            # A Content-Length body in three pieces, apart in time, as TLS records may come
            self.send_response(200)
            self.send_header("Content-Length", "3000")
            self.end_headers()
            for part in (b"a" * 1000, b"b" * 1000, b"c" * 1000):
                self.wfile.write(part)
                self.wfile.flush()
                time.sleep(0.2)
        elif path == "/slow":
            time.sleep(5)
            self.send_body(200, b"late")
        elif path == "/big":
            self.send_body(200, bytes(range(256)) * 4096)
        elif path == "/headers":
            self.send_body(200, str(self.headers).encode())
        elif path == "/continue":
            self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            self.send_body(200, b"after continue")
        elif path == "/cipher":
            # The suite and version the TLS handshake settled on
            cipher = self.connection.cipher() if hasattr(self.connection, "cipher") else None
            self.send_body(200, ("%s %s" % (cipher[0], cipher[1]) if cipher else "plain").encode())
        elif path == "/nocontent":
            self.send_response(204)
            self.end_headers()
        else:
            self.send_body(404, b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        if self.path == "/echo":
            self.send_body(200, b"POST:" + body)
        elif self.path == "/post-redirect":
            self.send_body(303, b"", [("Location", "/hello")])
        else:
            self.send_body(404, b"")

    do_PUT = do_POST


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # Clients the tests abort, or whose certificate checks fail, close mid-request
        pass


def save_client_hellos(port, path):
    # Saves the first TLS record each client sends (its ClientHello), as hex, then hangs up
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(4)
    while True:
        client, _ = listener.accept()
        with client:
            data = b""
            while len(data) < 5 or len(data) < 5 + int.from_bytes(data[3:5], "big"):
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
            with open(path, "w") as out:
                out.write(data.hex())


def main():
    port, cert, key, client_ca = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
    hello_path = sys.argv[5]
    plain = Server(("127.0.0.1", port), Handler)
    secure = Server(("127.0.0.1", port + 1), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    threading.Thread(target=secure.serve_forever, daemon=True).start()
    # The next port wants a client certificate, as PSN sign-in does
    mutual = Server(("127.0.0.1", port + 2), Handler)
    mutual_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    mutual_context.load_cert_chain(cert, key)
    mutual_context.verify_mode = ssl.CERT_REQUIRED
    mutual_context.load_verify_locations(client_ca)
    mutual.socket = mutual_context.wrap_socket(mutual.socket, server_side=True)
    threading.Thread(target=mutual.serve_forever, daemon=True).start()
    # The next one is an old-style TLS 1.2 server, with static-RSA suites only
    legacy = Server(("127.0.0.1", port + 3), Handler)
    legacy_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    legacy_context.load_cert_chain(cert, key)
    legacy_context.maximum_version = ssl.TLSVersion.TLSv1_2
    legacy_context.set_ciphers("AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:@SECLEVEL=0")
    legacy.socket = legacy_context.wrap_socket(legacy.socket, server_side=True)
    threading.Thread(target=legacy.serve_forever, daemon=True).start()
    # And the next only keeps the ClientHello it gets
    threading.Thread(target=save_client_hellos, args=(port + 4, hello_path), daemon=True).start()
    print("ready", flush=True)
    plain.serve_forever()


main()
