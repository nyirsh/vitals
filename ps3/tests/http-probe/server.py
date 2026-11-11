#!/usr/bin/env python3
"""The HTTP server the libhttp probe talks to (tests/http-probe/source/main.c): a few fixed answers,
each the same every run so Sony's libhttp and vitals' can be compared line by line.

    server.py <port> [certificates folder]

A proxy listens on port + 1 (18081): a plain request it answers itself, its body the request line
and headers it got; CONNECT host:port it tunnels to there (the TLS ports), noting what it got.
With a certificates folder (tools/http_probe.sh makes it), https too, the same paths on four ports
after port: +363 valid for 127.0.0.1 (18443), +364 for another host's name, +365 self-signed,
+366 expired; all but the self-signed one are signed by its ca.pem. Prints "ready" once listening.
Paths:
  /plain        200, Content-Length body "hello, vitals\\n" and two custom headers
  /chunked      200, the same body in three chunks
  /close        200, no length: the body ends when the connection closes
  /empty        204, no body
  /notfound     404 with a short body
  /redirect     302 to /plain
  /echo         200, the request's method, path, headers and body, as text
  /keepalive    200, a counter of requests on this connection
  /setcookie/<name>  200 with the Set-Cookie headers COOKIES has for it
  /basic, /basic/sub, /basic2  Basic authentication, realm "probe realm" (/basic2 "other realm"),
                user "user" and password "pass": 200 "basic ok" or 401
  /basicfail    always 401 (Basic, realm "probe realm")
  /digest, /digestnoqop  Digest (MD5, realm "probe digest", qop auth or none), the same user
  /cache/<kind> 200 with the headers CACHE_KINDS has for it; the body counts the server's requests
                to these paths, so one served from a cache shows, and says which conditional headers
                came (If-Modified-Since by its format only). /cache/s304 and /cache/e304 answer
                304 to If-Modified-Since and If-None-Match
  /gzip         the plain body, gzip-compressed (Content-Encoding gzip) when the request accepts it
  /proxylog     what the proxy received for CONNECT since the last /proxylog
  /cookie/echo, /cookie/sub/echo, /setcookie/echo  as /echo, on paths the cookies' Path attributes match
"""

import base64
import hashlib
import os
import socket
import ssl
import sys
import threading

BODY = b"hello, vitals\n"

# What /setcookie/<name> sends, for the probe's cookie half (tests/http-probe/source/cookie.c)
COOKIES = {
    "session": ["a=1"],
    "path": ["b=2; Path=/cookie"],
    "expires": ["c=3; Expires=Wed, 01 Jan 2099 00:00:00 GMT"],
    "replace": ["c=33; Expires=Wed, 01 Jan 2099 00:00:00 GMT"],
    "maxage": ["d=4; Max-Age=3600"],
    "domain": ["e=5; Domain=other.example"],
    "domainok": ["f=6; Domain=127.0.0.1"],
    "delete": ["a=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"],
    "secure": ["s=7; Secure"],
    "httponly": ["h=8; HttpOnly"],
    "two": ["x=1", "y=2"],
    "spaces": ["  sp = v w ; Path=/"],
    "noequal": ["novalue"],
    "quoted": ['q="a b"'],
    "subpath": ["p=1; Path=/cookie/sub"],
    "attributes": ["t=1; path=/; EXPIRES=Wed, 01 Jan 2099 00:00:00 GMT; version=1; comment=x"],
    "persist": ["k1=v1; Expires=Wed, 01 Jan 2099 00:00:00 GMT; Secure",
                "k2=v2; Expires=Wed, 01 Jan 2099 00:00:00 GMT; HttpOnly",
                "k3=v3; Expires=Wed, 01 Jan 2099 00:00:00 GMT; Domain=127.0.0.1",
                "k4=v4; Expires=Wed, 01 Jan 2099 00:00:00 GMT; Path=/cookie/sub",
                "k5; Expires=Wed, 01 Jan 2099 00:00:00 GMT",
                "k6=; Expires=Thu, 01 Jan 2099 00:00:01 GMT; Path=/",
                "k7=v7; Expires=Sat, 01 Jan 2000 00:00:00 GMT"],
    "prefix": ["pre=1; Path=/cookie/su"],
}


def read_request(connection, pending):
    """(request line, [(name, value)], body, leftover) or None when the connection closes"""
    while b"\r\n\r\n" not in pending:
        data = connection.recv(65536)
        if not data:
            return None
        pending += data
    head, rest = pending.split(b"\r\n\r\n", 1)
    lines = head.decode("latin1").split("\r\n")
    headers = [tuple(part.strip() for part in line.split(":", 1)) for line in lines[1:] if ":" in line]
    length = 0
    chunked = False
    for name, value in headers:
        if name.lower() == "content-length":
            length = int(value)
        if name.lower() == "transfer-encoding" and "chunked" in value.lower():
            chunked = True
    body = b""
    if chunked:
        while True:
            while b"\r\n" not in rest:
                rest += connection.recv(65536)
            size_line, rest = rest.split(b"\r\n", 1)
            size = int(size_line.split(b";")[0], 16)
            while len(rest) < size + 2:
                rest += connection.recv(65536)
            body += rest[:size]
            rest = rest[size + 2:]
            if size == 0:
                break
    else:
        while len(rest) < length:
            rest += connection.recv(65536)
        body, rest = rest[:length], rest[length:]
    return lines[0], headers, body, rest


CACHE_COUNT = [0]
LAST_MODIFIED = ("Last-Modified", "Wed, 01 Jan 2020 00:00:00 GMT")
CACHE_KINDS = {
    "full": [("Cache-Control", "max-age=600"), LAST_MODIFIED, ("ETag", '"c1"')],
    "lm": [LAST_MODIFIED],
    "maxage": [("Cache-Control", "max-age=600")],
    "plain": [],
    "etag": [("ETag", '"e1"')],
    "nocache": [("Cache-Control", "no-cache"), LAST_MODIFIED],
    "nostore": [("Cache-Control", "no-store"), LAST_MODIFIED],
    "private": [("Cache-Control", "private"), LAST_MODIFIED],
    "pragma": [("Pragma", "no-cache"), LAST_MODIFIED],
    "expires": [("Expires", "Wed, 01 Jan 2099 00:00:00 GMT")],
    "s304": [LAST_MODIFIED],
    "e304": [("ETag", '"e304"')],
    "big": [LAST_MODIFIED],
}
PROXY_LOG = []
LOCK = threading.Lock()

USER, PASSWORD, NONCE = "user", "pass", "dcd98b7102dd2f0e8b11d0f600bfb0c093"


def md5(text):
    return hashlib.md5(text.encode("latin1")).hexdigest()


def authenticate(method, path, headers, tries):
    """The answer for the authentication paths: (status, extra headers, body). tries is this
    connection's count of refusals since its last success, and whether the first request of them
    brought an Authorization: the body says both"""
    given = next((v for n, v in headers if n.lower() == "authorization"), None)
    if tries["refused"] == 0:
        tries["first"] = "first with" if given is not None else "first without"
    had = ("with Authorization" if given is not None else "without Authorization") + \
        f" after {tries['refused']} refusals, {tries['first']}"
    if path in ("/basic", "/basic/sub", "/basic2", "/basicfail"):
        realm = "other realm" if path == "/basic2" else "probe realm"
        good = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        if path != "/basicfail" and given == good:
            return "200 OK", [], f"basic ok {had}\n"
        if given is not None and not given.startswith("Basic "):
            had += " (" + given.split(" ")[0] + ")"
        scheme = given.split(" ")[0] if given else "-"
        return "401 Unauthorized", [("WWW-Authenticate", f'Basic realm="{realm}"')], f"basic refused {had} ({scheme})\n"
    qop = path == "/digest"
    challenge = f'Digest realm="probe digest", nonce="{NONCE}", opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=MD5'
    if qop:
        challenge += ', qop="auth"'
    if given is not None and given.startswith("Digest "):
        fields = {}
        for part in given[7:].split(","):
            if "=" in part:
                key, value = part.strip().split("=", 1)
                fields[key.strip()] = value.strip().strip('"')
        ha1 = md5(f"{fields.get('username', '')}:probe digest:{PASSWORD}")
        ha2 = md5(f"{method}:{fields.get('uri', '')}")
        if qop:
            expected = md5(f"{ha1}:{fields.get('nonce', '')}:{fields.get('nc', '')}:{fields.get('cnonce', '')}:auth:{ha2}")
        else:
            expected = md5(f"{ha1}:{fields.get('nonce', '')}:{ha2}")
        shown = " ".join(f"{k}={fields[k]}" for k in ("username", "realm", "uri", "algorithm", "qop", "nc", "opaque")
                         if k in fields)
        shown += " cnonce " + ("given" if "cnonce" in fields else "none")
        if fields.get("username") == USER and fields.get("response") == expected:
            return "200 OK", [], f"digest ok {had}: {shown}\n"
        return "401 Unauthorized", [("WWW-Authenticate", challenge)], f"digest refused {had}: {shown}\n"
    return "401 Unauthorized", [("WWW-Authenticate", challenge)], f"digest refused {had}\n"


def answer(status, headers, body=b"", length=True):
    text = f"HTTP/1.1 {status}\r\n"
    for name, value in headers:
        text += f"{name}: {value}\r\n"
    if length:
        text += f"Content-Length: {len(body)}\r\n"
    return text.encode("latin1") + b"\r\n" + body


def serve(connection):
    pending = b""
    count = 0
    tries = {"refused": 0, "first": ""}
    try:
        while True:
            request = read_request(connection, pending)
            if request is None:
                return
            line, headers, body, pending = request
            count += 1
            method, path = line.split(" ")[0], line.split(" ")[1]
            close = any(n.lower() == "connection" and v.lower() == "close" for n, v in headers)
            if path == "/plain":
                reply = answer("200 OK", [("X-Probe", "one"), ("X-Probe-Two", "two words")],
                               BODY if method != "HEAD" else b"")
            elif path == "/chunked":
                parts = [BODY[:5], BODY[5:10], BODY[10:]]
                chunks = b"".join(b"%x\r\n%s\r\n" % (len(p), p) for p in parts) + b"0\r\n\r\n"
                reply = answer("200 OK", [("Transfer-Encoding", "chunked")], chunks, length=False)
            elif path == "/close":
                connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + BODY)
                return
            elif path == "/empty":
                reply = b"HTTP/1.1 204 No Content\r\n\r\n"
            elif path == "/notfound":
                reply = answer("404 Not Found", [], b"no such page\n")
            elif path == "/redirect":
                reply = answer("302 Found", [("Location", "/plain")], b"")
            elif path in ("/basic", "/basic/sub", "/basic2", "/basicfail", "/digest", "/digestnoqop"):
                status, extra, text = authenticate(method, path, headers, tries)
                tries["refused"] = tries["refused"] + 1 if status.startswith("401") else 0
                reply = answer(status, extra, text.encode() if method != "HEAD" else b"")
            elif path.startswith("/cache/") and path[7:] in CACHE_KINDS:
                kind = path[7:]
                with LOCK:
                    CACHE_COUNT[0] += 1
                    number = CACHE_COUNT[0]
                none_match = next((v for n, v in headers if n.lower() == "if-none-match"), None)
                since = next((v for n, v in headers if n.lower() == "if-modified-since"), None)
                said = ""
                if since is not None:
                    said += " if-modified-since " + ("the Last-Modified" if since == LAST_MODIFIED[1] else
                                                     "a date ending +0000" if since.endswith("+0000") else
                                                     "a date ending GMT" if since.endswith("GMT") else "other")
                if none_match is not None:
                    said += f" if-none-match {none_match}"
                if (kind == "s304" and since is not None) or (kind == "e304" and none_match == '"e304"'):
                    reply = f"HTTP/1.1 304 Not Modified\r\nX-Count: {number}{said}\r\n\r\n".encode()
                else:
                    text = f"{kind} {number}{said}\n" + ("x" * 40000 + "\n" if kind == "big" else "")
                    reply = answer("200 OK", CACHE_KINDS[kind], text.encode() if method != "HEAD" else b"")
            elif path == "/gzip":
                import gzip as gzip_module
                wants = any(n.lower() == "accept-encoding" and "gzip" in v.lower() for n, v in headers)
                if wants:
                    reply = answer("200 OK", [("Content-Encoding", "gzip")], gzip_module.compress(BODY, mtime=0))
                else:
                    reply = answer("200 OK", [], BODY)
            elif path == "/proxylog":
                with LOCK:
                    text = "".join(PROXY_LOG) or "nothing\n"
                    PROXY_LOG.clear()
                reply = answer("200 OK", [], text.encode("latin1"))
            elif path == "/setcookie/echo":
                text = f"{method} {path}\n" + "".join(f"{n}: {v}\n" for n, v in headers) + "\n"
                reply = answer("200 OK", [], text.encode("latin1") + body)
            elif path.startswith("/setcookie/") and path[len("/setcookie/"):] in COOKIES:
                reply = answer("200 OK", [("Set-Cookie", c) for c in COOKIES[path[len("/setcookie/"):]]], b"set\n")
            elif path in ("/echo", "/cookie/echo", "/cookie/sub/echo", "/cookiex/echo"):
                text = f"{method} {path}\n" + "".join(f"{n}: {v}\n" for n, v in headers) + "\n"
                reply = answer("200 OK", [], text.encode("latin1") + body)
            elif path == "/keepalive":
                reply = answer("200 OK", [], f"request {count} on this connection\n".encode())
            else:
                reply = answer("400 Bad Request", [], b"")
            connection.sendall(reply)
            if close:
                return
    finally:
        connection.close()


def proxy(connection):
    """The proxy: plain requests answered here, CONNECT tunnelled"""
    pending = b""
    try:
        while True:
            request = read_request(connection, pending)
            if request is None:
                return
            line, headers, body, pending = request
            method, target = line.split(" ")[0], line.split(" ")[1]
            shown = line + "\n" + "".join(f"{n}: {v}\n" for n, v in headers)
            if method == "CONNECT":
                with LOCK:
                    PROXY_LOG.append(shown + "\n")
                host, port = target.rsplit(":", 1)
                try:
                    upstream = socket.create_connection((host, int(port)))
                except OSError:
                    connection.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    return
                connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if pending:
                    upstream.sendall(pending)

                def pipe(source, sink):
                    try:
                        while True:
                            data = source.recv(65536)
                            if not data:
                                break
                            sink.sendall(data)
                    except OSError:
                        pass
                    finally:
                        try:
                            sink.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass

                threading.Thread(target=pipe, args=(upstream, connection), daemon=True).start()
                pipe(connection, upstream)
                return
            text = ("proxied " + shown + (f"body {body.decode('latin1')}\n" if body else "")).encode("latin1")
            connection.sendall(answer("200 OK", [], text if method != "HEAD" else b""))
            if any(n.lower() in ("connection", "proxy-connection") and v.lower() == "close" for n, v in headers):
                return
    except (OSError, ValueError):
        pass
    finally:
        connection.close()


def accept_proxy(listener):
    while True:
        connection, _ = listener.accept()
        threading.Thread(target=proxy, args=(connection,), daemon=True).start()


def listen(port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(16)
    return listener


def accept(listener, context):
    while True:
        connection, _ = listener.accept()
        threading.Thread(target=serve_tls if context else serve, args=(connection, context) if context else (connection,),
                         daemon=True).start()


def serve_tls(connection, context):
    try:
        connection = context.wrap_socket(connection, server_side=True)
    except (ssl.SSLError, OSError):
        connection.close()
        return
    serve(connection)


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    port = int(sys.argv[1])
    listeners = [(listen(port), None)]
    threading.Thread(target=accept_proxy, args=(listen(port + 1),), daemon=True).start()
    if len(sys.argv) == 3:
        folder = sys.argv[2]
        for offset, name in ((363, "valid"), (364, "wronghost"), (365, "selfsigned"), (366, "expired")):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # Sony's libssl offers TLS 1.0 and SSL-C's old suites; vitals' up to TLS 1.3
            context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
            context.load_cert_chain(os.path.join(folder, name + ".pem"), os.path.join(folder, name + ".key"))
            listeners.append((listen(port + offset), context))
    for listener, context in listeners[1:]:
        threading.Thread(target=accept, args=(listener, context), daemon=True).start()
    print("ready", flush=True)
    accept(*listeners[0])


if __name__ == "__main__":
    main()
