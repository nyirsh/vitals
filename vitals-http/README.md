# vitals-http

Sony's HTTP library (`SceLibHttp`, the `sceHttp*` API) written from scratch, as a user module
exported under libhttp's own library and function NIDs ([vitals_http_api.yml.in](vitals_http_api.yml.in)),
all 116 of them. Its TLS is the libssl module's, [vitals-ssl](../vitals-ssl/), imported as Sony's
libhttp imports Sony's libssl: Mbed TLS 3.6 lives there, not here. It calls Sony's functions and
the VitalsSsl additions, declared in vitals-ssl's `include/vitals_ssl.h`, through the stub
vitals-ssl's build makes, linked weak: a process that loads libhttp without libssl (Adrenaline's
bubble booter, the browser's WebKit process) still loads it and does no https, as with Sony's.
As with Sony's, only an https connection calls into it: the module is shared, so in a process
without libssl its imports point at the libssl another process loaded. `sceHttpsLoadCert` keeps
what it is given, read when a connection starts, and `sceHttpTerm` and plain http never touch it.
A connection's memory is the pool the app gives `sceSslInit`; without it https fails with
`SCE_HTTP_ERROR_SSL`, as Sony's does.

The kernel plugin loads it in place of Sony's libhttp in every process, shared as Sony's is, and
the vitals app installs it as `vs0:/data/external/vitals/libhttp.suprx`. Its whole lifetime, from the
console's storage to a request's last byte, is in [docs/vitals-http.md](../docs/vitals-http.md).

## Building

```bash
make            # build/vitals-http/libhttp.suprx
make DEBUG=1    # build/vitals-http-debug1/: start-up, connections and failures on the console
make test       # host tests (needs VITASDK for <psp2/net/http.h>; skipped without it)
```

`USER_AGENT` (`libhttp/3.74 (PS Vita)` by default) sets what follows each app's own User-Agent
when there is no `ux0:data/vitals/useragent.txt`, e.g. `make USER_AGENT="libhttp/3.74 (PS Vita) MyFork/1.0"`.
`TLS_HEAP_KIB` (64 by default) sets the small heap for what this library keeps of TLS (each
connection's state, the app's `sceHttpsLoadCert` certificates), one memory block per process, apart
from the pool the app gives `sceHttpInit`. The connections themselves are in libssl's pool.
vitals-ssl is built first (`make` at the top does this), since this links its stub.

## Layout

| File | Role |
|---|---|
| [src/core.c](src/core.c) | init and term, the pool, object IDs, settings inherited from template to request |
| [src/request.c](src/request.c) | connections, requests, sending, reading bodies, redirects, Basic and Digest auth, abort |
| [src/message.c](src/message.c) | the request text, status line and header parsing, chunk sizes |
| [src/uri.c](src/uri.c) | `sceHttpUri*` |
| [src/cookie.c](src/cookie.c) | the cookie jar (RFC 6265), export and import |
| [src/inflate.c](src/inflate.c) | gzip bodies, with zlib |
| [src/async.c](src/async.c) | non-blocking requests (a worker thread per call) and the epoll API |
| [src/redirect.c](src/redirect.c) | the host redirect list, `ux0:data/vitals/redirects.txt` |
| [src/useragent.c](src/useragent.c) | the User-Agent suffix, `ux0:data/vitals/useragent.txt` |
| [src/private.c](src/private.c) | the 23 exports nothing names, as Sony's code does them |
| [src/tls.c](src/tls.c) | TLS 1.2 and 1.3 over a connection, through the libssl module, and `sceHttpsLoadCert` |
| [src/platform_vita.c](src/platform_vita.c) | module start, the pool's memory, the lock, SceNet |
| [tests/](tests/) | host tests: `platform_posix.c` in place of the Vita's, against `server.py`, with vitals-ssl built in (its platform in `ssl_platform.c`) |

From tls13-vita it uses Mbed TLS's MD5 only (for Digest authentication, from the build in
`crypto/`), `provider/platform_shims.c`, `provider/user_runtime.c` (the heap, and the C library the
module is linked without), `src/error_map.c`, and `src/host_map.c` with `src/redirect_list.c` for
the redirect list.

## Sony's own connections

The shell's PSN sign-in goes through a CDN that refuses TLS handshakes that don't look like the
console's. Sony's TLS is RSA BSAFE SSL-C 2.8.1, which offers only static-RSA and DHE suites;
Mbed TLS 4 has neither, which is why vitals-ssl is on 3.6. Connections with Sony's private HTTPS
option `0x40` (`sceHttpsEnableOptionPrivate`, which only Sony's code sets) send the console's own
ClientHello, as a capture of a working sign-in shows it, byte for byte but for the random bytes:
TLS 1.2, no session ID, AES256-SHA256, AES128-SHA256, AES256-SHA, AES128-SHA, 3DES-SHA, RC4-SHA,
RC4-MD5 and the renegotiation SCSV, null compression, and only `server_name` and
`signature_algorithms` (RSA PKCS#1 with SHA-256, SHA-512, SHA-384, SHA-1). Mbed TLS has no 3DES or
RC4 suites, so they are only offered, through a small patch
([tls13-vita/crypto/offer-unknown-ciphersuites.patch](../tls13-vita/crypto/offer-unknown-ciphersuites.patch)); every server
seen picks AES128-SHA256, and one that picked one of them would fail the handshake. Every other
connection gets TLS 1.2 to 1.3 with Mbed TLS's default suites. Both are vitals-ssl's profiles
(`vitalsSslCtxSetProfile`).

## Trust

Servers are checked against `vs0:/data/external/cert/CA_LIST.cer`, the bundle the vitals app
installs, plus the CA certificates an app loads with `sceHttpsLoadCert`. As with the provider:

- a self-signed server certificate that is itself trusted counts as trusted
- SHA-1 signatures are allowed
- the HTTPS options decide which problems count
- an app's SSL callback gets the problems and an empty certificate list

A client certificate and key given to `sceHttpsLoadCert` (PEM or DER) are presented to servers
that ask for one; each connection parses its own copy. As with Sony's, what is loaded is only kept
(an empty entry is `SCE_HTTP_ERROR_INVALID_VALUE`) and read when an https connection starts: a CA
certificate that doesn't parse isn't trusted, and a certificate or key that doesn't isn't sent,
with the reason logged with `DEBUG=1`.

## Host redirects

The pairs in `ux0:data/vitals/redirects.txt` (`from-host to-host` per line, as earlier versions
read them) are applied to the host a connection is made with: `sceHttpCreateConnection`'s host
name, and the host in a URL passed to `sceHttpCreateConnectionWithURL`, `sceHttpCreateRequestWithURL`
or `sceHttpCreateRequest2WithURL`. Games can't open `ux0:data`, so the list is read through the
kernel plugin's `vitals_redirects_read`, which means building it needs `../vitals-plugin` built
first. It is read once per `sceHttpInit`, on the first connection or request, and kept in the
pool until `sceHttpTerm`. With `DEBUG=1`, the number of rules and each rewrite are logged.

A request to a host the list redirects to waits at least 30 seconds for the server to answer,
whatever shorter receive timeout the app set: community servers can be slower than the
official ones the game's timeouts were made for.

## User-Agent suffix

A template's User-Agent is the app's own followed by `libhttp/3.74 (PS Vita)`, or by the first
line of `ux0:data/vitals/useragent.txt` that isn't empty or a `#` comment (trimmed, at most 127
printable ASCII characters; anything else and the default is kept). Like the redirect list, it is
read through the kernel plugin (`vitals_useragent_read`), once per `sceHttpInit`.

## Non-blocking requests

With `sceHttpSetNonblock`, `sceHttpSendRequest` and `sceHttpReadData` return
`SCE_HTTP_ERROR_EAGAIN` (`0x80431082`) while the call runs on a worker thread, and the app's next
call gets its result. A request with an epoll (`sceHttpSetEpoll`, inherited from its template or
connection) reports each finished call once to `sceHttpWaitRequest`, as Sony's
`{events, eventDetail, id, userArg}` with its event bits: OUT and IN when a send is done, IN (and
HUP at the body's end) when a read is, SOCK_ERR when either failed. The timeout is in
microseconds; a negative one waits until an event or `sceHttpAbortWaitRequest`.

Deleting a busy request, or a connection or template with one, aborts it and succeeds: the IDs
are gone at once and the memory is freed when the worker is done.

## Unnamed exports

Sony's libhttp exports 23 functions no header or NID database names. Here they are named
`sceHttpPrivate<what it does>` ([src/private.c](src/private.c), each with its NID), and each does
what Sony's code does, worked out from its disassembly. The names are this project's: apps link to
them by NID, so they don't change anything for them.

| Name (`sceHttpPrivate…`) | NID | What it does |
| --- | --- | --- |
| `DumpRequests` | `FE60380A` | prints every request, in Sony's format, as debug output (`DEBUG=1` or `2`; Sony's prints them in every build) |
| `DumpConnections` | `B0E41827` | prints every connection |
| `DumpMemoryPool` | `88116DB8` | prints the pool's current and peak use |
| `DumpDebugInfo` | `0B0D8E7A` | prints all three, under Sony's header |
| `DebugNothing` | `5B6A0ACE` | does nothing, as Sony's |
| `GetConnectionStats` | `54847CFE` | a connection's socket, and whether it is open |
| `GetRequestStats` | `80E6013D` | a request's socket |
| `SetSocketOption` | `F30073EC` | Sony's option 14. Sony's sets socket option `0x40000` on every socket, to 8, or to 0 when bit 0 of this is set; here it is set only once something calls this, so connections otherwise keep the system's value |
| `GetSocketOption` | `30F5D11F` | reads option 14 back; Sony's asks for it with the wrong size, so it always fails, as here |
| `SetOption19` | `43A7CC70` | Sony's option 19, kept; what it does isn't known |
| `SetOption21` | `C498765A` | Sony's option 21, on or off, kept; what it does isn't known |
| `SetMode` | `175685B8` | a mode, 2 or 3, of a template or connection, kept; what it does isn't known |
| `SetProxy` | `53B722F2` | a proxy (options 17 and 18): its host and port, used when its mode is 1 (see [Proxies](#proxies)) |
| `SetSslContextOption` | `855D5254` | a library-wide option Sony's hands to the TLS contexts libssl makes for it; kept, as this TLS isn't libssl's |
| `LoadedCertInit` | `E0825488` | sets up the store of loaded certificates, with the caller's allocator, which isn't needed here |
| `LoadedCertTerm` | `11C9BCE8` | ends it: every CA certificate, the client certificate and key are forgotten |
| `LoadedCertAddCa` | `F8885CFD` | adds a CA certificate, as `sceHttpsLoadCert` does |
| `LoadedCertClearCa` | `0CC59EF6` | forgets the CA certificates |
| `LoadedCertSetClientCert` | `031EBD2A` | sets the client certificate |
| `LoadedCertSetClientKey` | `802E3C30` | sets the client key |
| `LoadedCertClearClient` | `42108FBE` | forgets the client certificate and key |
| `SslContextAddCertCheck` | `A9A39BA1` | installs libhttp's certificate check on a libssl context its caller made (the NetCheck dialog's own TLS), as Sony's: the verify mode on, and a check that does what Sony's libhttp's does with the caller's argument (its `SCE_HTTPS_FLAG_*` flags, host name, result and bits, callback and lock), on the bundle and the app's loaded certificates (`tls.c`). The context is the libssl module's, which is vitals-ssl too |
| `CertCheckNothing` | `A4CF892E` | only succeeds, as Sony's |

With `DEBUG=1`, the settings and certificate calls are logged.

## Proxies

As Sony's, a request goes through an HTTP proxy in two cases:

- its template was made with `autoProxyConf` 1 (`sceHttpCreateTemplate`'s third argument): then
  the proxy set in the console's network settings, read again for every request
  (`sceNetCtlInetGetInfo`), or none when the settings have none;
- otherwise, the proxy `sceHttpPrivateSetProxy` gave the template, connection or request, when it
  turned it on (mode 1).

Plain `http` requests are sent to the proxy with the whole URL in the request line and
`Proxy-Connection` in place of `Connection`. `https` opens a tunnel with `CONNECT host:port`, and
TLS runs through it with the real server, whose certificate is checked as usual: the proxy can't
read or change what passes. A proxy that refuses the tunnel fails the request with
`SCE_HTTP_ERROR_SSL` and `SCE_HTTPS_ERROR_PROXY`. Host redirects apply to the real server, and a
kept socket is reused only by a request that goes the same way, through the proxy or not.

## Not supported

Proxies that ask for credentials (407), and SOCKS proxies.
