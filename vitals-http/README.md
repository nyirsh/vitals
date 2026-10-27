# vitals-http

Sony's HTTP library (`SceLibHttp`, the `sceHttp*` API) written from scratch, as a user module
exported under libhttp's own library and function NIDs ([vitals_http_api.yml.in](vitals_http_api.yml.in)),
all 116 of them. Its TLS is Mbed TLS 3.6 ([crypto/](crypto/)) with tls13-vita's CA bundle index, exact
trust of self-signed certificates, certificate-problem mapping and heap runtime.

The kernel plugin loads it in place of Sony's libhttp in every process, shared as Sony's is, and
the vitals app installs it as `vs0:/data/external/vitals/libhttp.suprx`.

## Building

```bash
make            # build/vitals-http/libhttp.suprx
make DEBUG=1    # build/vitals-http-debug1/: start-up, connections and failures on the console
make test       # host tests (needs VITASDK for <psp2/net/http.h>; skipped without it)
```

`USER_AGENT` (`libhttp/3.74 (PS Vita)` by default) sets what follows each app's own User-Agent
when there is no `ux0:data/vitals/useragent.txt`, e.g. `make USER_AGENT="libhttp/3.74 (PS Vita) MyFork/1.0"`.
`TLS_HEAP_KIB` (128 by default) sets the TLS heap, one memory block per process, apart from the pool
the app gives `sceHttpInit`. An open https connection takes about 40 KiB of it.

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
| [src/private.c](src/private.c) | stubs for the 23 exports nothing names |
| [src/tls.c](src/tls.c) | TLS 1.2 and 1.3 over a connection, `sceHttpsLoadCert` |
| [src/tls_platform.c](src/tls_platform.c) | Mbed TLS's mutexes, entropy and time, on the kernel and the RTC |
| [src/platform_vita.c](src/platform_vita.c) | module start, the pool's memory, the lock, SceNet |
| [tests/](tests/) | host tests: `platform_posix.c` in place of the Vita's, against `server.py` |

From tls13-vita it uses `provider/ca_index.c`, `provider/user_runtime.c` (the heap, and the C
library the module is linked without), `src/error_map.c`, and `src/host_map.c` with
`src/redirect_list.c` for the redirect list.

## Sony's own connections

The shell's PSN sign-in goes through a CDN that refuses TLS handshakes that don't look like the
console's. Sony's TLS is RSA BSAFE SSL-C 2.8.1, which offers only static-RSA and DHE suites;
Mbed TLS 4 has neither, which is why vitals-http is on 3.6. Connections with Sony's private HTTPS
option `0x40` (`sceHttpsEnableOptionPrivate`, which only Sony's code sets) send the console's own
ClientHello, as a capture of a working sign-in shows it, byte for byte but for the random bytes:
TLS 1.2, no session ID, AES256-SHA256, AES128-SHA256, AES256-SHA, AES128-SHA, 3DES-SHA, RC4-SHA,
RC4-MD5 and the renegotiation SCSV, null compression, and only `server_name` and
`signature_algorithms` (RSA PKCS#1 with SHA-256, SHA-512, SHA-384, SHA-1). Mbed TLS has no 3DES or
RC4 suites, so they are only offered, through a small patch
([crypto/offer-unknown-ciphersuites.patch](crypto/offer-unknown-ciphersuites.patch)); every server
seen picks AES128-SHA256, and one that picked one of them would fail the handshake. Every other
connection gets TLS 1.2 to 1.3 with Mbed TLS's default suites.

## Trust

Servers are checked against `vs0:/data/external/cert/CA_LIST.cer`, the bundle the vitals app
installs, plus the CA certificates an app loads with `sceHttpsLoadCert`. As with the provider:

- a self-signed server certificate that is itself trusted counts as trusted
- SHA-1 signatures are allowed
- the HTTPS options decide which problems count
- an app's SSL callback gets the problems and an empty certificate list

A client certificate and key given to `sceHttpsLoadCert` (PEM or DER) are presented to servers
that ask for one; each connection parses its own copy. One that doesn't parse is refused with
`SCE_HTTP_ERROR_INVALID_VALUE`, and with `DEBUG=1` every load is logged with what parsed.

## Host redirects

The pairs in `ux0:data/vitals/redirects.txt` (`from-host to-host` per line, as the HTTP provider
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

Sony's libhttp exports 23 functions no header or NID database names (`sceHttpPrivate<NID>` here).
Their code shows what they are: debug dumps, object statistics, settings, allocator hooks and a
list of loaded certificates. They are stubs that never touch their arguments; the dumps and
settings succeed, the rest return `SCE_HTTP_ERROR_UNKNOWN`. One is known: `A9A39BA1` installs
libhttp's certificate check on a libssl context its caller made (the NetCheck dialog's own TLS);
it succeeds without installing anything, so that context keeps only libssl's own checks, because
failing it ends a game's PSN sign-in. With `DEBUG=1`, each call is logged,
to find which ones Sony's own code relies on.

## Not supported

Proxies.
