# vitals-http in vitals: its whole lifetime

This document follows `vitals-http`, vitals' rewrite of Sony's HTTP library (`SceLibHttp`,
`libhttp.suprx`), from the console's storage to a request's last byte. Its companions are
[browser.md](browser.md), for the browser, and [libssl.md](libssl.md); the component itself, its
build options and its source layout are described in [vitals-http/README.md](../vitals-http/README.md).

In one paragraph: every process that loads Sony's libhttp gets `vitals-http` instead, shared as
Sony's is, the shell included. Apps call the same `sceHttp`/`sceHttps` functions under the same
NIDs, and nothing is injected or hooked. `sceHttpInit` gives the library its pool; templates,
connections and requests live in it. A request's first HTTPS connection sets up Mbed TLS in a heap
of its own; each connection then does its TLS 1.2 or 1.3 handshake on a worker thread, checks the
server against the installed certificate store, and stays open for the next request when the
server allows it. The host redirect list and the User-Agent suffix are read through the kernel
plugin, since games can't open `ux0:data` themselves.

## At a glance

| Module                     | File loaded                                                                             | Loaded when                    | Into                                                           | Shared or private | Until                                         |
| -------------------------- | --------------------------------------------------------------------------------------- | ------------------------------ | -------------------------------------------------------------- | ----------------- | --------------------------------------------- |
| `SceLibHttp` (vitals-http) | `vs0:/data/external/vitals/libhttp.suprx`, in place of `vs0:sys/external/libhttp.suprx` | a process loads Sony's libhttp | every process that loads it, mapped once, as Sony's library is | always **shared** | the last process using it unloads it or exits |

| Memory                            | Taken when                           | Size                                                             | Freed            |
| --------------------------------- | ------------------------------------ | ---------------------------------------------------------------- | ---------------- |
| the pool (`vh_pool`), per process | `sceHttpInit`                        | what the app asks for, plus an eighth and 64 KiB for bookkeeping | `sceHttpTerm`    |
| the TLS heap, per process         | the process's first HTTPS connection | 128 KiB (`TLS_HEAP_KIB`); about 40 KiB per open connection       | the module stops |

## 1. On disk

| File on the console                       | Comes from                                                        | Installed by                                                   |
| ----------------------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------------- |
| `vs0:/data/external/vitals/libhttp.suprx` | built from [vitals-http/](../vitals-http/)                        | `install_http_modules` in [install.c](../vitals-app/install.c) |
| `vs0:/data/external/vitals/libssl.suprx`  | `app0:lssl.suprx`, see [libssl.md](libssl.md)                     | same function                                                  |
| `vs0:/data/external/cert/CA_LIST.cer`     | the certificate store: Sony's, Mozilla's and `custom-certs.pem`'s | `install_certificates`                                         |
| `ux0:data/vitals/redirects.txt`           | the host redirect list, created once with examples                | the installer; never overwritten                               |
| `ux0:data/vitals/useragent.txt`           | the User-Agent suffix, optional                                   | you                                                            |

Sony's own `vs0:sys/external/libhttp.suprx` is never modified. Installing also removes what earlier
versions used in its place: the old HTTP provider and reAuth's module.

## 2. Boot

The kernel plugin's `add_replace_flags` ([vitals-plugin/main.c](../vitals-plugin/main.c)) looks for
vitals' libhttp and libssl. `g_replace_iap` is set only when **both** exist: the two libraries are
always swapped together.

## 3. A process asks for libhttp

Like every load, it reaches `load_for_pid_patched` ([main.c](../vitals-plugin/main.c)):

1. **Path swap:** `vs0:sys/external/libhttp.suprx`, `vs0:/sys/external/libhttp.suprx` and reAuth's
   `ur0:data/reAuth/libhttp.suprx` all become `vs0:/data/external/vitals/libhttp.suprx`. The load is
   logged as `vitals: libhttp load pid=… path=…`.
2. **Flags left alone:** the loader's shared mapping is kept, so one copy of the code serves every
   process, each with its own data, exactly as with Sony's library.
3. **Nothing queued:** nothing is injected after it. `vitals-http` exports libhttp's own library and
   all 116 function NIDs ([vitals_http_api.yml.in](../vitals-http/vitals_http_api.yml.in)), so the
   process links to it as it would to Sony's.

## 4. The module starts

`module_start` ([platform_vita.c](../vitals-http/src/platform_vita.c)) only creates the library's
lock (a recursive lightweight mutex) and the condition non-blocking calls wait on. It allocates
nothing: every process loads this library, and most never use it. The module says it was built
with SDK 3.73, as Sony's does.

## 5. `sceHttpInit`: the pool

`sceHttpInit(poolSize)` ([core.c](../vitals-http/src/core.c)) allocates one memory block for the
pool, a little larger than asked so the allocator's own bookkeeping doesn't eat into it. Every
template, connection, request, header, cookie and response buffer comes from it, and its use is
counted against `poolSize` exactly, as `sceHttpGetMemoryPoolStats` reports it. Objects take only
the space their kind needs: the shell creates about twenty templates at boot from a small pool.

Nothing is read from disk yet. The redirect list and the User-Agent suffix are read on first use
after each `sceHttpInit`, through the kernel plugin's `vitals_redirects_read` and
`vitals_useragent_read` ([vitals-plugin/redirects.c](../vitals-plugin/redirects.c)), and kept in the
pool until `sceHttpTerm`.

## 6. Templates, connections and requests

IDs follow Sony's scheme: the top digit is the kind (`1…` template, `2…` connection, `3…`
request) and the rest counts up per kind; up to 256 objects are live at once. Each object copies
its parent's settings when it is made (timeouts, headers, callbacks, cookie, gzip and HTTPS
options), and its own changes apply to it and to what is made from it afterwards.

- **Template** (`sceHttpCreateTemplate`): its User-Agent becomes the app's own followed by
  `libhttp/3.74 (PS Vita)`, or by `useragent.txt`'s line.
- **Connection** (`sceHttpCreateConnection`, `…WithURL`): the host is where
  [host redirects](../README.md#host-redirects) apply: a host on the list is replaced by its new
  host, logged as `redirect host … -> …` or `redirect <url> -> <url>`.
- **Request** (`sceHttpCreateRequest`, `…WithURL`, `…2`): a URL or a path on its connection; a URL
  is redirected the same way. Its `Host` header is set when it is made.

Request headers go in front of the list, so the last one added is sent first, as with Sony's.
`sceHttpAddRequestHeaderRaw` takes a whole `Name: value` line, and `sceHttpRequestGetAllHeaders`
lists the headers as name and value pairs, both as Sony's do.

## 7. One request

`sceHttpSendRequest` ([request.c](../vitals-http/src/request.c)):

1. **The body**, when the request declared a length: it may come in pieces, one call each. Each
   piece but the last returns 0; the last sends the request. The shell's store sends its session
   requests like that.
2. **The text:** the status line, the cookies the jar has for the URL (after the app's cookie
   callback), the header list, then `Connection`, `Content-Length` for the methods with a body, and
   `Accept-Encoding: gzip` when gzip is on ([message.c](../vitals-http/src/message.c)).
3. **The socket:** the connection's open one, when the last request left it to the same server;
   otherwise a new one, through the resolver and `sceNetConnect`. A reused socket the server closed
   meanwhile is replaced once, silently. A request to a redirected host waits at least 30 seconds for
   an answer, whatever shorter receive timeout the app set. Through a proxy (the network settings',
   for a template made with `autoProxyConf` 1), the socket goes to the proxy, and `https` asks it
   for a tunnel first ([vitals-http/README.md](../vitals-http/README.md#proxies)).
4. **TLS**, for `https`: see the next section.
5. **The exchange:** the text and the body go out, and the response's status line and headers come
   back. Cookies the response sets are offered to the app's callback and kept in the jar.
6. **Redirects and credentials:** a 301, 302, 303, 307 or 308 is followed when the app allows it,
   and a 401 is retried with what the app's auth callback gives (Basic, or Digest with MD5 or
   MD5-sess), up to Sony's limits.
7. **The body:** `sceHttpReadData` reads it as the server sends it: by `Content-Length`, chunked, or
   until the server closes, and decompressed when it is gzip and the app asked for that. A body of
   known length fills the app's buffer up to its end, as some games read it in one call. Once read,
   the socket goes back to the connection for the next request, when keep-alive allows it.

With debug output on, each finished request is one line, `request <id> <method> <url> rc=… status=…`,
and a failed or refused one also shows the headers sent and received. Cookie, Set-Cookie and
Authorization values are logged as their length only.

### Non-blocking requests

With `sceHttpSetNonblock`, the send and each read run on a worker thread
([async.c](../vitals-http/src/async.c)). The call returns `SCE_HTTP_ERROR_EAGAIN` until the work is
done, and the app's next call gets its result. An epoll set with `sceHttpSetEpoll` reports each
finished call once to `sceHttpWaitRequest`.

### Aborting and deleting

`sceHttpAbortRequest` stops a busy request at its next step, and the request returns
`SCE_HTTP_ERROR_ABORTED`. Deleting a busy request, or the connection or template it belongs to,
aborts it and succeeds at once: the IDs are gone, and the memory is freed when the request's own
call has returned.

## 8. TLS

[tls.c](../vitals-http/src/tls.c), through [vitals-ssl](../vitals-ssl/), built into the module, with
Mbed TLS 3.6 ([tls13-vita/crypto](../tls13-vita/crypto/), the same build as the browser provider's).
Each connection is a vitals-ssl connection over vitals-http's own socket functions, so timeouts,
aborts and proxies work as before; vitals-http decides on the certificate from what vitals-ssl
found, the HTTPS options and the app's callback.

**Set up once per process.** The first HTTPS connection starts the TLS heap and the random number
generator, and on the first check builds an **index** of the certificate store: where each root
is in `CA_LIST.cer`, not the roots themselves. The log says `tls ready rc=1`, then `roots=<count>`.

**Two profiles:**

- **modern**, for every connection an app makes: TLS 1.2 or 1.3, Mbed TLS's default suites, with
  the server's name (SNI).
- **console**, for Sony's own connections, the ones with the private HTTPS option `0x40` (the
  shell's PSN sign-in sets it): the console's own ClientHello, byte for byte but for the random
  bytes, since the CDN in front of PSN sign-in refuses handshakes that don't look like a console's.
  [vitals-http/README.md](../vitals-http/README.md#sonys-own-connections) lists what it holds.

**The handshake runs on a thread of its own,** with a known stack: games often call from a
network thread whose stack is too small for TLS 1.3 with elliptic curves. The caller waits for it.

**Trust.** The server's chain is checked against the store, a root read from the file only when
the index says it is needed, plus any CA certificates the app loaded with `sceHttpsLoadCert`. A
self-signed server certificate that is itself in the store counts as trusted, and SHA-1 signatures
are allowed, as PSN still uses them. The HTTPS options decide which problems count (unknown
issuer, expired, not yet valid, wrong name); an app's SSL callback is offered the remaining ones
and may accept them. A refusal is `SCE_HTTP_ERROR_SSL` (`0x80431075`), and `sceHttpsGetSslError`
gives the reason in Sony's codes: `0x80435060` with detail bits for a certificate, `0x80435061`
for a failed handshake. TLS 1.0 and 1.1 are never offered.

A client certificate and key given to `sceHttpsLoadCert` are presented to servers that ask for one.

The log, with debug output on: `handshake ok host=… <version> <cipher> profile=…`, or
`handshake failed host=… tls=… io=… verify=…` and `certificate host=… verify=… detail=… accepted=…`.

## 9. The end

- **`sceHttpTerm`** refuses with `SCE_HTTP_ERROR_BUSY` while a request is inside a blocking call.
  Otherwise it deletes requests, then connections, then templates, and forgets the cookie jar, the
  redirect list, the User-Agent suffix, the epolls and the loaded certificates, then frees the
  pool. A later `sceHttpInit` reads the lists again.
- **The TLS heap** stays until the module stops, since Mbed TLS keeps its global state in it.
- **The module** is unloaded when the last process using it unloads it or exits; its
  `module_stop` terminates what the process left initialized.

## 10. What the logs show

Lines start with `vitals-http:` and appear with debug output on Basic (1) or Full (2), set from the
app's **Debug output** option.

| Line                                                      | Printed by    | Meaning                                                 |
| --------------------------------------------------------- | ------------- | ------------------------------------------------------- |
| `vitals: libhttp load pid=… path=…`                       | kernel plugin | a process loaded libhttp; vitals-http is what it gets   |
| `redirects loaded=<n>`                                    | vitals-http   | the redirect list was read, on the first use after init |
| `redirect host <old> -> <new>`, `redirect <url> -> <url>` | vitals-http   | a host or URL on the list was rewritten                 |
| `user agent suffix from file: …`                          | vitals-http   | `useragent.txt` gave the suffix                         |
| `tls ready roots=<n>`                                     | vitals-http   | the process's first HTTPS connection set up TLS         |
| `handshake ok host=… …`                                   | vitals-http   | one connection's TLS                                    |
| `certificate host=… accepted=0`                           | vitals-http   | a server refused for its certificate                    |
| `request <id> <method> <url> rc=… status=…`               | vitals-http   | one finished request, with the headers when it failed   |
| `private option …`, `private client certificate …`       | vitals-http   | something used one of the exports no header names       |

## 11. Files

| File                                                                                                       | Role                                                       |
| ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| [vitals-plugin/main.c](../vitals-plugin/main.c)                                                            | the path swap                                              |
| [vitals-plugin/redirects.c](../vitals-plugin/redirects.c)                                                  | reading `redirects.txt` and `useragent.txt` for games      |
| [vitals-app/install.c](../vitals-app/install.c)                                                            | putting the files on the console                           |
| [vitals-http/src/platform_vita.c](../vitals-http/src/platform_vita.c)                                      | module start and stop, the pool's memory, sockets, threads |
| [vitals-http/src/core.c](../vitals-http/src/core.c)                                                        | init and term, IDs, settings, headers, HTTPS options       |
| [vitals-http/src/request.c](../vitals-http/src/request.c)                                                  | connections, requests, sending, reading, redirects, auth   |
| [vitals-http/src/message.c](../vitals-http/src/message.c)                                                  | the request text and response parsing                      |
| [vitals-http/src/tls.c](../vitals-http/src/tls.c)                                                          | TLS, trust and `sceHttpsLoadCert`                          |
| [vitals-http/src/async.c](../vitals-http/src/async.c)                                                      | non-blocking calls and the epoll                           |
| [vitals-http/src/redirect.c](../vitals-http/src/redirect.c), [useragent.c](../vitals-http/src/useragent.c) | the two lists from `ux0:data/vitals/`                      |
| [tls13-vita/provider/ca_index.c](../tls13-vita/provider/ca_index.c)                                        | the certificate store's index                              |
| [tls13-vita/src/error_map.c](../tls13-vita/src/error_map.c)                                                | TLS outcomes to Sony's error codes                         |
