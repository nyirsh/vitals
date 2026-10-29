# vitals-ssl

Sony's SSL library (`SceLibSsl`, the `sceSsl` API) being written from scratch, as a user module
exported under libssl's own library and function NIDs ([libssl_api.yml.in](libssl_api.yml.in)),
all 109 of them, with TLS 1.2 and 1.3 from Mbed TLS 3.6 ([tls13-vita/crypto](../tls13-vita/crypto/),
shared with vitals-http and the browser provider).

Written so far: `sceSslInit`, `sceSslTerm`, `sceSslGetMemoryPoolStats` and the 27 connection
functions Sony's libhttp uses (below), plus three that do nothing in Sony's either. Every other
export logs its name (with `DEBUG=1` or `2`) and fails with `SCE_SSL_ERROR_INTERNAL`
(`0x80435026`), or returns `NULL` where it returns a pointer. Nothing installs it; the app still
installs the copy of Sony's libssl it bundles ([docs/libssl.md](../docs/libssl.md)).

## Building

```bash
make            # build/vitals-ssl/libssl.suprx
make DEBUG=1    # build/vitals-ssl-debug1/: connections, failures and every call to an export that isn't written yet
make DEBUG=2    # also Mbed TLS's own messages
make test       # host tests (needs VITASDK for <psp2/libssl.h>; skipped without it)
```

The host tests build the library for this machine ([tests/platform_posix.c](tests/platform_posix.c)
in place of the Vita's) and call it as Sony's libhttp does, against a local TLS server
([tests/server.py](tests/server.py)): connecting, reading and writing, the server's close_notify or a
dropped socket, a receive timeout, the certificate and host name checks, and the error codes.

## Exports

The NIDs are those of the libssl the app bundles ([vitals-app/assets/lssl.suprx](../vitals-app/assets/lssl.suprx)),
read from its export table, and so is the module NID (`0xB1620F91`; the NID database's 3.60
entry gives `0x9CD6CA85`). Each function's comment gives its NID and the address of Sony's
function in that copy, whose code is mapped at `0x81000000`, as the starting point for working out
what it does.

| Library | NID | Functions | Named |
| --- | --- | --- | --- |
| `SceSsl` | `0xCAF5F2E9` | 11 | all, as `<psp2/libssl.h>` declares them ([src/core.c](src/core.c), [src/ssl.c](src/ssl.c)) |
| `SceSslInternal` | `0x68D6C3FF` | 98 | 3 from the NID database: `sceSslInternalGetCertificateAuthority`, `sceSslInternalIsInitalized` (its spelling) and `sceSslInternalWrite`; the ones written here after what they do ([src/core.c](src/core.c), [src/connection.c](src/connection.c)); the others `sceSslInternal<NID>` ([src/internal.c](src/internal.c)) |

`SceSslInternal` is the part Sony's own modules use for their TLS: Sony's libhttp alone imports 69
of its functions. The arguments of the ones not written yet aren't known, so their stubs take none.

## How the written part behaves

- **The pool**: as Sony's, everything comes from one memory block of the size `sceSslInit` is
  given (`SceLibsslGlobalHeap`), Mbed TLS's allocations included; `sceSslGetMemoryPoolStats`
  reports its size, peak and current use. A size the kernel refuses (not a multiple of 4 KiB, or
  more than the process has) fails with the kernel's error; 0 is `SCE_SSL_ERROR_INVALID_VALUE`, a
  second `sceSslInit` `SCE_SSL_ERROR_ALREADY_INITED`.
- **Returns**: connect, read and write return what the socket returned when it failed (a negative
  SceNet error: a receive timeout is `0x80410123`, which libhttp checks for), 0 when the server
  closed the connection, and -1 when the TLS failed. `SSL_get_error` then says which, as Sony's: 1
  for TLS, 2 after any failed receive (Sony's socket BIO asks for a retry on each), 3 after a send
  that sent nothing, 6 for 0 after the server's close_notify, 5 otherwise (libhttp then reads
  SceNet's errno).
- **The host name**: libhttp gives it with `BIO_ctrl(bio, 100, 0, host)`, and Sony's ClientHello
  reads it back (command 123) as SNI, unless it's an IPv4 address. Here too: a name is sent as SNI
  and checked against the certificate; an IPv4 address isn't sent, and is checked against the
  certificate's IP address entries.
- **Certificates**: while a context's verify mode is on (libhttp always turns it on), the server is
  checked by Mbed TLS against the CA bundle (`vs0:/data/external/cert/CA_LIST.cer`, indexed on the
  first connection that needs it), with SHA-1 signatures allowed and a self-signed certificate in
  the bundle trusted, as vitals-http does. Sony's libssl instead calls the verify callback libhttp
  sets (`SSL_CTX_set_cert_verify_callback`), and libhttp does the whole check itself with the
  certificate functions; that callback is kept, not called yet. So for now a failed check always
  refuses the connection, even where libhttp's HTTPS options would accept it.
- **Not yet**: the client certificate callback is kept, not called; session resumption (libhttp
  turns Sony's cache off anyway); the option masks are kept, with no effect.
- **The handshake** runs on a thread with a 64 KiB stack, as vitals-http's does: a TLS 1.3
  handshake with elliptic curves needs more than some apps' network threads have.

## What Sony's libhttp uses

Sony's libhttp imports 69 of the 98 `SceSslInternal` functions. Read from its call sites, they are
an OpenSSL-like API: BSAFE SSL-C comes from SSLeay, as OpenSSL does. On top of that, certificates,
keys and names are handled through RSA's Cert-C object calls (create an object, read an item by
number, free it), which have no OpenSSL equivalent and need reading in libssl itself.

What each one does is worked out from how libhttp calls it (the addresses are in Sony's libhttp,
also mapped at `0x81000000`) and, for the connection functions, from Sony's libssl itself. The
arguments come from the registers libhttp sets before the call.

### Connection setup, handshake, reading, writing and closing

| NID | Called from | Arguments | What it is | Here |
| --- | --- | --- | --- | --- |
| `4B4A2307` | every entry point | `()` → 0, or `SCE_SSL_ERROR_BEFORE_INIT` | 0, or `SCE_SSL_ERROR_BEFORE_INIT` before `sceSslInit` | `sceSslInternalIsInitalized` |
| `2185BB05` | setup | `(void **out)` → 0 | hands out the library object `sceSslInit` made; `SCE_SSL_ERROR_BEFORE_INIT` before it | `sceSslInternalGetLibrary` |
| `A374CD7B` | setup | `()` → method | a client method (a static table in Sony's) | `sceSslInternalClientMethod` |
| `AC1DBE40` | second setup path (`0x81015B08`) | `()` → method | another client method | `sceSslInternalClientMethod2` |
| `E746465E` | setup | `(library, method)` → ctx | `SSL_CTX_new` | `sceSslInternalCtxNew` |
| `EF9EBAC7` | close | `(ctx)` | `SSL_CTX_free` | `sceSslInternalCtxFree` |
| `67FB1CD3` | setup | `(ctx, bytes, 8)` → 0 or a reason | adds the bytes to the context's random generator; Sony's reason 32 without any | `sceSslInternalCtxSeedRandom` |
| `FBEB1FD7` | setup | `(ctx, 0x20001FFB or 0x22001FFB)` | `SSL_CTX_set_options`: ORs the mask in; the second mask for apps built with SDK 3.50 or later and SSL version option 3 | `sceSslInternalCtxSetOptions` |
| `9E38815D` | setup | `(ctx, callback)` | `SSL_CTX_set_client_cert_cb`: the callback gets `(ssl, X509 **, EVP_PKEY **)` | `sceSslInternalCtxSetClientCertCallback` |
| `CC7F4211` | setup | `(ctx, 44, 0, NULL)` | `SSL_CTX_ctrl`; 44 and 45 set and get the session cache mode (OpenSSL's numbers), here turning it off | `sceSslInternalCtxCtrl` |
| `D28834E6` | setup | `(ctx)` → ssl | `SSL_new` | `sceSslInternalNew` |
| `19B2BB58` | setup, close | `(ssl)` | `SSL_free` | `sceSslInternalFree` |
| `0DB6C206` | setup | `(ssl, 0x40000)` | `SSL_set_options`: ORs the bits in | `sceSslInternalSetOptions` |
| `FFE2ED51` | setup | `(socket, 0)` → bio | `BIO_new_socket(fd, BIO_NOCLOSE)` | `sceSslInternalBioNewSocket` |
| `16D7C7CA` | setup | `(bio, 100, 0, pointer)` | `BIO_ctrl`; Sony's command 100 keeps the host name on the BIO, which the ClientHello reads back (123) for SNI | `sceSslInternalBioCtrl` |
| `4A1557A7` | setup | `(ssl, bio, bio)` | `SSL_set_bio` | `sceSslInternalSetBio` |
| `F2C9B744` | setup | `(ssl, callback)` | `SSL_set_info_callback`; libhttp's logs alerts (`SSL_CB_ALERT` with the read or write bit) | `sceSslInternalSetInfoCallback` |
| `F71DB06F` | setup | `(ssl, callback, NULL)` | keeps a callback and its argument; libhttp's does nothing | `sceSslInternalSetCallback` |
| `CEE46B33` | setup | `(ssl)` | `SSL_set_connect_state` | `sceSslInternalSetConnectState` |
| `E5EDD91B` | handshake | `(ssl)` → rc | `SSL_connect` | `sceSslInternalConnect` |
| `2F0FC3CD` | handshake, I/O | `(ssl, rc)` → kind | `SSL_get_error` | `sceSslInternalGetError` |
| `4F781BB6` | read | `(ssl, buffer, length ≤ 1500)` → rc | `SSL_read` | `sceSslInternalRead` |
| `F39A49C6` | write | `(ssl, buffer, length ≤ 1500)` → rc | `SSL_write` | `sceSslInternalWrite` |
| `EC9FAF42` | close, failed setup | `(ssl)` | `SSL_shutdown` | `sceSslInternalShutdown` |
| `461C5990` | 38 calls, after failures | `(kind, reason)` → `0x8043xxxx` | turns an internal failure into an SCE error code: kind 0 a certificate function's reason (most of 10001 to 10037 become `0x80432AF0` + reason, 10005 out of memory), kind 1 the given code unless an allocation failed | `sceSslInternalErrorCode` |

### Client certificate callback (`0x81009088`): the certificate and key `sceHttpsLoadCert` loaded

| NID | Called from | Arguments | Likely |
| --- | --- | --- | --- |
| `24C6257F` | callback, verification, second setup | `(ssl, 5 or 6, &out)` | reads an item of the SSL object by number |
| `A4EA9DE0` | callback | `(ssl)` → count | how many of a list the server sent (likely acceptable CA names) |
| `243DE290` | callback | `(ssl, index, &out)` | entry *index* of that list |
| `29AAC768` | callback, `sceHttpsLoadCert` | 7 arguments, DER in | makes a certificate object from DER |
| `144FA354` | callback, verification | `(certificate)` | frees a certificate object |
| `B8E6E249` | callback | `()` → buffer | a memory BIO or buffer object |
| `33AC7A16` | callback | `(buffer, data, length)` → written | writes to it |
| `7D30F0A6` | callback | `(buffer, ?, &key, 6, 0x1100)` | parses a private key from it |
| `C4D984C2` | callback | `(buffer)` | frees it |
| `46358909` | callback, verification | `(key)` | frees a key |
| `D68D8421` | callback | `(certificate, key)` → match | checks the key belongs to the certificate |
| `81FA5DBE` | callback, verification | `(certificate, 1, &name)` | a name of the certificate (issuer) |
| `568F0E80` | callback, verification | `(name, name)` → 1 when equal | compares two names |
| `CE37B69E` | callback, host check, verification | `(name)` | frees a name |

### Host name check (`0x81013EFA`): subjectAltName, then the subject's CN

| NID | Called from | Arguments | Likely |
| --- | --- | --- | --- |
| `BF99D664` | host check, verification | `(?, -1, &object)` | creates a list object |
| `64BDF1BB` | host check, verification | `(certificate, 0x4003, object)` | reads an extension into it (subjectAltName) |
| `93EAE08A` | host check, verification | `(object, 0x8002, &entry)` | an entry of it by type |
| `F030A0DE` | host check, verification | `(object)` | frees the list object |
| `08179EBD` | host check, verification | `(certificate, 1, &name)` | a name of the certificate (subject) |
| `91C2531C` | host check | `(name, 10 → count, 11 → entry)` | a name's attributes |
| `B5A099D2` | host check | `(attribute, 1 → type, 2 → value, &out)` | an attribute's type or value |
| `4D80D3F7` | host check | `(&out, 1, data, length)` | decodes an attribute type |
| `3DE4F3DB` | host check | `(type, 0, 24, text)` | writes it as dotted text, compared with `2.5.4.3` (CN) |
| `17BF2367` | host check | `(attribute)` | releases an attribute |

### Loading certificates (`sceHttpsLoadCert`, `0x81014292`) and `sceHttpPrivateSslContextAddCertCheck`

| NID | Called from | Arguments | Likely |
| --- | --- | --- | --- |
| `064DFC99` | load | 6 arguments | known: `sceSslInternalGetCertificateAuthority` |
| `3746501F` | load | 6 arguments | a wrapper like the one above, around another of libssl's own functions |
| `260F5A85` | `AddCertCheck` | `(ctx, 1)` | `SSL_CTX_set_verify`'s mode; written: `sceSslInternalCtxSetVerify` |
| `AF50B945` | `AddCertCheck` | `(ctx, callback, argument)` | `SSL_CTX_set_cert_verify_callback`, whose callback (libhttp's `0x81014592`) does the whole certificate check; written, the callback kept and not called yet: `sceSslInternalCtxSetCertVerifyCallback` |

### Certificate verification (`0x81014592`), not read yet

| NID | Called from | Arguments | Likely |
| --- | --- | --- | --- |
| `04BAED82` | verification |  |  |
| `08ED1B25` | verification |  |  |
| `170D595D` | verification |  |  |
| `2074A6EB` | verification |  |  |
| `2464F9D0` | verification |  |  |
| `306E2A22` | verification |  |  |
| `349B0E73` | verification |  |  |
| `4AAF0D45` | verification |  |  |
| `5E50CB55` | verification |  |  |
| `6CDB4EE8` | verification |  |  |
| `6D2A86F0` | verification |  |  |
| `88391E03` | verification |  |  |
| `B0E4CB2F` | verification |  |  |
| `D1A82B1A` | verification |  |  |
| `D3C049B9` | verification |  |  |
| `D4ADF069` | verification |  |  |

## Layout

| File | Role |
|---|---|
| [src/core.c](src/core.c) | `sceSslInit`, `sceSslTerm`, the pool's stats, the library object, the error translator, the random generator and the CA bundle's index |
| [src/connection.c](src/connection.c) | methods, contexts, connections, the socket BIO, connect, read, write, shutdown and `SSL_get_error` |
| [src/ssl.c](src/ssl.c) | `SceSsl`'s certificate functions (not written yet), and the stub every unwritten export calls |
| [src/internal.c](src/internal.c) | the `SceSslInternal` exports not written yet |
| [src/platform_vita.c](src/platform_vita.c) | module start and stop, the lock, the pool, SceNet and the handshake's thread |
| [tests/](tests/) | host tests: `platform_posix.c` in place of the Vita's, against `server.py` |

From tls13-vita it uses the Mbed TLS build in `crypto/`, `provider/ca_index.c`,
`provider/platform_shims.c` (Mbed TLS's mutexes, entropy and time) and `provider/user_runtime.c`
(the pool, and the C library the module is linked without).
