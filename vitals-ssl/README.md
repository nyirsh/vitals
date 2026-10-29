# vitals-ssl

Sony's SSL library (`SceLibSsl`, the `sceSsl` API) being written from scratch, as a user module
exported under libssl's own library and function NIDs ([libssl_api.yml.in](libssl_api.yml.in)),
all 109 of them, with TLS 1.2 and 1.3 from Mbed TLS 3.6 ([tls13-vita/crypto](../tls13-vita/crypto/),
shared with vitals-http and the browser provider).

Written so far: all 11 `SceSsl` functions and the 69 `SceSslInternal` functions Sony's libhttp
uses (below: connections, its certificate check and its client certificate callback), plus three
that do nothing in Sony's either. Every other
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
dropped socket, a receive timeout, the certificate and host name checks, and the error codes; and
the certificate functions on a CA and a server certificate it signed: names, extensions, keys and
signatures, dates, the CA store, and a verify callback that checks the chain with them, as
libhttp's does.

### On a console

With vitals installed, no process runs Sony's libhttp, which is what vitals-ssl is written for. The
vitals-ssl test app gives one process exactly that:

```bash
make -C ../vitals-app SSL_TEST=1    # build/vitals-app-ssltest/vitals-app.vpk
```

It is vitals-app with its own title (`VITALSSL1`, "vitals ssl test"), carrying the kernel plugin
built with its test route (`make -C ../vitals-plugin SSL_TEST=1`) and this library's `DEBUG=1`
build as `vssl.suprx`. Install it next to vitals-app, run its Install, and reboot. In its process
only, the plugin leaves Sony's libhttp alone and loads `ux0:app/VITALSSL1/vssl.suprx` in place of
libssl; every other process is as with the release plugin, and deleting the app removes the
route's target (the app then gets Sony's libssl, which makes the stock run to compare with).
Running vitals-app's Install again puts the release plugin back.

Its connection test is vitals-app's (BrowserLeaks TLS 1.0 to 1.3 and the badssl.com battery), on
Sony's libhttp over vitals-ssl, so `sceHttpsEnableOption`/`DisableOption`, the verify callback and
the certificate functions all run. Its saved report (`ux0:data/vitals/vitalsssl-*.txt`) adds which
libssl loaded, the pool before and after the run, and what an `sceHttpsSetSslCallback` saw through
the `sceSslGet*` getters (it refuses what libhttp found wrong, as without one). It also loads
badssl.com's untrusted root with `sceHttpsLoadCert` (libhttp looks for issuers among the
certificates an app loaded before the CA store), connects to `untrusted-root.badssl.com`, which
must work, and again after `sceHttpsUnloadCert`, which must be refused. Then it loads badssl.com's
published client certificate and key (the key decrypted) and requests `client.badssl.com`, which
answers 200 when the certificate was sent and 400 when it wasn't, before and after unloading them.


The NIDs are those of the libssl the app bundles ([vitals-app/assets/lssl.suprx](../vitals-app/assets/lssl.suprx)),
read from its export table, and so is the module NID (`0xB1620F91`; the NID database's 3.60
entry gives `0x9CD6CA85`). Each function's comment gives its NID and the address of Sony's
function in that copy, whose code is mapped at `0x81000000`, as the starting point for working out
what it does.

| Library | NID | Functions | Named |
| --- | --- | --- | --- |
| `SceSsl` | `0xCAF5F2E9` | 11 | all, as `<psp2/libssl.h>` declares them ([src/core.c](src/core.c), [src/ssl.c](src/ssl.c)) |
| `SceSslInternal` | `0x68D6C3FF` | 98 | 3 from the NID database: `sceSslInternalGetCertificateAuthority`, `sceSslInternalIsInitalized` (its spelling) and `sceSslInternalWrite`; the ones written here after what they do ([src/core.c](src/core.c), [src/connection.c](src/connection.c), [src/certificate.c](src/certificate.c)); the others `sceSslInternal<NID>` ([src/internal.c](src/internal.c)) |

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
  reads it back (command 123) as SNI, unless it's an IPv4 address. The firmware's libhttp on a
  console doesn't (the copy read for this was another build); there the name comes from its verify
  callback's argument, which holds the host name its check compares. Here too: a name is sent as SNI
  and checked against the certificate; an IPv4 address isn't sent, and is checked against the
  certificate's IP address entries.
- **Certificates**: while a context's verify mode is on (libhttp always turns it on), the server is
  checked. When the context has a verify callback (`SSL_CTX_set_cert_verify_callback`, which libhttp
  sets), it decides, as in Sony's: it's called once Mbed TLS has the server's chain, with the
  certificates in the order the server sent them, and whatever Mbed TLS found is dropped. libhttp's
  does the whole check itself with the certificate functions (below), so `sceHttpsDisableOption`
  and `sceHttpsSetSslCallback` work as on Sony's. Without one, Mbed TLS checks the server against
  the CA bundle (`vs0:/data/external/cert/CA_LIST.cer`, indexed on the first connection that needs
  it), with SHA-1 signatures allowed and a self-signed certificate in the bundle trusted, as
  vitals-http does.
- **The CA store**: Sony's libssl has its roots built in, served as PEM text by number
  (`064DFC99`) and by name (`3746501F`); here they are the CA bundle's. Where Sony's has one root
  per name, the bundle can have several (cross-signed roots), so asking again for a name on the
  same thread gives the next, then none: libhttp asks again when the root it got doesn't verify the
  certificate, and with the same answer would ask forever. A version 3 certificate without
  basicConstraints is not a CA here (RFC 5280, Mbed TLS), where libhttp would skip the check.
- **Client certificates**: when the server asks for one, the context's client certificate callback
  (`SSL_CTX_set_client_cert_cb`) runs with the CA names the server gave, as in Sony's, and the
  certificate and key it gives are sent. libhttp's gives the ones `sceHttpsLoadCert` loaded, and
  only when one of those names is the certificate's issuer. Mbed TLS doesn't pass those names on or
  let a client pick its certificate then, so a patch adds that
  ([tls13-vita/crypto/certificate-request-callback.patch](../tls13-vita/crypto/certificate-request-callback.patch)),
  for TLS 1.2's CertificateRequest and TLS 1.3's `certificate_authorities`; a TLS 1.3 server that
  sends no names gets no certificate from libhttp's callback.
- **Not yet**: session resumption (libhttp turns Sony's cache off anyway); the option masks are
  kept, with no effect.
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
| `260F5A85` | `sceHttpPrivateSslContextAddCertCheck` | `(ctx, 1)` | `SSL_CTX_set_verify`'s mode: 1 checks the server | `sceSslInternalCtxSetVerify` |
| `AF50B945` | `sceHttpPrivateSslContextAddCertCheck` | `(ctx, callback, argument)` | `SSL_CTX_set_cert_verify_callback`: libhttp's `0x81014592`, which does the whole check (below) | `sceSslInternalCtxSetCertVerifyCallback` |
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

### Certificate verification (`0x81014592`): libhttp's own check of the server's chain

Sony's libssl calls it from its chain check (`0x810166A7`) in place of its own verifier, as
`int callback(SSL *ssl, X509 *certificates[], int count, void *argument, int *reason)`, the server's
certificates as it sent them, and `reason` the connection's verify result. 1 accepts; on 0 Sony's
refuses the connection (when the verify mode is on) with the alert for the reason: 2 → 51
(decrypt_error), 3 → 42 (bad_certificate), 4 → 45 (certificate_expired), 8 → 44
(certificate_revoked), 10 → 40 (handshake_failure), 11 → 80 (internal_error). The argument is the
structure libhttp gave `sceHttpPrivateSslContextAddCertCheck`:

| Offset | What |
| --- | --- |
| 0 | the `SCE_HTTPS_FLAG_*` bits (101 when 0: server verify, CN check, known CA check and 0x40); 0x40 looks issuers up in the CA store; 0x100 only the store's first group; 0x40000000 takes the lock at 20, 40 and 44 around it |
| 4 | the host name the CN check compares |
| 8 | where the SCE result goes: `0x80435806` when refused, `0x80435804` when out of memory, 0 when accepted |
| 12 | where the `SCE_HTTPS_ERROR_SSL_*` bits go: 1 a certificate function failed, 2 an invalid certificate or chain, 4 the CN check, 8 expired, 16 not yet valid, 32 an unknown CA |
| 16, 20 | the app's `sceHttpsSetSslCallback` and its argument, called last as `(bits, certificates, count, argument)`; a negative return refuses |

For each certificate it reads the serial number, subject and issuer, compares the current time with
the validity dates when `NOT_AFTER_CHECK` or `NOT_BEFORE_CHECK` is set, and takes the DER
encoding. The host check (`0x81013EFA`) then runs on the first certificate when `CN_CHECK` is set:
the subjectAltName's value, which libhttp parses itself, and only without one the subject's CN
(the entry whose attribute is `2.5.4.3`). Then the chain is ordered: each issuer is looked for among
the certificates and, with 0x40, in the certificates `sceHttpsLoadCert` loaded and the CA store
(libhttp's `0x81014292`, which decodes the PEM text and parses it with `29AAC768`); a root found is
checked against its group's refused serial numbers, its key must verify the signature below it, and
up the chain each issuer must be a CA with room in its path length and must have made the
signature below; MD2, MD4 and MD5 signatures are refused. Without a known root, bit 32.

What each function is comes from how libhttp uses what it returns and from Sony's libssl, where
they are RSA Cert-C's object calls (an object's info by number through its type's table). The
objects are only ever reached through these functions, so here they are vitals-ssl's own, over
Mbed TLS ([src/certificate.c](src/certificate.c)); only the items libhttp reads directly keep
Sony's layout: an item is `{length, bytes}`, an entry's info `{tag, length, bytes}`.

| NID | Arguments | What it is | Here |
| --- | --- | --- | --- |
| `24C6257F` | `(ssl, item, &out)` | an item of the connection: 1 the Cert-C context, 3, 5 and 6 other Cert-C objects, 7 another of the connection; `10017` without a connection or out, `10011` for another number | `sceSslInternalGetItem`: one Cert-C object for 1, 5 and 6, nothing for the others |
| `B0E4CB2F` | `(ssl, result)` | `SSL_set_verify_result`; libhttp sets the reason again | `sceSslInternalSetVerifyResult` |
| `29AAC768` | `(cert_c, 0, 1, length, der, &consumed, &certificate)` | a certificate from DER | `sceSslInternalCertFromBinary` |
| `144FA354` | `(certificate)` | frees one | `sceSslInternalCertFree`; the server's stay the connection's |
| `64BDF1BB` | `(certificate, item, out)` | a certificate's info: 2 the serial number (an item), `0x4003` subjectAltName and `0x4005` basicConstraints into an extension object, `0x8007` the signature's algorithm (7 and 8 refused), `0x8009` the public key, `0x800A` and `0x800B` the issuer's and subject's names; `10008` without the extension | `sceSslInternalCertInfo`; 8 for MD5; a version 3 certificate without basicConstraints gets one with cA false |
| `08ED1B25` | `(certificate, 4, size, buffer, &length)` | the DER encoding; its length with no buffer | `sceSslInternalCertToBinary` |
| `2074A6EB` | `(certificate, time)` | the notAfter into a time object | `sceSslInternalCertNotAfter` |
| `2464F9D0` | `(certificate, time)` | the notBefore | `sceSslInternalCertNotBefore` |
| `170D595D` | `(certificate, 1, &key)` | the public key, freed with `46358909` | `sceSslInternalCertPublicKey` |
| `306E2A22` | `(certificate, key, &valid)` | whether the key made the certificate's signature | `sceSslInternalCertVerifySignature` |
| `46358909` | `(key)` | frees a key | `sceSslInternalKeyFree` |
| `08179EBD` | `(certificate, 1, &name)` | the subject's name, freed with `CE37B69E` | `sceSslInternalCertSubject` |
| `81FA5DBE` | `(certificate, 1, &name)` | the issuer's | `sceSslInternalCertIssuer` |
| `CE37B69E` | `(name)` | frees a name | `sceSslInternalNameFree` |
| `568F0E80` | `(name, name)` → 1 when the same | compares two names | `sceSslInternalNameEqual`, as Mbed TLS compares them |
| `91C2531C` | `(name, 10, &count)`, `(name, 11, &{index, entry})` | the number of entries, an entry, freed with `17BF2367` | `sceSslInternalNameInfo` |
| `B5A099D2` | `(entry, 1 or 2, &{tag, length, bytes})` | an entry's attribute (the OID's bytes) or value | `sceSslInternalEntryInfo` |
| `17BF2367` | `(entry)` | frees an entry | `sceSslInternalEntryFree` |
| `4D80D3F7` | `(&oid, 1, bytes, length)` | points an OID object (16 bytes, libhttp's stack) at bytes | `sceSslInternalOidSet` |
| `3DE4F3DB` | `(oid, 0, 24, text)` | the OID as dotted text | `sceSslInternalOidText` |
| `BF99D664` | `(cert_c, -1, &extension)` | an empty extension object | `sceSslInternalExtensionNew` |
| `93EAE08A` | `(extension, item, out)` | `0x8001` critical, `0x8002` the value (an item), for basicConstraints `0x8007` cA and `0x8008` the path length | `sceSslInternalExtensionInfo`; no path length is `INT_MAX` |
| `F030A0DE` | `(extension)` | frees it | `sceSslInternalExtensionFree` |
| `D3C049B9` | `(cert_c, 0, &provider)` | the context's time provider | `sceSslInternalTimeProvider` |
| `D4ADF069` | `(provider)` | frees it | `sceSslInternalTimeProviderFree` |
| `5E50CB55` | `(provider, &time)` | a time object, freed with `6CDB4EE8` | `sceSslInternalTimeNew` |
| `6CDB4EE8` | `(time)` | frees it | `sceSslInternalTimeFree` |
| `4AAF0D45` | `(&now)` | the current time (Sony's calls a hook) | `sceSslInternalTimeNow`: 8 bytes of seconds |
| `6D2A86F0` | `(&now, 3, &value, 8)` | that time as a value of format 3 | `sceSslInternalTimeExport` |
| `88391E03` | `(time, 3, &value, 8)` | sets a time object from one | `sceSslInternalTimeImport` |
| `04BAED82` | `(time, time, &order)` | -1, 0 or 1 as the first is before, at or after the second | `sceSslInternalTimeCompare` |
| `D1A82B1A` | `(time, 6, text, &length, 20)` | a time as text, for libhttp's log | `sceSslInternalTimeText`: `YYYYMMDDHHMMSSZ` |
| `3746501F` | `(name, &entries, buffer, size, &total, flag)` → 1, or 0 | the store's root with the name, `entries[0]` its PEM text; with no buffer the size needed | `sceSslInternalGetCertificateAuthorityByName`, from the CA bundle |
| `064DFC99` | `(group, mask, &entries, buffer, size, &total)` → count, or `0x80010086` | the store's roots by number: a group from 1 and a bit each, group 0 with mask `0xFFFFFFFF` all of them | `sceSslInternalGetCertificateAuthority`: the bundle's roots in groups of 32 |
| `349B0E73` | `(group, mask, &entries, &count)` | the serial numbers a root refuses, as items; Sony's has ten, for one root | `sceSslInternalCaRevoked`: none |

### Client certificate callback (`0x81009088`): the certificate and key `sceHttpsLoadCert` loaded

Called as `int callback(SSL *ssl, X509 **certificate, EVP_PKEY **key)`: it parses the loaded
certificate (`29AAC768`, with `24C6257F`'s item 5) and writes the loaded key to a buffer to parse it
(with item 6), checks they belong together, then looks for the certificate's issuer among the
server's CA names. When one is the issuer it gives both and returns 1, which hands them to the
connection; otherwise it frees them and returns 0, and no certificate is sent.

| NID | Arguments | What it is | Here |
| --- | --- | --- | --- |
| `A4EA9DE0` | `(ssl)` → count | how many CA names the server's certificate request gave | `sceSslInternalGetCaNameCount`; 0 outside the callback |
| `243DE290` | `(ssl, index, &name)` | one of them, a name object the connection keeps | `sceSslInternalGetCaName` |
| `B8E6E249` | `()` → buffer | a memory buffer (a memory BIO) | `sceSslInternalBufferNew` |
| `33AC7A16` | `(buffer, data, length)` → written | appends to it; libhttp loops until all is written | `sceSslInternalBufferWrite` |
| `7D30F0A6` | `(buffer, cert_c, &key, 6, 0x1100)` | a private key from it, freed with `46358909` | `sceSslInternalKeyFromBuffer`: PEM or DER |
| `C4D984C2` | `(buffer)` | frees it | `sceSslInternalBufferFree` |
| `D68D8421` | `(certificate, key)` → 1 when they match | whether the key is the certificate's | `sceSslInternalKeyMatches` |

`29AAC768` takes PEM text here too, as an app may load its certificate that way.

`sceHttpPrivateSslContextAddCertCheck` sets the verify mode (`260F5A85`, `(ctx, 1)`) and the
callback (`AF50B945`), both in the connection table above.

## VitalsSsl: vitals' additions

vitals-http does its TLS through vitals-ssl, built into it for now, so a later step can have it
import the libssl module as Sony's libhttp does. It uses Sony's functions and a few more, which
the module exports as its own library, `VitalsSsl` (NID `0x6D89DA35`; each function's NID is the
first word of the SHA-1 of its name, as Sony's are made). [include/vitals_ssl.h](include/vitals_ssl.h)
declares both, with every object opaque:

| Functions | What for |
| --- | --- |
| `vitalsSslInitShared` | the library without a pool of its own: its memory is the caller's (vitals-http's heap) |
| `vitalsSslBioNew` | a BIO over the caller's transport (its timeouts, aborts and proxy tunnels) |
| `vitalsSslCtxSetProfile` | the console's ClientHello for Sony's private HTTPS option `0x40` (PSN sign-in) |
| `vitalsSslCtxSetDeferredVerify`, `vitalsSslGetCertificateFlags`, `vitalsSslGetVerifyResult` | the handshake goes on whatever the check finds, and the caller decides from it (its HTTPS options, the app's callback) |
| `vitalsSslStoreNew`, `vitalsSslStoreAdd`, `vitalsSslStoreRelease`, `vitalsSslCtxSetStore` | CA certificates trusted besides the bundle (an app's `sceHttpsLoadCert` ones), also as exact self-signed certificates |
| `vitalsSslCtxSetIdentity`, `vitalsSslCheckCertificate`, `vitalsSslCheckKey` | a client certificate sent to any server that asks, as vitals-http does |
| `vitalsSslGetTlsError`, `vitalsSslTlsErrorIsMemory`, `vitalsSslGetVersion`, `vitalsSslGetCiphersuite`, `vitalsSslCertificateRequested` | what a connection did, for errors and logs |

Built in, vitals-ssl's platform is vitals-http's ([vitals-http/src/ssl_platform.c](../vitals-http/src/ssl_platform.c)).

## Layout

| File | Role |
|---|---|
| [src/core.c](src/core.c) | `sceSslInit`, `sceSslTerm`, the pool's stats, the library object, the error translator, the random generator and the CA bundle's index |
| [src/connection.c](src/connection.c) | methods, contexts, connections, the socket BIO, connect, read, write, shutdown, `SSL_get_error`, and calling the verify callback |
| [src/certificate.c](src/certificate.c) | the certificate objects: certificates, names and entries, extensions, keys, times and the CA store |
| [src/ssl.c](src/ssl.c) | `SceSsl`'s certificate getters, and the stub every unwritten export calls |
| [src/internal.c](src/internal.c) | the `SceSslInternal` exports not written yet |
| [src/vitals.c](src/vitals.c), [include/vitals_ssl.h](include/vitals_ssl.h) | VitalsSsl, vitals' additions, and the header vitals' own callers include |
| [src/platform_vita.c](src/platform_vita.c) | module start and stop, the lock, the pool, SceNet and the handshake's thread |
| [tests/](tests/) | host tests: `platform_posix.c` in place of the Vita's, against `server.py` |

From tls13-vita it uses the Mbed TLS build in `crypto/`, `provider/ca_index.c`,
`provider/platform_shims.c` (Mbed TLS's mutexes, entropy and time) and `provider/user_runtime.c`
(the pool, and the C library the module is linked without).
