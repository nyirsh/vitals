# The browser's TLS in vitals: its whole lifetime

This document follows the two modules that give the browser modern TLS: vitals' copy of the
browser engine's networking module (`ScePsp2Compat`, `compat.suprx`) and the browser provider
(`vitals.suprx`). Its companion is [libssl.md](libssl.md); apps and games use `vitals-http`, described
in [vitals-http.md](vitals-http.md).

In one paragraph: the browser doesn't use libhttp; its engine does its networking through
`ScePsp2Compat`, which carries its own libcurl. The kernel plugin swaps that module for vitals'
known copy whenever a process loads it from a `webcore` folder, and once it has started, loads
vitals' libssl ([vitals-ssl](../vitals-ssl/)) into that process, then injects the browser provider.
The provider checks it has the exact module it expects, and hooks four functions of libcurl's TLS
layer inside it. From then on libssl does the TLS of the browser's connections, as it does every
app's through vitals-http, and the provider points each connection's send and receive at itself.
Everything lives until the process exits.

## At a glance

| Module                          | File loaded                                                                 | Loaded when                                                    | Into         | Shared or private                                     | Until                               |
| ------------------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------- | ------------ | ----------------------------------------------------- | ----------------------------------- |
| `ScePsp2Compat` (vitals' copy)  | `…/vitals/ScePsp2Compat.suprx`, in place of `…/webcore/ScePsp2Compat.suprx` | a process loads the browser engine's networking module         | that process | as the process asked; vitals doesn't change its flags | the process unloads it or exits     |
| `SceLibSsl` (vitals-ssl)        | `ux0:data/vitals/system/libssl.suprx`, in place of Sony's                | right after that `ScePsp2Compat` has started, unless there     | that process | **shared**, as the system loads it for apps           | the process exits                   |
| `vitals` (the browser provider) | `ux0:data/vitals/system/vitals.suprx`                                        | right after libssl, once per process                           | that process | private                                               | the process exits; it never unloads |

## 1. On disk

| File on the console                             | Comes from                                                                                | Installed by                                                    |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `vs0:/data/external/vitals/ScePsp2Compat.suprx` | `app0:compat.suprx` ([vitals-app/assets/compat.suprx](../vitals-app/assets/compat.suprx)) | `install_compat`, [install.c:832](../vitals-app/install.c#L832) |
| `ux0:data/vitals/system/vitals.suprx`            | the browser provider, built from [tls13-vita/browser/](../tls13-vita/browser/)            | same function                                                   |
| `ux0:data/vitals/system/libssl.suprx`        | vitals-ssl, the system's libssl, which also does the provider's TLS                       | `install_http_modules`                                          |
| `vs0:/data/external/cert/CA_LIST.cer`           | the certificate bundle libssl trusts                                                      | `install_certificates`                                          |

- **One copy of the provider**, in `ux0:data/vitals/system` with vitals' other modules
  (`VITALS_BROWSER_PROVIDER_BOOT_PATH`, [path.h](../tls13-vita/include/vitals/path.h)). Earlier
  versions kept it in `ur0:tai/vitals-native/` with an unused second copy on `vs0:`; installing
  removes both.
- **The engine stays on `vs0:`**, next to Sony's: its swap keeps the folder the process names it by
  (below), which a process may see under another device name.
- **Sony's own** `ScePsp2Compat.suprx` in the `webcore` folder is never modified. A leftover
  `vs0:/data/external/webcore/ScePsp2Compat.supr0` from older tools is removed
  ([install.c:834](../vitals-app/install.c#L834)), and while it exists vitals doesn't count as
  installed ([install.c:1058](../vitals-app/install.c#L1058)).
- **A fixed binary** — the bundled `compat.suprx` is checked by SHA-256 in the kernel and by sizes
  and code bytes in the provider, which is what lets the provider hook it at fixed offsets.

## 2. Boot: the kernel plugin gets ready

The kernel plugin's `module_start` ([vitals-plugin/main.c](../vitals-plugin/main.c)):

1. **The replacement exists** — `module_start` ([main.c](../vitals-plugin/main.c)) sets
   `g_replace_compat` when `vs0:/data/external/vitals/ScePsp2Compat.suprx` exists. It is
   independent of the libhttp and libssl pair.
2. **Loader readiness** — `vitals_kernel_loader_init`
   ([tls13_loader.c](../vitals-plugin/tls13_loader.c)) runs `target_matches` for the
   browser target ([tls13_loader.c](../vitals-plugin/tls13_loader.c)): the provider
   at `ux0:data/vitals/system/vitals.suprx` must exist, and the replacement module's SHA-256 must
   equal `g_expected_browser_sha256` ([tls13_loader.c](../vitals-plugin/tls13_loader.c)).
   Only then is the loader ready (`browser=1` in `vitals: loader init=…`). When the provider isn't
   there yet at boot (`ux0:` not mapped), `vitals_kernel_browser_loader_ready` looks again at each
   engine load.
3. **The module manager hooks**: the load and start hooks every replacement goes through.

## 3. A process asks for the browser engine: the load hook

`load_for_pid_patched` ([main.c](../vitals-plugin/main.c)) sees every load:

1. **Path swap** ([main.c](../vitals-plugin/main.c)) —
   `vitals_browser_replacement_path` ([path.c:67](../tls13-vita/src/path.c#L67)) matches any path
   ending in `webcore/ScePsp2Compat.suprx` right after a `/` or `:`, and keeps its prefix: for
   example `vs0:/data/external/webcore/ScePsp2Compat.suprx` becomes
   `vs0:/data/external/vitals/ScePsp2Compat.suprx`. Keeping the prefix means the swap works with
   whatever device name the process sees that folder under.
2. **Flags left alone** — the load is shared or private as the process asked; there is no HTTP
   policy for the browser engine.
3. **The real load** — `TAI_CONTINUE` ([main.c](../vitals-plugin/main.c)).
4. **Queue the injection** ([main.c](../vitals-plugin/main.c)): when the loader is
   ready, `vitals_browser_provider_path` ([path.c:74](../tls13-vita/src/path.c#L74)) works out
   `…/vitals/vitals.suprx` from the swapped path, and `vitals_post_start_defer(pid, module, path)`
   ([post_start.c](../vitals-plugin/post_start.c)) records it. That path only serves to find
   the module again for its hash check (step 5.4); the provider itself is always loaded from `ur0:`.

## 4. Which processes

Any process loading the engine from a `webcore` folder: the browser's WebKit process, and others
that embed a web view. Their HTTP library, like every process's, is `vitals-http`; the engine's own
libcurl connections are this provider's.

## 5. The module has started: injecting the provider

`start_for_pid_patched` ([main.c](../vitals-plugin/main.c)) calls
`vitals_post_start_complete` ([post_start.c](../vitals-plugin/post_start.c)), which calls
`vitals_kernel_inject_browser_for_pid` ([tls13_loader.c](../vitals-plugin/tls13_loader.c))
for the queued module, through `inject_target`
([tls13_loader.c](../vitals-plugin/tls13_loader.c)):

1. **One injection per process at a time**, in a 4 KiB lookup workspace.
2. **Not already there** — `ScePsp2Compat` must be found in the process, and the module `vitals`
   must not be ([tls13_loader.c](../vitals-plugin/tls13_loader.c)).
3. **The provider to load** — always `ux0:data/vitals/system/vitals.suprx`
   ([tls13_loader.c](../vitals-plugin/tls13_loader.c)).
4. **The module's hash, in the process's own view** — the module path is worked back from the
   queued provider path (`vitals_browser_module_path`, [path.c:88](../tls13-vita/src/path.c#L88)) and
   hashed through the process's own file system view (`ksceIoOpenForPid`,
   [tls13_loader.c](../vitals-plugin/tls13_loader.c)), since that is the path the process
   loaded it from ([tls13_loader.c](../vitals-plugin/tls13_loader.c)).
5. **Still the right module** — the module ID handed over must be `ScePsp2Compat`.
6. **Start arguments** — `VitalsBrowserStartArgs` (magic `0x42544C53`, version 1, the module's ID;
   [browser_abi.h:55](../tls13-vita/include/vitals/browser_abi.h#L55)) in a user memory block of
   that process.
7. **libssl first** — the browser engine's process doesn't load libssl, and the provider's TLS is
   libssl's: unless `SceLibSsl` is already there, Sony's libssl is loaded into the process as the
   system loads it for an app (the module manager's own load, with sceSysmodule's flags,
   `vitals_kernel_load_system_libssl` in [main.c](../vitals-plugin/main.c)), which the path swap
   turns into vitals-ssl, then started (`ensure_libssl`, [tls13_loader.c](../vitals-plugin/tls13_loader.c)).
   It has to be **shared**: the shared libhttp there imports from it, and the kernel refuses a
   private module exporting to a shared one (`0x8002D018`). Logged as
   `vitals: libssl for the browser pid=… modid=… start=… status=…`. Without it the provider isn't
   loaded, and the browser keeps its own TLS.
8. **Load and start** — `ksceKernelLoadStartModuleForPid`
   ([tls13_loader.c](../vitals-plugin/tls13_loader.c)); unloaded again if its start fails.
   Logged as `vitals: inject browser provider pid=… rc=…`.

## 6. The provider starts: checks and hooks

`module_start` in [tls13-vita/browser/module.c:106](../tls13-vita/browser/module.c#L106), in the
browser's process:

1. **Once per process** — a second start is refused.
2. **Start arguments** checked.
3. **The module it was given** — `validate_module` ([module.c:69](../tls13-vita/browser/module.c#L69)):
   named `ScePsp2Compat`; code `0x39f508`/`0x39f630` bytes and data `0x9c28`/`0xd234`
   ([module_descriptor.h:25-28](../tls13-vita/browser/module_descriptor.h#L25-L28)); the code bytes
   at six known functions matching their signatures
   ([module_descriptor.h:12-19](../tls13-vita/browser/module_descriptor.h#L12-L19)). The module's own
   path gives the certificate bundle's: the same prefix with `cert/CA_LIST.cer`
   (`vitals_browser_ca_path`, [path.c:81](../tls13-vita/src/path.c#L81)).
4. **Two of the engine's own functions** the provider will call: libcurl's time-left and
   socket-wait helpers, at fixed offsets ([module.c:135-136](../tls13-vita/browser/module.c#L135-L136),
   [browser_abi.h:13-14](../tls13-vita/include/vitals/browser_abi.h#L13-L14)), so its handshakes
   respect the browser's timeouts.
5. **State** — `vitals_browser_init` ([backend.c](../tls13-vita/browser/backend.c)): mutexes and
   the connection registry. The TLS is libssl's, imported through vitals-ssl's stub: on the first
   connection the provider checks the certificate bundle is there (`ensure_default_ca`) and sets
   libssl up with a 1 MiB pool (`sceSslInit`, `ensure_library`), which every connection's memory
   comes from; libssl reads the bundle itself, through an index, as for apps. The provider's own
   few allocations come from the process's C library (it links `SceLibc`).
6. **The four hooks** — by offset in `ScePsp2Compat` (`taiHookFunctionOffset`, Thumb;
   [module.c:147-161](../tls13-vita/browser/module.c#L147-L161)), on libcurl's TLS layer:

   | Hook                            | Offset ([browser_abi.h:9-12](../tls13-vita/include/vitals/browser_abi.h#L9-L12)) | Goes to                  |
   | ------------------------------- | -------------------------------------------------------------------------------- | ------------------------ |
   | connect (the handshake)         | `0xa5ece`                                                                        | `vitals_browser_connect` |
   | close                           | `0xa36ba`                                                                        | `vitals_browser_close`   |
   | pending (buffered data)         | `0xa6240`                                                                        | `vitals_browser_pending` |
   | check (is the connection alive) | `0xa354c`                                                                        | `vitals_browser_check`   |

   If a later hook fails, the ones already in place stay, as a thread may already be running them.

7. **Enabled** — `vitals_browser_enable(1)`; logged as `browser TLS active`.

## 7. One browser HTTPS connection

```
libcurl in ScePsp2Compat ─ TLS connect ─▶ vitals_browser_connect
    first call: read curl's options; a libssl connection for this socket, or decline
    then: handshake steps, waiting with the engine's own socket-wait and time-left
    done: curl's send and receive for this connection point at vitals_browser_send / _recv
libcurl ─ send / recv ─▶ libssl ─▶ sceNetSend / sceNetRecv (non-blocking) on curl's socket
libcurl ─ pending / check ─▶ buffered data, liveness
libcurl ─ close ─▶ close_notify, session removed
    declined ─▶ libcurl's own TLS in the engine
```

- **Connect, first call** — `create_or_acquire` ([backend.c](../tls13-vita/browser/backend.c))
  reads curl's settings for the connection (`vitals_browser_read_options`,
  [config.c](../tls13-vita/browser/config.c)): socket, host, CA file, peer and host
  verification, cipher list, and any context callback. It **declines**, leaving the engine's own
  TLS to handle the connection, when the provider is disabled, curl already set up TLS on it, a
  setting is one it can't honour (another TLS version, client certificates, CRLs, certificate info
  requests, a context callback other than the browser's default), the certificate bundle can't
  be read, or libssl can't be set up. Each connection is a libssl one with vitals' callback BIO
  over curl's socket, TLS 1.2 and 1.3 with the suites curl's list allows (TLS 1.3's always),
  ALPN `http/1.1`, and the verification deferred: a page's own CA file, when it names one, is the
  only trust (`vitalsSslCtxSetTrustBundle`), otherwise the bundle. A connection with verification
  turned off, to a host whose certificate was refused here, is refused too, unless the user was
  asked about it ([section 8](#8-a-certificate-refused-the-browser-asks)).
- **The handshake** — `vitals_browser_connect` ([backend.c](../tls13-vita/browser/backend.c))
  steps `vitalsSslHandshake`, waiting between steps with the engine's socket-wait and time-left,
  or returning at once for non-blocking connects. On a certificate failure it writes the verify
  result where curl reports it, and reports the failure to WebKit ([section 8](#8-a-certificate-refused-the-browser-asks)).
  Once done, it marks curl's
  TLS state connected and replaces the connection's receive and send functions with
  `vitals_browser_recv` / `vitals_browser_send`.
- **Data** — through libssl (`SSL_read`, `SSL_write`), on curl's own socket with
  `SCE_NET_MSG_DONTWAIT` (`browser_send` / `browser_recv`, which answer `VITALS_SSL_WOULD_BLOCK`
  when the socket has nothing or no room).
- **Pending and check** — `vitals_browser_pending` / `_check`:
  whether decrypted data is waiting, and whether the connection is still alive (peeking one byte if
  needed).
- **Close** — `vitals_browser_close` sends
  `close_notify` when the connection was healthy, and removes it from the registry.

## 8. A certificate refused: the browser asks

The browser asks before it shows a page whose certificate didn't verify, and only after a yes
retries the request with verification off. vitals keeps that behaviour by reporting a refusal
the way the engine's own TLS does.

**How the engine's own TLS does it.** WebKit gives curl a context callback for every HTTPS
request (the "browser's default" the provider recognises). It hands the OpenSSL context to
ScePsp2Compat, which installs its own certificate check with WebKit's request as the argument.
That check never fails the handshake: it records what it found in the request, which starts with
a part ScePsp2Compat defines:

| Offset | What                                                                                       |
| ------ | ------------------------------------------------------------------------------------------ |
| `+12`  | a chain record of the server's certificates, when the check failed                         |
| `+16`  | the OpenSSL verify error (10 expired, 9 not yet valid, 20 unknown issuer…), or 100 when the flag at `+20` is clear |
| `+20`  | whether WebKit wants the error itself                                                      |

curl then fails the connection with error 60 or 51. WebKit's ResourceHandleManager looks at
`+12`:

- **A record there** — the request goes to its `verifySslThread`, which asks the user, showing the
  certificates from the record. On a yes, the host goes in a list of accepted hosts for the
  session, and the request is made again with `SSL_VERIFYPEER` and `SSL_VERIFYHOST` off; later
  requests to that host go out that way from the start. On a no, the request fails.
- **No record** — the request is made again at once with verification off, without asking. With the
  engine's own TLS this happens for a wrong host name (its check passes the chain; curl refuses the
  name), so such pages loaded with no warning.

**What the provider does.** On a certificate failure (curl errors 60 and 51), for a connection with
the browser's default callback, it fills in the same record (`report_to_webkit`,
[backend.c](../tls13-vita/browser/backend.c)): the server's certificates in DER form from libssl
(`vitalsSslGetPeerCertificate`), each made into one of the engine's OpenSSL `X509`s with its own
`d2i_X509`, in a chain record laid out as the engine's (the chain's top first, the server's
certificate last), and the verify error at `+16`. Both come from the engine's C library heap, as
WebKit frees them with the request. A wrong host name is reported too (error 62), so the browser
asks there as well.

The host is then remembered as refused, with the user asked. The retry with verification off,
which WebKit makes only after a yes, is then done by the provider over libssl, still TLS 1.2 or 1.3,
without the certificate check (`vitals_browser_read_unverified_options`). A host whose refusal
couldn't be reported (no browser callback, or the record couldn't be made) keeps its retries
refused, with the same error, so nothing loads unasked.

The record's layout and the engine's functions are at fixed places in the one ScePsp2Compat build
vitals ships, whose hash the kernel checks: `d2i_X509` at `0x48d64` and `X509_free` at `0x48d84`
([browser_abi.h](../tls13-vita/include/vitals/browser_abi.h)).

## 9. The end

- **The provider never unloads**: its `module_stop` refuses ([module.c:167-171](../tls13-vita/browser/module.c#L167-L171)).
- **Process exit**: the module, the provider, their hooks and every connection go away with the
  process.

## 10. What the logs show

| Line                                                               | Printed by         | Meaning                                           |
| ------------------------------------------------------------------ | ------------------ | ------------------------------------------------- |
| `vitals: loader init=… browser=…`                                  | kernel, boot       | `browser=1`: the browser provider can be injected |
| `vitals: post_start pid=… http=0 …`                                | kernel, start hook | the engine module started; injection follows      |
| `vitals: libssl for the browser pid=… modid=… start=… status=…`    | kernel             | libssl loaded into the browser engine's process   |
| `vitals: inject browser provider pid=… rc=…`                       | kernel             | the browser provider's load result                |
| `vitals_browser: browser libssl pool=… rc=…`                       | provider           | libssl set up, on the first connection            |
| `vitals_browser: browser TLS active: compat=… text=…`              | provider           | hooks in place                                    |
| `vitals_browser: browser handshake complete: … version=… cipher=…` | provider           | one connection's TLS, with debug output on        |
| `vitals_browser: browser connection uses legacy TLS: …`            | provider           | a connection left to the engine's own TLS         |
| `vitals_browser: browser connect rejected: socket=… code=…`        | provider           | a connection refused (60, 51: the certificate)    |
| `vitals_browser: browser certificate reported: certificates=… error=…` | provider       | the refusal reported to WebKit, which asks the user |
| `vitals_browser: browser unverified retry the user allowed`        | provider           | the retry after the user's yes                    |
| `vitals_browser: browser refused unverified retry: code=…`         | provider           | a retry without verification nobody asked about   |

## 11. Files

| File                                                                                                                            | Role                                                |
| ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| [vitals-plugin/main.c](../vitals-plugin/main.c)                                                                                 | the load and start hooks, the module swap           |
| [tls13-vita/src/path.c](../tls13-vita/src/path.c)                                                                               | the module, provider and certificate paths          |
| [vitals-plugin/tls13_loader.c](../vitals-plugin/tls13_loader.c)                                                                 | hashes and injection                                |
| [vitals-plugin/post_start.c](../vitals-plugin/post_start.c)                                                                     | the queue between a load and its start              |
| [tls13-vita/include/vitals/browser_abi.h](../tls13-vita/include/vitals/browser_abi.h)                                           | the engine's offsets and libcurl's structure fields |
| [tls13-vita/browser/module.c](../tls13-vita/browser/module.c), [module_descriptor.h](../tls13-vita/browser/module_descriptor.h) | provider start, module checks, the four hooks       |
| [tls13-vita/browser/backend.c](../tls13-vita/browser/backend.c)                                                                 | each connection, on libssl                          |
| [vitals-ssl/](../vitals-ssl/)                                                                                                   | the TLS                                             |
| [tls13-vita/browser/config.c](../tls13-vita/browser/config.c)                                                                   | reading curl's settings                             |
| [tls13-vita/browser/webkit_callback.c](../tls13-vita/browser/webkit_callback.c)                                                 | recognising the browser's default context callback  |
| [vitals-app/install.c](../vitals-app/install.c)                                                                                 | putting the files on the console                    |
