# libssl in vitals: its whole lifetime

This document follows Sony's SSL library (`SceLibSsl`, `libssl.suprx`) through vitals. Its
companions are [libhttp.md](libhttp.md) (the HTTP library that links to it, and where vitals' own
TLS lives), [reauth.md](reauth.md) and [browser.md](browser.md).

In one paragraph: vitals swaps libssl for its bundled copy whenever a process loads it, but leaves
it **shared** and never hooks it. vitals' TLS doesn't run in libssl: the HTTP provider replaces
libhttp's TLS with Mbed TLS. libssl is what libhttp falls back on whenever the provider leaves a
connection to Sony's TLS, and what the processes without the provider use all along.

## At a glance

| Module | File loaded | Loaded when | Into | Shared or private | Until |
|---|---|---|---|---|---|
| `SceLibSsl` (vitals' copy) | `vs0:/data/external/vitals/libssl.suprx`, in place of `vs0:sys/external/libssl.suprx` | a process loads Sony's libssl, usually with the HTTPS system module, as libhttp imports it | every process that loads it, mapped once (at `0xE…` in your logs) | always **shared** | the last process using it unloads it or exits |

Nothing is injected after it, and nothing hooks it.

## 1. On disk

| File on the console | Comes from | Installed by |
|---|---|---|
| `vs0:/data/external/vitals/libssl.suprx` | `app0:lssl.suprx` ([vitals-app/assets/lssl.suprx](../vitals-app/assets/lssl.suprx)) | `install_http_modules`, [install.c:919](../vitals-app/install.c#L919) |

Sony's own `vs0:sys/external/libssl.suprx` is never modified; the replacement happens at load
time. Uninstalling removes vitals' copy with the HTTP modules
([install.c:871](../vitals-app/install.c#L871)).

## 2. Boot

The kernel plugin's `add_replace_flags` ([vitals-plugin/main.c:50](../vitals-plugin/main.c#L50))
looks for vitals' libhttp and libssl. `g_replace_iap` is set only when **both** exist
([main.c:56](../vitals-plugin/main.c#L56)): the two libraries are always swapped together, so a
process never pairs vitals' libhttp with Sony's libssl or the other way round. The rest of the
boot is in [libhttp.md](libhttp.md), section 2.

## 3. A process asks for libssl: the load hook

libssl usually comes in with the HTTPS system module, since libhttp imports its `SceSsl` library
(`0xCAF5F2E9`). Like every load, it reaches `load_for_pid_patched`
([main.c:67](../vitals-plugin/main.c#L67)):

1. **Path swap** — `vs0:sys/external/libssl.suprx` or `vs0:/sys/external/libssl.suprx` becomes
   `vs0:/data/external/vitals/libssl.suprx` ([main.c:84-88](../vitals-plugin/main.c#L84-L88)). It is
   not logged.
2. **Flags left alone** — unlike libhttp, the shared request in the loader's flags is never
   cleared ([main.c:96-101](../vitals-plugin/main.c#L96-L101)), whatever the process. No HTTP policy
   is asked.
3. **The real load** — `TAI_CONTINUE` ([main.c:103](../vitals-plugin/main.c#L103)). libssl is mapped
   in the **shared** region: one copy of its code, at one address, for every process that uses it,
   each process with its own data. Your logs show it at `text=0xe064a440` in one boot and
   `0xe0689c40` in another.
4. **Nothing queued** — no injection follows a libssl load
   ([main.c:107-115](../vitals-plugin/main.c#L107-L115)).

## 4. Linking

A private libhttp (in a game) links to the shared libssl's exports like any module linking to a
shared library. libssl itself doesn't change.

libssl's library ID also matters to the HTTP policy: `vitals_native_http_shared_consumer`
([native_module_api.c:136](../vitals-plugin/native_module_api.c#L136)) treats a shared module that
imports `SceSsl` (or `SceHttp`) the same way: that process keeps a shared libhttp and Sony's TLS
([libhttp.md](libhttp.md), section 3).

## 5. Never hooked

Neither the kernel plugin nor the HTTP provider patches libssl:

- **The provider doesn't need to.** Its TLS is Mbed TLS, reached through its hooks on the private
  libhttp ([libhttp.md](libhttp.md), section 5).
- **It would reach every process.** libssl is a single shared copy, so a patch in it would apply
  to all processes using it.
- **It's said in the code**: [cert_hooks.c:261-262](../tls13-vita/provider/cert_hooks.c#L261-L262),
  *"libssl stays Sony's shared copy, which must not be hooked"*.

libssl's sizes and the offsets of its certificate getters are still kept in
[sony_abi.h:19](../tls13-vita/include/vitals/sony_abi.h#L19) and
[sony_abi.h:28-35](../tls13-vita/include/vitals/sony_abi.h#L28-L35), unused.

## 6. When libssl does the TLS

- **Connections the provider declines** in a game: `vitals_transport_create`
  ([transport.c:399](../tls13-vita/provider/transport.c#L399)) returns without handling them when
  the provider isn't active, after the game loaded a client certificate or key or unreadable CA
  certificates (`sceHttpsLoadCert`, [cert_hooks.c:140](../tls13-vita/provider/cert_hooks.c#L140)),
  or for an invalid connection. libhttp's original code then uses libssl ("BSAFE" in the code's
  comments).
- **Every connection of the processes without the provider**: the shell, the browser and its
  WebKit helper, processes with a shared HTTP/SSL importer, and Adrenaline
  ([libhttp.md](libhttp.md), section 7).
- **Apps and system code calling `sceSsl` directly.**

In all of these, the swapped libssl does the TLS exactly as Sony's would, with the system's
certificate store (`vs0:/data/external/cert/CA_LIST.cer`, which vitals' installer updates).

## 7. Why shared, and what it costs

- **Memory** — a private copy costs each game about 440 KiB
  ([main.c:98-99](../vitals-plugin/main.c#L98-L99)), on a console where games have little to spare.
- **Game certificate callbacks get an empty list** — when a game installs its own certificate
  callback and the provider handles the connection, `vitals_cert_callback_decide`
  ([cert_hooks.c:244-268](../tls13-vita/provider/cert_hooks.c#L244-L268)) calls it with the
  verification result but no certificates (`NULL, 0`). Handing it the server's real certificates
  would mean hooking libssl's certificate getters, which needs a private libssl. Games whose
  callback only looks at the verification result behave as before; a game that reads the
  certificate itself (its subject or issuer, say, to pin a server) gets nothing to read.

**How tls_fixer did it**: tls_fixer, which vitals derives from, cleared the shared flags on libssl
as well as libhttp in every process allowed the provider ("Stateful user hooks require private
HTTP/SSL code"), and hooked eight of libssl's certificate getters (subject, issuer, serial,
validity dates, names), so game callbacks received the real certificates. It refused to hook a
libssl that wasn't private. vitals dropped both to save the memory.

## 8. The end

libssl is unloaded when the last process using it unloads it or exits. Since it is never hooked,
there is nothing of vitals' to release.

## 9. Files

| File | Role |
|---|---|
| [vitals-plugin/main.c](../vitals-plugin/main.c) | the path swap; libssl's flags left shared |
| [vitals-plugin/native_module_api.c](../vitals-plugin/native_module_api.c) | `SceSsl` importers in the HTTP policy |
| [tls13-vita/provider/cert_hooks.c](../tls13-vita/provider/cert_hooks.c) | the certificate callback, with its empty list |
| [tls13-vita/provider/transport.c](../tls13-vita/provider/transport.c) | when connections are left to libssl |
| [tls13-vita/include/vitals/sony_abi.h](../tls13-vita/include/vitals/sony_abi.h) | libssl's size and getter offsets (unused) |
| [vitals-app/install.c](../vitals-app/install.c) | putting the file on the console |
