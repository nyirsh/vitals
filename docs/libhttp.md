# libhttp in vitals: its whole lifetime

This document follows Sony's HTTP library (`SceLibHttp`, `libhttp.suprx`) through vitals: how it
gets onto the console, how it is loaded into memory, how vitals takes over its TLS, what happens
to each HTTPS request, and how it all ends. Every step names the code that does it. Its
companions are [libssl.md](libssl.md) (Sony's SSL library, which libhttp links to),
[reauth.md](reauth.md) (the PSN redirect module that follows the shell's libhttp) and
[browser.md](browser.md) (the browser, which has its own networking and its own provider).

In one paragraph: the kernel plugin swaps libhttp for vitals' bundled copy whenever a process
loads it, and loads it as a **private** copy in processes that may use the HTTP provider. Once
that private libhttp has started, the kernel plugin injects the HTTP provider
(`vitals_http.suprx`) into the process. The provider checks it really has a private, known
libhttp, and hooks six of libhttp's internal TLS functions plus a few of its exports. From then on
Mbed TLS does the TLS of that process's libhttp connections. Everything lives until the process
exits.

## At a glance

| Module | File loaded | Loaded when | Into | Shared or private | Until |
|---|---|---|---|---|---|
| `SceLibHttp` (vitals' copy) | `vs0:/data/external/vitals/libhttp.suprx`, in place of `vs0:sys/external/libhttp.suprx` | a process loads Sony's libhttp, usually with the HTTPS system module | that process | **private** in apps the HTTP policy allows; **shared** in the shell, the browser and the other refused processes (section 3) | a private copy: the process unloads it or exits; a shared one: the last process using it |
| `vitals_http` (the HTTP provider) | `vs0:/data/external/vitals/native/vitals_http.suprx` | right after that private libhttp has started, once per process | that process, in its private memory (below `0xE0000000`), with a 128 KiB heap block | private | the process exits; it never unloads |

## 1. On disk

| File on the console | Comes from | Installed by |
|---|---|---|
| `vs0:/data/external/vitals/libhttp.suprx` | `app0:lhttp.suprx` ([vitals-app/assets/lhttp.suprx](../vitals-app/assets/lhttp.suprx)) | `install_http_modules`, [install.c:915](../vitals-app/install.c#L915) |
| `vs0:/data/external/vitals/native/vitals_http.suprx` | the HTTP provider, built from [tls13-vita/provider/](../tls13-vita/provider/) | same function, [install.c:871](../vitals-app/install.c#L871) |
| `ur0:tai/vitals.skprx` | the kernel plugin, built from [vitals-plugin/](../vitals-plugin/) | `install_plugin` |
| `vs0:/data/external/cert/CA_LIST.cer` | the certificate bundle the provider trusts | `install_certificates` |

Sony's own `vs0:sys/external/libhttp.suprx` is never modified; the replacement happens at load
time. A leftover `vs0:sys/external/libhttp.supr0` from older tools is removed
([install.c:876](../vitals-app/install.c#L876)), and while it exists vitals doesn't count as
installed ([install.c:1057](../vitals-app/install.c#L1057)).

The bundled `lhttp.suprx` is a fixed, known binary: the kernel plugin checks its SHA-256 and the
provider checks its segment sizes and code bytes (below). That is what lets the provider hook it
at fixed offsets on both 3.60 and 3.65.

## 2. Boot: the kernel plugin gets ready

taiHEN loads `vitals.skprx` from `config.txt`'s `*KERNEL` section. Its `module_start`
([vitals-plugin/main.c:132](../vitals-plugin/main.c#L132)):

1. **Which replacements exist** — `add_replace_flags` ([main.c:50](../vitals-plugin/main.c#L50))
   checks each file in `g_replacement_modules` ([main.c:36](../vitals-plugin/main.c#L36)).
   `g_replace_iap` is set only when both the libhttp **and** the libssl replacements exist: the two
   are always swapped together or not at all ([libssl.md](libssl.md)). With nothing to replace, the
   plugin stops here.
2. **Kernel module-manager functions** — `vitals_native_module_api_init`
   ([native_module_api.c:18](../vitals-plugin/native_module_api.c#L18)) resolves get-info, get-list,
   unload and is-shared from `SceModulemgrForKernel`, with each firmware family's library and NIDs
   (3.60: `0xc445fa63`, 3.65: `0x92c9ffc2`).
3. **Loader readiness** — `vitals_kernel_loader_init`
   ([tls13_loader.c:271](../vitals-plugin/tls13_loader.c#L271)) runs `target_matches`
   ([tls13_loader.c:258](../vitals-plugin/tls13_loader.c#L258)) for the HTTP target: the provider
   file must exist and the replacement libhttp's SHA-256 (`hash_file_sha256`,
   [tls13_loader.c:148](../vitals-plugin/tls13_loader.c#L148)) must equal
   `g_expected_libhttp_sha256` ([tls13_loader.c:45](../vitals-plugin/tls13_loader.c#L45)). Only then
   is `ready[0]` set. Without it libhttp is still swapped and made private, but no provider is
   injected.
4. **The PSN redirect module** — `vitals_reauth_init` ([reauth.md](reauth.md)).
5. **Two hooks on the module manager** — `vitals_validate_loader_hook`
   ([hook_guard.c:94](../vitals-plugin/hook_guard.c#L94)) first checks the module manager's code
   bytes at the hook points (with variants for 3.60 and 3.65), then
   ([main.c:157-162](../vitals-plugin/main.c#L157-L162)):
   - the **start hook** at offset `0x286c` → `start_for_pid_patched`
   - the **load hook** at offset `0x21ec` → `load_for_pid_patched`

   (offsets in [hook_guard.h](../vitals-plugin/hook_guard.h)). Every module any process loads now
   passes through these two functions.

## 3. A process asks for libhttp: the load hook

Apps normally get libhttp by loading the HTTPS system module
(`sceSysmoduleLoadModule(SCE_SYSMODULE_HTTPS)`, as the app's own connection test does in
[check.c](../vitals-app/check.c)). The load reaches `load_for_pid_patched`
([main.c:67](../vitals-plugin/main.c#L67)) in kernel context, with the process (`pid`, 0 meaning
the caller), the requested path and the loader's flags.

1. **Decided on the requested path** ([main.c:74-75](../vitals-plugin/main.c#L74-L75)): whether it
   is Sony's libhttp, and whether vitals-reauth should follow it (shell only, [reauth.md](reauth.md)).
2. **Path swap** — `vs0:sys/external/libhttp.suprx`, `vs0:/sys/external/libhttp.suprx` or reAuth's
   old `ur0:data/reAuth/libhttp.suprx` become `vs0:/data/external/vitals/libhttp.suprx`
   ([main.c:77-83](../vitals-plugin/main.c#L77-L83)); logged as `vitals: libhttp load pid=…
   flags=… path=…`.
3. **Shared or private** ([main.c:96-101](../vitals-plugin/main.c#L96-L101)): the loader's flags
   normally ask for a shared mapping (`0x08000001`, `VITALS_SHARED_LOAD_FLAGS`; your logs show
   libhttp requested with `0x08008001`). They are cleared — a private copy — when
   `vitals_kernel_http_process_allowed` says the process may have the provider.
4. **The HTTP policy** — `vitals_kernel_http_process_allowed`
   ([tls13_loader.c:546](../vitals-plugin/tls13_loader.c#L546)) refuses:
   - the **shell** (`ksceKernelSysrootGetShellPid`): its libhttp is shared with other Sony code, and
     a private copy fails there with `0x8002D018` (`CANNOT_EXPORT_LIB_TO_SHARED`)
   - the **browser** (`NPXS10003`) and its **WebKit helper** (`NPXS10083`), which use the browser
     provider instead
   - any process where `vitals_native_http_shared_consumer`
     ([native_module_api.c:77-159](../vitals-plugin/native_module_api.c#L77-L159)) finds a shared
     module importing `SceHttp` (`0xE8F15CDE`) or `SceSsl` (`0xCAF5F2E9`): that module linked to the
     shared copies once, and couldn't use a private one. It walks the process's module list
     (skipping SceLibHttp, SceLibSsl and vitals_http themselves), reads each module's import table,
     and asks the kernel whether an importer's code is shared
   - **Adrenaline**: a process running `ScePspemu` ([native_module_api.c:98-108](../vitals-plugin/native_module_api.c#L98-L108)),
     whose PSP emulator crashes on a private libhttp with the provider loaded

   Refused processes still get vitals' libhttp file, but **shared** and without the provider: their
   TLS stays Sony's, through libssl.
5. **The real load** — `TAI_CONTINUE(…, pid, path, flags, …)`
   ([main.c:103](../vitals-plugin/main.c#L103)) runs Sony's loader with the swapped path and
   adjusted flags. A private libhttp lands in the process's own memory, below `0xE0000000`; a
   shared one in the shared region, at the same address in every process using it.
6. **Queue the injection** ([main.c:107-115](../vitals-plugin/main.c#L107-L115)): when `ready[0]`
   is set, `vitals_post_start_defer_http(pid, module)`
   ([post_start.c:109](../vitals-plugin/post_start.c#L109)) records the process and libhttp's
   module ID in a small table (`defer_target`, [post_start.c:59](../vitals-plugin/post_start.c#L59)).
   Nothing is injected yet: the library hasn't linked or started.

## 4. libhttp has started: injecting the provider

When the loader starts a module, `start_for_pid_patched` ([main.c:119](../vitals-plugin/main.c#L119))
first lets Sony's start run (linking the imports, running `module_start`), then calls
`vitals_post_start_complete(pid, module, result)` ([post_start.c:151](../vitals-plugin/post_start.c#L151)).
For a queued libhttp whose start succeeded it calls `vitals_kernel_inject_for_pid`
([post_start.c:188](../vitals-plugin/post_start.c#L188)), logged as `vitals: post_start pid=…
mod=… native=… http=1 reauth=…`.

`vitals_kernel_inject_for_pid` ([tls13_loader.c:570](../vitals-plugin/tls13_loader.c#L570)) asks the
policy again (logged `vitals: http policy pid=… allowed=…`; your logs show `allowed=0` for system
apps), then runs `inject_target` on a 16 KiB stack of its own (`dispatch_preparation`,
[tls13_loader.c:537](../vitals-plugin/tls13_loader.c#L537)). `inject_target`
([tls13_loader.c:312](../vitals-plugin/tls13_loader.c#L312)):

1. **One injection per process at a time** — the process is recorded in `in_flight` under the
   injection mutex ([tls13_loader.c:358](../vitals-plugin/tls13_loader.c#L358)).
2. **Lookup workspace** — a 4 KiB kernel memory block, so the nested loader's small stack isn't used.
3. **Not already there** — `provider_is_loaded_by_name`
   ([tls13_loader.c:243](../vitals-plugin/tls13_loader.c#L243)): `SceLibHttp` must be found in the
   process, and `vitals_http` must not be. A provider that is already resident is left alone
   ([tls13_loader.c:380-387](../vitals-plugin/tls13_loader.c#L380-L387), section 8).
4. **Still the right files** — `target_matches` again (provider present, libhttp hash).
5. **Still the right module** — the module ID handed over must be `SceLibHttp`, the same one the
   name lookup found, with a code segment.
6. **Start arguments** — `VitalsStartArgs` (magic `0x49544C53`, version 1, libhttp's module ID;
   [sony_abi.h:89](../tls13-vita/include/vitals/sony_abi.h#L89)) are written into a 4 KiB user
   memory block allocated for that process, then read back to confirm.
7. **Load and start** — `ksceKernelLoadStartModuleForPid(pid, VITALS_HTTP_PROVIDER_PATH, …)`
   ([tls13_loader.c:470](../vitals-plugin/tls13_loader.c#L470)). The provider is loaded privately
   into the process (no shared flags). If its `module_start` doesn't return success, it is unloaded
   again ([tls13_loader.c:485-490](../vitals-plugin/tls13_loader.c#L485-L490)).
8. **Cleanup** — the argument and workspace blocks are freed, the `in_flight` slot cleared. Logged
   as `vitals: inject target=0 pid=… rc=…`.

## 5. The provider starts: checks, heap, hooks

`module_start` in [tls13-vita/provider/provider.c:368](../tls13-vita/provider/provider.c#L368)
runs inside the app's process. Any failure undoes what came before and returns
`SCE_KERNEL_START_FAILED`, so the kernel plugin unloads it and the app keeps Sony's TLS.

1. **Start arguments** — `vitals_http_validate_start_args` ([provider.c:224](../tls13-vita/provider/provider.c#L224)).
2. **The libhttp it was given** — `vitals_http_validate_module` ([provider.c:241](../tls13-vita/provider/provider.c#L241)):
   - named `SceLibHttp`, code exactly `0x1D150` bytes, data `0x5A4`/`0x640`
     ([sony_abi.h:15-17](../tls13-vita/include/vitals/sony_abi.h#L15-L17))
   - code **below `0xE0000000`** — a shared copy is refused (`event=module.gate
     reason=shared_text`, [provider.c:273](../tls13-vita/provider/provider.c#L273))
   - code and data **privately mapped**, asked of the user Sysmem API
     (`vitals_require_private_mapping`, [private_mapping.c:6](../tls13-vita/provider/private_mapping.c#L6);
     `reason=nonprivate_mapping`)
   - the code bytes at each hook point match their signatures (`g_libhttp_signatures`,
     [provider.c:43](../tls13-vita/provider/provider.c#L43))
   - the four import veneers the certificate policy calls are at their places
     (`vitals_cert_policy_bind`, [cert_policy.c:30](../tls13-vita/src/cert_policy.c#L30))
3. **Heap** — `vitals_user_runtime_init` ([user_runtime.c:23](../tls13-vita/provider/user_runtime.c#L23))
   allocates one user memory block (`vitals HTTP heap`, `VITALS_HTTP_HEAP_KIB`, 128 KiB by
   default, set in [tls13-vita/Makefile](../tls13-vita/Makefile)) and makes it an `sceClib` mspace;
   all of the provider's and Mbed TLS's allocations come from it.
4. **TLS state** — `vitals_transport_global_init` ([transport.c:77](../tls13-vita/provider/transport.c#L77)):
   the connection registry and its mutex, then `vitals_trust_store_init`
   ([trust_store.c:23](../tls13-vita/provider/trust_store.c#L23)): crypto platform, PSA, and an
   **index** of `CA_LIST.cer` (the path converted for the process's `vs0:` view). Roots are parsed
   only when a handshake needs them.
5. **Certificate hooks** — `vitals_cert_hooks_install` ([cert_hooks.c:187](../tls13-vita/provider/cert_hooks.c#L187))
   hooks two libhttp exports (library `0xE8F15CDE`):
   - `sceHttpsLoadCert` (`0xAE8D7C33`) — `hook_https_load_cert` ([cert_hooks.c:140](../tls13-vita/provider/cert_hooks.c#L140)):
     a game's own CA certificates are parsed and trusted too; a client certificate or key, or
     certificates that can't be parsed, switch new connections to Sony's TLS
   - `sceHttpsUnloadCert` (`0x8577833F`) — `hook_https_unload_cert` ([cert_hooks.c:174](../tls13-vita/provider/cert_hooks.c#L174)):
     forgets them and switches back

   With debug output on, the request trace hooks ([http_trace.c](../tls13-vita/provider/http_trace.c))
   are installed here as well.
6. **The six TLS hooks** — `vitals_http_install_hooks` ([provider.c:328](../tls13-vita/provider/provider.c#L328))
   hooks internal libhttp functions by offset (`taiHookFunctionOffset`, Thumb), in the private
   copy only:

   | Hook | Offset ([sony_abi.h:21-26](../tls13-vita/include/vitals/sony_abi.h#L21-L26)) | Goes to |
   |---|---|---|
   | create (a connection's TLS session) | `0x8130` | `vitals_transport_create` |
   | connect (the handshake) | `0x8362` | `vitals_transport_connect` |
   | map_io (I/O error mapping) | `0x85FE` | `vitals_transport_map_io` |
   | read | `0x869C` | `vitals_transport_read` |
   | write | `0x86F4` | `vitals_transport_write` |
   | shutdown | `0x874C` | `vitals_transport_shutdown` |

   Each hook function (`hook_create` and the others in [provider.c](../tls13-vita/provider/provider.c))
   calls the transport, and continues into libhttp's original code when the transport says the
   connection isn't its own (`handled == 0`).
7. **Host redirects** — `vitals_host_redirect_install`
   ([host_redirect.c:175](../tls13-vita/provider/host_redirect.c#L175)) reads the redirect list
   through the kernel plugin's `vitals_redirects_read` system call; only if it has rules does it
   hook `sceHttpCreateConnection` (`0xAEB3307E`), `sceHttpCreateConnectionWithURL` (`0xC616C200`)
   and `sceHttpCreateRequestWithURL` (`0xBD5DA1D0`) ([host_redirect.c:103-105](../tls13-vita/provider/host_redirect.c#L103-L105)).
   Optional: it never stops the provider.
8. **Active** — `g_vitals_http.state = VITALS_PROVIDER_ACTIVE` ([provider.c:453](../tls13-vita/provider/provider.c#L453)).

## 6. One HTTPS request

```
app ─ sceHttpCreateConnectionWithURL ─▶ redirect hook (host swapped if listed) ─▶ libhttp
app ─ sceHttpSendRequest ─▶ libhttp opens the TCP socket itself, then:
        create  ─▶ vitals_transport_create   Mbed TLS session for this connection, or decline
        connect ─▶ vitals_transport_connect  TLS 1.2/1.3 handshake on the app's socket
        write / read ─▶ vitals_transport_write / _read   records via sceNetSend / sceNetRecv
        shutdown ─▶ vitals_transport_shutdown   close_notify, session removed
     declined at create ─▶ libhttp's original code ─▶ libssl (Sony's TLS, "BSAFE" in the code)
```

- **Create** — `vitals_transport_create` ([transport.c:399](../tls13-vita/provider/transport.c#L399))
  declines (Sony's TLS handles the connection) when the provider isn't active, when a game loaded
  certificate material it can't use (`vitals_legacy_certificates_loaded`), or for an invalid
  connection or socket. Otherwise it allocates a `VitalsConnection` from the provider heap, takes
  the effective HTTPS options (the connection's, or libhttp's global ones at data offset `0xF4`),
  sets up Mbed TLS (`setup_connection`, [transport.c:223](../tls13-vita/provider/transport.c#L223):
  TLS 1.2 to 1.3, SHA-1 signatures allowed for Sony's own servers, roots looked up through the CA
  index, exact self-signed certificates trusted, the connection's hostname for SNI and checks),
  and registers it under libhttp's connection pointer.
- **Connect** — `vitals_transport_connect` ([transport.c:518](../tls13-vita/provider/transport.c#L518))
  runs `mbedtls_ssl_handshake`. Would-block results are returned the way libhttp expects for
  non-blocking requests; failures are stored as Sony SSL errors on the connection (the app reads
  them with `sceHttpsGetSslError`). After a handshake, `complete_verification`
  ([transport.c:302](../tls13-vita/provider/transport.c#L302)) maps Mbed TLS's verification flags
  to Sony's detail bits, filtered by the connection's options, and asks
  `vitals_cert_callback_decide` ([cert_hooks.c:244](../tls13-vita/provider/cert_hooks.c#L244)):
  without a game callback, any remaining problem rejects the connection; with one, the game's
  callback is called with the verification detail and **an empty certificate list**
  ([cert_hooks.c:261-265](../tls13-vita/provider/cert_hooks.c#L261-L265); why: [libssl.md](libssl.md)),
  and its answer goes through the compatibility policy.
- **Read and write** — `vitals_transport_read` / `_write`
  ([transport.c:667](../tls13-vita/provider/transport.c#L667),
  [transport.c:743](../tls13-vita/provider/transport.c#L743)): `mbedtls_ssl_read` / `_write` in
  chunks of at most 1500 bytes, over the app's own socket through `vitals_vita_send` /
  `vitals_vita_recv` ([vita_net.c:21](../tls13-vita/provider/vita_net.c#L21),
  [vita_net.c:55](../tls13-vita/provider/vita_net.c#L55)). Post-handshake TLS 1.3 records (session
  tickets) are consumed without reporting a timeout.
- **map_io** — `vitals_transport_map_io` ([transport.c:609](../tls13-vita/provider/transport.c#L609))
  turns would-block into libhttp's internal retry code.
- **Shutdown** — `vitals_transport_shutdown` ([transport.c:822](../tls13-vita/provider/transport.c#L822))
  sends `close_notify` when the connection was healthy and removes it from the registry; its
  memory is freed when the last user lets go.

## 7. Processes that work differently

| Process | libhttp | Provider | Notes |
|---|---|---|---|
| Games and most apps | vitals' copy, **private** | injected | the path above |
| The shell (`main`) | vitals' copy, **shared** | no | Sony's TLS; vitals-reauth redirects its PSN sign-in ([reauth.md](reauth.md)) |
| Browser (`NPXS10003`), WebKit helper (`NPXS10083`) | vitals' copy, shared | no | the browser provider handles their TLS ([browser.md](browser.md)) |
| Processes with a shared HTTP/SSL importer | vitals' copy, shared | no | `vitals_native_http_shared_consumer` |
| Adrenaline (`ScePspemu`) | vitals' copy, shared | no | crashes with a private copy |

## 8. The end

- **The provider never unloads**: its `module_stop` refuses
  ([provider.c:463-469](../tls13-vita/provider/provider.c#L463-L469)), because a thread can still be
  inside one of its hooks. It stays until the process exits.
- **libhttp unloaded and loaded again in the same process**: the provider stays with the first
  copy; the new one is left to Sony's TLS ([tls13_loader.c:380-387](../vitals-plugin/tls13_loader.c#L380-L387)).
- **Process exit**: the private libhttp, the provider, its heap, its hooks (taiHEN drops a
  process's hook records when it exits) and every connection go away with the process. A shared
  libhttp stays for the other processes using it.
- **The kernel plugin never unloads** while its hooks are installed
  ([main.c:176-188](../vitals-plugin/main.c#L176-L188)); it lives until the console is turned off.

## 9. What the logs show

| Line | Printed by | Meaning |
|---|---|---|
| `vitals: loader init=… app=… browser=… iap=…` | kernel, boot | `app=1`: the HTTP provider can be injected |
| `vitals: libhttp load pid=… flags=… path=…` | kernel, load hook | a process asked for libhttp; flags as requested, before clearing |
| `[SceLibHttp]:text=0x…` | the log tool's module list | `0xe…`: shared copy; lower: private |
| `vitals: post_start pid=… http=1 …` | kernel, start hook | libhttp started; injection follows |
| `vitals: http policy pid=… allowed=…` | kernel | `0`: Sony's TLS for this process |
| `vitals: inject target=0 pid=… rc=…` | kernel | the provider's load result; `0x8002D000` is a failed start |
| `vitals_http: …` | provider | its own start-up and per-connection logs, with debug output on |
| `vitals: provider already resident …` | kernel | a second libhttp in the same process, left to Sony's TLS |

## 10. Files

| File | Role |
|---|---|
| [vitals-plugin/main.c](../vitals-plugin/main.c) | load and start hooks, path swaps, private flags |
| [vitals-plugin/hook_guard.c](../vitals-plugin/hook_guard.c) | checks the module manager before hooking it |
| [vitals-plugin/post_start.c](../vitals-plugin/post_start.c) | the queue between a load and its start |
| [vitals-plugin/tls13_loader.c](../vitals-plugin/tls13_loader.c) | HTTP policy, hashes, provider injection |
| [vitals-plugin/native_module_api.c](../vitals-plugin/native_module_api.c) | module-manager functions, shared-consumer check |
| [tls13-vita/include/vitals/sony_abi.h](../tls13-vita/include/vitals/sony_abi.h) | libhttp's sizes, offsets, structure fields, error codes |
| [tls13-vita/provider/provider.c](../tls13-vita/provider/provider.c) | provider start, libhttp checks, the six hooks |
| [tls13-vita/provider/transport.c](../tls13-vita/provider/transport.c) | the TLS of each connection |
| [tls13-vita/provider/cert_hooks.c](../tls13-vita/provider/cert_hooks.c) | game certificates, certificate callbacks |
| [tls13-vita/provider/host_redirect.c](../tls13-vita/provider/host_redirect.c) | host redirects |
| [tls13-vita/provider/trust_store.c](../tls13-vita/provider/trust_store.c), [ca_index.c](../tls13-vita/provider/ca_index.c) | the certificate store |
| [tls13-vita/provider/user_runtime.c](../tls13-vita/provider/user_runtime.c) | the provider heap |
| [tls13-vita/provider/vita_net.c](../tls13-vita/provider/vita_net.c) | sending and receiving on the app's socket |
| [vitals-app/install.c](../vitals-app/install.c) | putting the files on the console |
