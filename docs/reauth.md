# vitals-reauth: its whole lifetime

This document follows vitals-reauth (`vitals-reauth.suprx`), the small module that sends PSN
sign-in and the Store to their new hosts. It is based on Reiko Asakura's reAuth, and is built
into vitals instead of being a separate plugin. Its companions are [libhttp.md](libhttp.md),
[libssl.md](libssl.md) and [browser.md](browser.md).

In one paragraph: Sony moved PSN sign-in from `native.np.ac.playstation.net` to
`native-vita.np.ac.playstation.net`, but old firmware still asks for the old host. The shell (for
sign-in) and apps using the Store library don't get the HTTP provider's redirect, so the kernel
plugin loads vitals-reauth into them right after the library it follows has started. vitals-reauth
reads the host redirect list through the kernel plugin, and hooks that module's own import of
`sceHttpCreateConnection`, rewriting listed host names. It changes nothing else, and lives until
the process exits.

## At a glance

| Module | File loaded | Loaded when | Into | Shared or private | Until |
|---|---|---|---|---|---|
| `vitals_reauth` | `vs0:/data/external/vitals/native/vitals-reauth.suprx` | right after the shell's libhttp, or an app's Store library (`SceNpCommerce2`), has started; once per process | that process | private | the process exits; or at once, when it finds nothing to hook |

## 1. On disk

| File on the console | Comes from | Installed by |
|---|---|---|
| `vs0:/data/external/vitals/native/vitals-reauth.suprx` | built from [vitals-reauth/](../vitals-reauth/), packaged as `app0:vitals-reauth.suprx` | `install_http_modules`, [install.c:911](../vitals-app/install.c#L911) |
| `ux0:data/vitals/redirects.txt` | the starter list, [vitals-app/assets/redirects.txt](../vitals-app/assets/redirects.txt), copied only if there is none | same function |

- **Debug builds** — vitals-reauth is built at debug levels 0, 1 and 2
  ([vitals-reauth/CMakeLists.txt](../vitals-reauth/CMakeLists.txt), `VITALS_DEBUG`); the app carries
  all three, and the Debug output menu replaces the installed one with the chosen level's
  ([install.c:1160-1161](../vitals-app/install.c#L1160-L1161)). Level 0 logs nothing; levels 1 and 2
  log each hook and redirect (`REAUTH_LOG`, [vitals-reauth/main.c:10](../vitals-reauth/main.c#L10)).
- **The original reAuth** — installing vitals removes Reiko Asakura's reAuth plugin, its
  `config.txt` line and its files (`remove_reauth_install`, [install.c:751](../vitals-app/install.c#L751)):
  both would take over the same libhttp loads.
- **Uninstalling** removes vitals-reauth with the HTTP modules ([install.c:887](../vitals-app/install.c#L887)).
  The redirect list is the user's and is left.

## 2. The redirect list

`ux0:data/vitals/redirects.txt` holds one `old-host new-host` pair per line; `#` starts a comment,
and lines that aren't exactly two valid host names are skipped (`vitals_host_map_parse_line`,
[host_map.c:56](../tls13-vita/src/host_map.c#L56)). The starter list holds the PSN pair.

- **Read through the kernel** — apps and games run in a sandbox that refuses `ux0:data`
  (`0x80010013`), so the list is read with the kernel plugin's system call `vitals_redirects_read`
  ([vitals-plugin/redirects.c:12](../vitals-plugin/redirects.c#L12)): it opens the file afresh for
  each read and copies at most 256 bytes into the caller's memory. The kernel plugin exports it as
  library `vitals_redirects` ([vitals.yml.in](../vitals-plugin/vitals.yml.in)), and its build
  generates the stub vitals-reauth links (`libvitals_kernel_stub.a`,
  [vitals-reauth/CMakeLists.txt:14](../vitals-reauth/CMakeLists.txt#L14)).
- **Parsed with the HTTP provider's code** — `vitals_redirect_list_read`
  ([redirect_list.c:24](../tls13-vita/src/redirect_list.c#L24)) reads it in pieces and passes each
  valid pair on; vitals-reauth links the same `host_map.c` and `redirect_list.c` as the provider
  ([vitals-reauth/CMakeLists.txt:19](../vitals-reauth/CMakeLists.txt#L19)).
- **Read once per process**, when vitals-reauth starts: changes apply to the next process that
  loads it.

## 3. Boot: the kernel plugin gets ready

The kernel plugin's `module_start` calls `vitals_reauth_init`
([vitals-plugin/reauth.c:21](../vitals-plugin/reauth.c#L21)), logged as `vitals: reauth ready=…`:
when `vs0:/data/external/vitals/native/vitals-reauth.suprx` exists
([reauth.c:13](../vitals-plugin/reauth.c#L13)), it creates the mutex that keeps injections one at a
time, and redirects are possible. Otherwise vitals-reauth is never loaded. `vitals_reauth_destroy`
([reauth.c:33](../vitals-plugin/reauth.c#L33)) undoes it when the plugin's start fails.

## 4. When it is wanted: the load hook

Every module load passes through the kernel plugin's `load_for_pid_patched`
([vitals-plugin/main.c:67](../vitals-plugin/main.c#L67)), which asks `vitals_reauth_wanted` about
the path the process asked for, before any swap ([main.c:74-75](../vitals-plugin/main.c#L74-L75)).
`vitals_reauth_wanted` ([reauth.c:60](../vitals-plugin/reauth.c#L60)) says yes for:

- **the shell's libhttp** — Sony's libhttp loaded by the process `ksceKernelSysrootGetShellPid`
  names; the shell signs in to PSN
- **the Store library in any other process** — a `vs0:` path containing `commerce2`, any case
  (`is_store_library`, [reauth.c:43](../vitals-plugin/reauth.c#L43)). The match is loose on purpose:
  vitals-reauth checks for itself that `SceNpCommerce2` really is loaded before hooking anything.

When the real load succeeds, `vitals_post_start_defer_reauth(pid, module)`
([main.c:113-115](../vitals-plugin/main.c#L113-L115), [post_start.c:114](../vitals-plugin/post_start.c#L114))
queues it. In the shell, the same entry also carries the HTTP provider's injection, which the HTTP
policy then refuses (`vitals: http policy … allowed=0`, [libhttp.md](libhttp.md), section 3): the
shell keeps vitals' libhttp shared, with Sony's TLS, and only vitals-reauth is loaded.

## 5. The module has started: injecting vitals-reauth

Once the trigger module has linked and started, `start_for_pid_patched`
([main.c:119](../vitals-plugin/main.c#L119)) calls `vitals_post_start_complete`
([post_start.c:151](../vitals-plugin/post_start.c#L151)), which calls `vitals_reauth_inject(pid)`
([post_start.c:194](../vitals-plugin/post_start.c#L194)); logged as `vitals: post_start pid=…
http=… reauth=1`. When an entry also carries a provider injection, the provider's result is the
one reported.

`vitals_reauth_inject` ([reauth.c:109](../vitals-plugin/reauth.c#L109)) takes the mutex and runs
`inject_on_stack` ([reauth.c:82](../vitals-plugin/reauth.c#L82)) on a 16 KiB stack of its own:

1. **The module it will hook is there** — `SceShell` in the shell, `SceNpCommerce2` elsewhere
   (`taiGetModuleInfoForKernel`). If not, nothing is loaded.
2. **Not already there** — only taiHEN's explicit "not found" for `vitals_reauth` lets it go on;
   one copy per process.
3. **Load and start** — `ksceKernelLoadStartModuleForPid(pid, VITALS_REAUTH_PATH, 0, NULL, 0, …)`
   ([reauth.c:102](../vitals-plugin/reauth.c#L102)): a private, ordinary user module in that
   process, with no start arguments. Logged as `vitals: reauth pid=… target=… mod=… status=…`.

## 6. vitals-reauth starts: rules and its hook

`module_start` in [vitals-reauth/main.c:109](../vitals-reauth/main.c#L109) runs in the process:

1. **Which module to hook** — the first of `SceShell` and `SceNpCommerce2` found in the process
   (`taiGetModuleInfo`).
2. **The rules** — `load_rules` ([main.c:67](../vitals-reauth/main.c#L67)) reads the list through
   `vitals_redirects_read`. `keep_rule` ([main.c:47](../vitals-reauth/main.c#L47)) copies each pair
   into a fixed 2 KiB buffer (`NAMES_SIZE`, [main.c:27](../vitals-reauth/main.c#L27); the module has
   no heap), up to the host map's limit with one place left free. A pair that no longer fits is
   skipped; a list that can't be read is left out entirely.
3. **The PSN rule** — unless the list redirects `native.np.ac.playstation.net` itself, the built-in
   rule to `native-vita.np.ac.playstation.net` ([main.c:23-24](../vitals-reauth/main.c#L23-L24)) is
   added, so sign-in works even with an empty or missing list.
4. **The hook** — `taiHookFunctionImport` on that module's import of `sceHttpCreateConnection`
   (library `0xE8F15CDE`, NID `0xAEB3307E`; [main.c:122](../vitals-reauth/main.c#L122)). Only calls
   made **by that module** are affected: an import hook patches the module's own import entry,
   not libhttp.
5. **Resident or not** — with its hook in place it stays (`SCE_KERNEL_START_SUCCESS`); without a
   target module or a hook it has nothing to do and returns `SCE_KERNEL_START_NO_RESIDENT`, so the
   loader unloads it right away.

## 7. One redirected connection

```
SceShell (or SceNpCommerce2) ─ sceHttpCreateConnection(template, "native.np.ac.playstation.net", …)
    ─▶ create_connection_hook: host on the list? ─▶ "native-vita.np.ac.playstation.net"
    ─▶ TAI_CONTINUE ─▶ libhttp's sceHttpCreateConnection with the new host
```

`create_connection_hook` ([main.c:92](../vitals-reauth/main.c#L92)) looks the host up in the rules
(`vitals_host_map_find`, [host_map.c:112](../tls13-vita/src/host_map.c#L112), without case) and
passes the new name on, or the original one. Logged as `vitals_reauth: redirected … to …` with debug
output on. The scheme, port and everything after are untouched, and the TLS of the connection is
whatever libhttp does in that process: Sony's, through libssl, in the shell
([libssl.md](libssl.md)); the HTTP provider's in an app that has it.

Only `sceHttpCreateConnection` is hooked: connections that module opens by URL
(`sceHttpCreateConnectionWithURL`) aren't redirected by vitals-reauth. In apps with the HTTP
provider, the provider's own redirect hooks cover all three ways of opening a connection
([libhttp.md](libhttp.md), section 5).

## 8. The end

- **No unload while running**: vitals-reauth stays until the process exits. Its `module_stop`
  ([main.c:131](../vitals-reauth/main.c#L131)) releases the hook if the module is ever stopped.
- **Process exit**: the module, its rules and its hook go away with the process.
- **List changes** apply to the next process that loads it, typically after a reboot for the shell.

## 9. What the logs show

| Line | Printed by | Meaning |
|---|---|---|
| `vitals: reauth ready=…` | kernel, boot | `1`: vitals-reauth is installed and can be injected |
| `vitals: post_start pid=… reauth=1` | kernel, start hook | the trigger module started; injection follows |
| `vitals: reauth pid=… target=… mod=… status=…` | kernel | the load result; `target` is SceShell or SceNpCommerce2 |
| `vitals_reauth: redirects loaded=…` | vitals-reauth, debug | how many rules, the PSN rule included |
| `vitals_reauth: hook SceShell rc=…` | vitals-reauth, debug | the import hook's result |
| `vitals_reauth: redirected … to …` | vitals-reauth, debug | one connection's host rewritten |

## 10. Files

| File | Role |
|---|---|
| [vitals-plugin/reauth.c](../vitals-plugin/reauth.c) | when to load vitals-reauth, and loading it |
| [vitals-plugin/main.c](../vitals-plugin/main.c) | the load and start hooks that trigger it |
| [vitals-plugin/post_start.c](../vitals-plugin/post_start.c) | the queue between a load and its start |
| [vitals-plugin/redirects.c](../vitals-plugin/redirects.c) | the system call that reads the list |
| [vitals-reauth/main.c](../vitals-reauth/main.c) | the rules, the PSN rule and the hook |
| [tls13-vita/src/redirect_list.c](../tls13-vita/src/redirect_list.c), [host_map.c](../tls13-vita/src/host_map.c) | reading and matching the list |
| [vitals-app/install.c](../vitals-app/install.c) | installing it, its debug builds, removing reAuth |
| [vitals-reauth/tests/test_reauth.c](../vitals-reauth/tests/test_reauth.c), [vitals-plugin/tests/test_reauth.c](../vitals-plugin/tests/test_reauth.c) | its host tests |
