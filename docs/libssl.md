# libssl in vitals

This document follows Sony's SSL library (`SceLibSsl`, `libssl.suprx`) through vitals. Its
companion is [browser.md](browser.md); apps and games use `vitals-http`, described in
[vitals-http.md](vitals-http.md).

In one paragraph: vitals swaps libssl for the copy bundled with the app whenever a process loads
it, leaves it **shared** and never hooks it. vitals' TLS doesn't run in libssl: `vitals-http`, which
replaces Sony's libhttp in every process, does its own TLS with Mbed TLS and doesn't import libssl
at all. libssl is left for apps and system code that call `sceSsl` directly.

## At a glance

| Module                     | File loaded                                                                           | Loaded when                   | Into                                                              | Shared or private | Until                                         |
| -------------------------- | ------------------------------------------------------------------------------------- | ----------------------------- | ----------------------------------------------------------------- | ----------------- | --------------------------------------------- |
| `SceLibSsl` (vitals' copy) | `vs0:/data/external/vitals/libssl.suprx`, in place of `vs0:sys/external/libssl.suprx` | a process loads Sony's libssl | every process that loads it, mapped once (at `0xE…` in your logs) | always **shared** | the last process using it unloads it or exits |

Nothing is injected after it, and nothing hooks it.

## 1. On disk

| File on the console                      | Comes from                                                                          | Installed by                                                   |
| ---------------------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `vs0:/data/external/vitals/libssl.suprx` | `app0:lssl.suprx` ([vitals-app/assets/lssl.suprx](../vitals-app/assets/lssl.suprx)) | `install_http_modules` in [install.c](../vitals-app/install.c) |

Sony's own `vs0:sys/external/libssl.suprx` is never modified; the replacement happens at load
time. Uninstalling removes vitals' copy with the HTTP modules.

## 2. Boot

The kernel plugin's `add_replace_flags` ([vitals-plugin/main.c](../vitals-plugin/main.c)) looks
for vitals' libhttp and libssl. `g_replace_iap` is set only when **both** exist: the two libraries
are always swapped together.

## 3. A process asks for libssl

Like every load, it reaches `load_for_pid_patched` ([main.c](../vitals-plugin/main.c)):

1. **Path swap**: `vs0:sys/external/libssl.suprx` or `vs0:/sys/external/libssl.suprx` becomes
   `vs0:/data/external/vitals/libssl.suprx`.
2. **Flags left alone**: the loader's shared mapping is kept, as for every replacement.
3. **The real load**: libssl is mapped in the **shared** region, one copy of its code for every
   process that uses it, each process with its own data.
4. **Nothing queued**: no injection follows a libssl load.

## 4. Never hooked

Nothing in vitals patches libssl: `vitals-http` doesn't use it, and since it is a single shared
copy, a patch would reach every process. libssl's sizes and the offsets of its certificate
getters are still kept in [sony_abi.h](../tls13-vita/include/vitals/sony_abi.h), unused.

## 5. The end

libssl is unloaded when the last process using it unloads it or exits. Since it is never hooked,
there is nothing of vitals' to release.

## 6. Files

| File                                            | Role                            |
| ----------------------------------------------- | ------------------------------- |
| [vitals-plugin/main.c](../vitals-plugin/main.c) | the path swap                   |
| [vitals-app/install.c](../vitals-app/install.c) | putting the file on the console |
