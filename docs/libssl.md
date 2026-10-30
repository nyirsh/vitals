# libssl in vitals

This document follows Sony's SSL library (`SceLibSsl`, `libssl.suprx`) through vitals. Its
companion is [browser.md](browser.md); apps and games use `vitals-http`, described in
[vitals-http.md](vitals-http.md).

In one paragraph: whenever a process loads libssl, vitals gives it [vitals-ssl](../vitals-ssl/),
Sony's library written from scratch on Mbed TLS, under Sony's own library and function NIDs. It is
left **shared** and never hooked. `vitals-http`, which replaces Sony's libhttp in every process,
does its TLS through this module as Sony's libhttp does through Sony's, in the pool the app gives
`sceSslInit`, with vitals' additions (the `VitalsSsl` library) for what Sony's libhttp reached into
libssl's structures for. Its import is weak, so processes that load libhttp without libssl
(Adrenaline's bubble booter and the browser's WebKit process do) still load it, and do no https,
as with Sony's. Apps and system code also call `sceSsl` directly (SceStoreBrowser and NpCommerce2
call `sceSslInit`, `sceSslTerm` and its pool's stats; the NetCheck dialog does its own TLS).

## At a glance

| Module                    | File loaded                                                                           | Loaded when                   | Into                                                              | Shared or private | Until                                         |
| ------------------------- | ------------------------------------------------------------------------------------- | ----------------------------- | ----------------------------------------------------------------- | ----------------- | --------------------------------------------- |
| `SceLibSsl` (vitals-ssl)  | `vs0:/data/external/vitals/libssl.suprx`, in place of `vs0:sys/external/libssl.suprx` | a process loads Sony's libssl | every process that loads it, mapped once (at `0xE…` in your logs) | always **shared** | the last process using it unloads it or exits |

Nothing is injected after it, and nothing hooks it.

## 1. On disk

| File on the console                      | Comes from                                                                          | Installed by                                                   |
| ---------------------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `vs0:/data/external/vitals/libssl.suprx` | `app0:libssl.suprx` (`build/vitals-ssl/libssl.suprx`), or `app0:debug/<level>/libssl.suprx` for Debug output | `install_http_modules` and the debug level switch in [install.c](../vitals-app/install.c) |

Sony's own `vs0:sys/external/libssl.suprx` is never modified; the replacement happens at load
time. Uninstalling removes vitals' copy with the HTTP modules. Earlier versions installed a copy of
Sony's own libssl here ([vitals-app/assets/lssl.suprx](../vitals-app/assets/lssl.suprx), kept as the
reference vitals-ssl was written from).

## 2. Boot

The kernel plugin's `add_replace_flags` ([vitals-plugin/main.c](../vitals-plugin/main.c)) looks
for vitals' libhttp and libssl. `g_replace_iap` is set only when **both** exist: the two libraries
are always swapped together.

## 3. A process asks for libssl

Like every load, it reaches `load_for_pid_patched` ([main.c](../vitals-plugin/main.c)):

1. **Path swap**: `vs0:sys/external/libssl.suprx` or `vs0:/sys/external/libssl.suprx` becomes
   `vs0:/data/external/vitals/libssl.suprx`.
2. **Flags left alone**: the loader's shared mapping is kept, as for every replacement.
3. **The real load**: vitals-ssl is mapped in the **shared** region, one copy of its code for every
   process that uses it, each process with its own data.
4. **Nothing queued**: no injection follows a libssl load.

Its memory is the pool the process gives `sceSslInit`, as Sony's is, and the CA bundle it trusts is
`vs0:/data/external/cert/CA_LIST.cer`, the store vitals installs.

## 4. Never hooked

Nothing in vitals patches libssl. libssl's sizes and the offsets of Sony's certificate getters are
still kept in [sony_abi.h](../tls13-vita/include/vitals/sony_abi.h), unused.

## 5. The end

libssl is unloaded when the last process using it unloads it or exits; `module_stop` ends what the
process left initialized.

## 6. Files

| File                                            | Role                            |
| ----------------------------------------------- | ------------------------------- |
| [vitals-ssl/](../vitals-ssl/)                   | the library                     |
| [vitals-plugin/main.c](../vitals-plugin/main.c) | the path swap                   |
| [vitals-app/install.c](../vitals-app/install.c) | putting the file on the console |
