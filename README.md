![vitals](/vitals-app/sce_sys/icon0.png)

# vitals - TLS Toolkit

Modern TLS (1.2 and 1.3) for the PS Vita browser, apps and games that use Sony's `sceHttp` APIs.  
All of the heavylifting has been done by [devnoname120](https://github.com/devnoname120) with `tls_fixer`, I'm only making those weights lighter. ([more info](#why-a-separate-project))

The Vita's own TLS stack (RSA BSAFE, 2014) can no longer connect to many current servers. vitals replaces only the TLS layer with [Mbed TLS](https://www.trustedfirmware.org/projects/mbed-tls/) and installs an up-to-date certificate store. Sony's HTTP code keeps handling URLs, redirects, cookies and everything else, so apps work unchanged.

> [!TIP]
> **If it's not broken, don't fix it**
> Please please please don't install this only because it's the shiny new thing and it has "security" in it. If you're happy with how your system is working and have no uses for the new functionalities that this project offer, DO NOT move away from iTLS, there's no reason to do so. Seriously.

> [!CAUTION]
> **Use `vitals` at your own risk.** It is provided as is, without any warranty, and I am not responsible for any damage, data loss or bricked console that may result from using it. While I personally tested this on two different systems of mine, I simply can't promise it will work on every single possible configuration out there.  
> You alone are responsible for your system, its maintenance and what's installed on it.
>
> `vitals` is a kernel plugin: it modifies files on your Vita's system partition (`vs0:`), your taiHEN configuration (`ur0:tai/config.txt`) and the system certificate store, and it changes how the system and your games connect to the internet. A bug, an interrupted installation or a conflict with another plugin could keep apps, the browser or the whole system from working properly.
>
> Before installing:
>
> - back up your Vita, including `ur0:tai/config.txt`;
> - make sure you know how to start your Vita without plugins (hold **L** while it boots) and how to recover it if something goes wrong;
> - only install it on firmware 3.60 or 3.65, the only firmware it is built and tested for.

## Installation

You need a hacked PS Vita on **firmware 3.60 or 3.65** with taiHEN. Supporting only these two versions keeps things a lot simpler; 3.65 is what [Vita Hacks Guide](https://vita.hacks.guide/) recommends, so if you're on another version and want to use this software, please follow their guides and update. On any other firmware the installation simply won't start.

- Download `vitals-app.vpk` from the releases page on [GitHub](https://github.com/nyirsh/vitals/releases) or [GitLab](https://gitlab.com/nyirsh/vitals/-/releases)
- Transfer it to your vita and install it (`VitaShell` can do both)
- Open `vitals`, select **Install** and press **Cross**  
  _This installs everything: the browser plugin, the system plugin and the certificates. The certificates are also downloaded from the internet, so there's no need to update them -- yet_
- The Vita reboots after a successful operation

Once `vitals` is installed, from the same application you'll be able to:

- **Reinstall** (or **Update**, when the installed version differs): installs this version over the existing one, to update `vitals` or repair an installation
- **Uninstall**: this removes all of `vitals` files and configurations
- **Update certificates**: it just downloads the latest Mozilla certificates and rebuilds the certificate store, without touching the plugins, use it from time to time to keep the store current
- **Test connections**: is `vitals` installed correctly and running just fine?

Before installing, the app removes the plugins known to conflict with vitals. Uninstalling vitals does not reinstall them:

- **iTLS-Enso:** its plugin hooks the same module loader as `vitals`, so the two cannot run together. The app removes its plugin, its taiHEN entry and its modules. iTLS's backup of Sony's original certificates is kept, and `vitals` restores it when you uninstall.
- **reAuth:** its PSN redirect is built into `vitals`, and both take over the same `libhttp` loads. The app removes every `reAuth.skprx` line from `ur0:tai/config.txt`, wherever the file was placed, and deletes the plugin and `ur0:data/reAuth/`.
- **tls_fixer** the plugin and its config entry are removed.

## What it covers

- **Browser:** a dedicated provider takes over TLS inside the browser's networking library (`ScePsp2Compat`/libcurl)
- **Apps and games:** `vitals-http`, Sony's HTTP library written from scratch on `Mbed TLS` 3.6, replaces `SceLibHttp` in every process that loads it. Apps keep calling the normal `sceHttp`/`sceHttps` APIs: if an app loads its own CA certificates (`sceHttpsLoadCert`), they are trusted in addition to the system store. This way, games that pinpoint a certificate that are redirected to community servers, such as Sound Shapes, can sign in via https!
- **PSN sign-in and the Store:** PSN sign-in moved from `native.np.ac.playstation.net` to `native-vita.np.ac.playstation.net`. A small module, `vitals-reauth.suprx`, is loaded into the shell once it loads its HTTP library, and into apps once they load the Store library (`SceNpCommerce2`). It sends their connections for the old host to the new one, and also applies the rules in your [host redirects](#host-redirects) list. The PSN redirect stays unless the list has its own rule for that host. This is the redirect [reAuth](https://github.com/psv-plugins-archive/reAuth) does, built into `vitals`

Adrenaline is left alone: its PSP emulator crashes when `vitals` takes over its HTTP library, so the plugin skips it, whichever bubble starts it, and PSP games keep Sony's own TLS.

TLS 1.0 and 1.1 are deliberately disabled.

## What's new compared to tls_fixer

- **Much less heap memory taken.** `tls_fixer` reserved a fixed 2 MiB heap inside every app that uses `sceHttp`, which is a lot on a console where games have little memory to spare. `vitals` reserves only 128 KiB and that fixes most of the crashes.
- **Certificates are looked up on demand.** `tls_fixer` parsed the whole certificate store (176 certificates!) into memory when each app started. `vitals` only builds a small index at start-up and reads a root certificate from the file when a handshake actually needs it. Apps and the browser start faster, and the parsed store no longer takes memory.
- **Games with their own certificates work.** When an app loaded its own CA certificates, `tls_fixer` sent all of that app's new connections back to Sony's old TLS stack, which fails against current servers. `vitals` keeps its modern TLS and trusts the app's certificates in addition to the system store. This is what lets games redirected to community servers, such as Sound Shapes, sign in via https instead of http.
- **A simpler kernel plugin**, modeled on `iTLS-Enso` module redirection, with the experimental, diagnostic and multi-firmware code removed. It targets firmware 3.60 and 3.65 only.
- **Host redirects for servers:** a simple list lets you redirect connections for a given host to a new one (see [Host redirects](#host-redirects))
- **PSN sign-in redirect built in:** the shell and the Store are sent to the new PSN sign-in host, without a separate reAuth installation, saving even more memory.
- **Easier to build and maintain:** refactored code, pinned and hash-verified `Mbed TLS` and curl downloads, a Makefile per component, `make update-certs` to refresh the bundled certificates, and `make test` to allow easy automated sanity checks.

## Host redirects

Games whose official servers are gone can be sent to a community server by listing the old and new host names in `ux0:data/vitals/redirects.txt`, one pair per line:

```
# old host                          new host
soundshapes.psvita.online.scea.com  sound.ture.fish
```

Installing `vitals` also creates the file with instructions and examples: it is never overwritten, and uninstalling leaves it in place. Changes apply the next time a game starts.

Every app and game that uses Sony's HTTP library, as well as the system shell, then connects to the new host. It applies to connections made by host name or by URL; the scheme, port, path and query are kept, and the certificate is checked against the new name.

## DNS rules

`redirects.txt` is for the HTTP library only. For every other lookup (a game's own UDP or TCP connections, and the other system libraries), put rules in `ux0:data/vitals/dns.txt`, one `host target` pair per line, where the target is another host name, an IPv4 address, or `block`:

```
# host                      target
old.server.example          new.server.example
game.server.example         203.0.113.5
telemetry.example           block
```

The kernel plugin watches the DNS queries every process sends. For a host name target it asks for that name instead and answers with its addresses under the original name; for an address it answers with that address; for `block` it answers that the name doesn't exist. Installing `vitals` creates the file with these instructions, commented out; it is never overwritten, and uninstalling leaves it in place. Changes apply to new lookups within a few seconds, and an answer already given may stay cached for up to 5 minutes.

The app still connects by the original name, so an HTTPS server must have a certificate for that name (apps using the HTTP library are better served by `redirects.txt`, which also checks the certificate against the new name). Only names are covered, not addresses a game has written in, and only IPv4 (A) lookups.

## User-Agent

Every request carries the app's own User-Agent followed by `libhttp/3.74 (PS Vita)`, as the latest firmware's library sends. To send something else in place of that last part, put it on a line of `ux0:data/vitals/useragent.txt`:

```
# replaces "libhttp/3.74 (PS Vita)"
libhttp/3.74 (PS Vita) MyFork/1.0
```

The first line that isn't empty or a `#` comment is used, trimmed, up to 127 printable ASCII characters; a line with anything else is ignored. Apps that set their own whole User-Agent keep it. Changes apply the next time an app starts.
For now, only up to a maximum of 32 hosts can be redirected (trying to be cautious with memory usage and performance), maybe one day after more careful testing the restriction will be lifted. Malformed host names are also ignored.

## Custom certificates

To trust your own servers, for example a community server with a self-signed certificate, put their certificates in `ux0:data/vitals/custom-certs.pem`, one or more PEM blocks (`-----BEGIN CERTIFICATE-----` … `-----END CERTIFICATE-----`). Comments and anything that isn't a certificate are ignored.

The file is optional. Its certificates are added to Sony's and Mozilla's whenever the app installs, updates, reinstalls or updates certificates, so after editing it run **Update certificates**. Duplicates are added only once, a mistake in the file never stops an update, and uninstalling leaves the file in place.

A server's self-signed certificate is trusted as itself, exactly as it appears in the file, whether or not it's marked as a certificate authority. For a server whose certificate was issued by a certificate authority of your own, add that authority's certificate instead. To make a self-signed certificate:

```
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout server.key -out server.crt \
    -subj "/CN=my.server.example" -addext "subjectAltName=DNS:my.server.example"
```

The certificate must also name the host apps connect to: combined with [host redirects](#host-redirects), that's the redirect's new host.

> [!caution]
> Every certificate in this file is trusted by every app, game and the browser. A server's own self-signed certificate is harmless, but adding someone else's certificate authority lets them impersonate any website on your console. Only add certificates you created yourself or fully trust.

## Connection test

**Test connections** in the app checks what an ordinary app experiences, using only Sony's HTTP APIs, and you can run it even without `vitals` being installed:

- TLS 1.0–1.3 checks against BrowserLeaks (with `vitals`, TLS 1.0 and 1.1 show as blocked, which is intended)
- PlayStation HTTPS reachability
- the negotiated cipher and handshake details, from the BrowserLeaks TLS report
- whether vitals-http is loaded in the app

Each run saves a report to `ux0:data/vitals/`. The test works on any firmware and changes nothing on the console.

## Repository layout

| Folder               | Contents                                                                                           |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `vitals-plugin/`     | the kernel plugin (`vitals.skprx`) that redirects Sony's modules and injects the browser provider  |
| `vitals-http/`       | Sony's HTTP library written from scratch (`libhttp.suprx`), with `tls13-vita`'s TLS               |
| `tls13-vita/`        | the TLS providers and their `Mbed TLS` configuration; `vitals-http` uses its certificate code     |
| `vitals-reauth/`     | the PSN sign-in host redirect (`vitals-reauth.suprx`)                                              |
| `vitals-app/`        | the `vitals` app (`VITALS001`)                                                                     |
| `licenses/`          | full license texts of the third-party software in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) |
| `dependencies.cmake` | pinned versions and SHA-256 hashes of `Mbed TLS` and `curl`                                        |

## Why a separate project

`vitals` started as a mashup of my URL redirector project and devnoname120's `tls_fixer`, and owes `tls_fixer` the hardest parts: running Mbed TLS inside Sony's HTTP stack, the providers and the injection. It's a separate project instead of a fork because the two have grown apart in ways that can't be merged back in either direction:

- **Different memory design.** `tls_fixer` gives every app its own private copy of Sony's HTTP and SSL libraries, which costs a game about 440 KiB on top of the provider. `vitals` keeps the SSL library shared and handles the certificates games load at the HTTP level instead, so games that were running out of memory (like Sound Shapes) now fit. The comments left in the code and in the specs made me feel like it was a deliberate choice from devnoname120 I was going against.
- **Different scope.** `tls_fixer` supports several firmware versions, and keeps experimental, diagnostic and self-disarming code for testing on hardware. `vitals` targets firmware 3.60 and 3.65 only, with that code removed and a simpler kernel plugin modeled on `iTLS-Enso`.
- **Features that don't exist upstream:** the configurable host redirects, the built-in PSN sign-in redirect, the redirect list read through the kernel for sandboxed games, and a single app for installing, updating certificates and testing.
- **They replace each other.** Both take over the same system modules and use different install paths, so only one can be installed at a time. The `vitals` installer removes `tls_fixer` for that reason.

Merging would mean asking `tls_fixer` to give up its multi-firmware and goals, or `vitals` to bring back what it removed. Keeping them apart lets each follow its own direction.

Seriously tho, devnoname120 is a legend and you'll find out that, out of respect and admiration for what was accomplished, I kept my name out of any visible part of the code or UIs.

## Building

The first build downloads the pinned `Mbed TLS` and `curl` releases, so it needs internet access. The easiest way is VitaSDK's Docker image:

```sh
docker run --rm -v "$PWD":"$PWD" -w "$PWD" vitasdk/vitasdk:latest sh -lc 'make'
```

This produces `build/vitals-app/vitals-app.vpk`. Everything is built under `build/`.

To build without Docker, install [VitaSDK](https://vitasdk.org) (make sure to add the sdk to your `PATH`) and the Vita libraries the app links, then run `make`:

```sh
vdpm install openssl-1.1.1 zlib zstd
make
```

Use `openssl-1.1.1`: vdpm's plain `openssl` package is the older 1.0.2.

Each component folder has its own Makefile that also works on its own (`make -C <folder>`); the root Makefile only calls them. `vitals-app/` builds `vitals-plugin/`, `vitals-http/`, `tls13-vita/` and `vitals-reauth/` first, because the vpk bundles them.

Available build options:

| Option          | Default | Effect                                                                     |
| --------------- | ------- | -------------------------------------------------------------------------- |
| `HTTP_HEAP_KIB` | `128`   | memory (KiB) the TLS provider reserves                                     |
| `TLS_HEAP_KIB`  | `128`   | memory (KiB) `vitals-http` reserves for TLS, in a process's first https use |
| `USER_AGENT`    | `libhttp/3.74 (PS Vita)` | what `vitals-http` puts after each app's own User-Agent, unless `useragent.txt` gives another; up to 127 printable ASCII characters, without quotes, backslashes, backticks, `#`, `$` or `;` |

Debug output levels, for `vitals-http` and the browser provider (lines start with `vitals-http:` for apps and games, `vitals_browser:` for the browser):

- **Off (0):** nothing, the default
- **Basic (1):** start-up, heap use, the app's `sceHttp` calls, the certificates a game loads, and a few lines per connection (connect, certificate result, handshake result), plus any failure. The kernel plugin also logs every DNS query a process sends (`vitals: dns query …`), after the reboot that switching debug output asks for
- **Full (2):** everything in Basic, plus every step of every connection (retries, locks, each socket read and write) and messages from `Mbed TLS`. This produces a lot of output and slows connections down, use it only to investigate a problem

Every build includes all three levels; choose one on the console from the app's **Debug output** option, which reboots the Vita. To build a single component at a level, run `make -C tls13-vita DEBUG=2` (each level has its own `build/` folder).

### Updating `Mbed TLS` or `curl`

Both are pinned in [dependencies.cmake](dependencies.cmake). Change the version and the SHA-256 together, where the SHA-256 is that of the new release archive (`sha256sum` of the downloaded file).  
The next build downloads and verifies it. The providers accept any `Mbed TLS` 4.x, and `vitals-http` any 3.6 (`VITALS_MBEDTLS3_*`, which it needs for the console's own TLS 1.2 suites); a new major version will need configuration work.

### Updating the bundled certificates

The installer downloads the latest certificates and checks them against this bundled copy; if the download fails, it uses the bundled copy instead. Refreshing it keeps that fallback current:

```sh
make update-certs
```

This downloads `https://curl.se/ca/cacert.pem`, checks it against the SHA-256 curl publishes next to it, rebuilds `certs.cer` with the app's own merge code and updates `certificate-sources.json`, all in `vitals-app/assets/`. It needs `pkg-config` with `libcurl` and `OpenSSL development files` on the host.

### Tests

```sh
make test
```

This runs every component's host tests (`make -C <folder> test` runs one component's). Each component keeps its tests in its own `tests/` folder, and any helper scripts its build uses in `tools/`:

- `vitals-plugin/tests/`: the kernel plugin's routing, injection and module checks, against mocks of the Vita kernel, and the build check that keeps floating-point instructions out of it
- `tls13-vita/tests/`: real TLS handshakes over loopback, certificate and hostname checks, the certificates games load (`sceHttpsLoadCert`), callbacks, nonblocking I/O, the host redirect list and the hooks that apply it, memory use, the Makefile's settings, and a build of the providers with debug output on, so every log line compiles
- `vitals-reauth/tests/`: which module it hooks, that only the old PSN host is redirected, and failed hooks
- `vitals-app/tests/`: install, reinstall and uninstall on a console mapped onto a temporary folder (including removing iTLS-Enso, tls_fixer and reAuth, and `config.txt` surviving a failed write), the install options, `config.txt` editing, OpenSSL locking, certificate merging and the certificate updater

The loopback TLS and most browser tests place memory at fixed low addresses, as the Vita's 32-bit pointers need, which only Linux allows; elsewhere they are left out (on macOS, run `make test` inside Docker to include them). A few certificate tests are skipped unless `pkg-config` and the libcurl and OpenSSL development files are installed: `pkg-config libcurl4-openssl-dev libssl-dev` on Debian/Ubuntu, `brew install pkgconf curl openssl` on macOS (the tests find Homebrew's copies themselves). The OpenSSL must be the one libcurl itself uses, as the code under test shares OpenSSL objects with curl.

Each normal build also checks that the kernel plugin contains no floating-point instructions and that the HTTP provider does not import the full C library.

> [!WARNING]
> **The kernel plugin must never use floating-point or vector (VFP/NEON) instructions.** `vitals.skprx` runs inside the Vita's kernel, which does not save or restore the floating-point registers around kernel code. If the plugin used them, it could silently corrupt the math of whatever app it interrupted, or even crash the whole system, including at boot.
>
> The compiler can add these instructions on its own, as a speed-up for copying or clearing memory, even when the code never uses decimal numbers. Two safeguards keep them out:
>
> - the plugin is compiled with `-mgeneral-regs-only`, so the compiler never uses those registers;
> - every build disassembles the finished plugin and fails if any such instruction appears (`kernel register check: no decoded FP/SIMD instructions`).
>
> Don't remove either one. If the check fails, find out which code produced the instruction rather than disabling the check. DO NOT install a new build on your system without running this test first. Out of all of the tests available, this is probably the most important one and I can't stress this concept enough.
>
> The TLS providers are not affected: they run inside an app's own process, where these registers are saved normally.

## Credits

**vitals is a continuation of [tls_fixer](https://github.com/devnoname120/vita_tls_fixer) by devnoname120, who did the most difficult part of the job.** The TLS providers, the integration of `Mbed TLS` with Sony's HTTP library and the browser, the kernel plugin's injection and module checks, the certificate merging, the certificate updater and the original Vital Signs connection test are his work. vitals renames the project and continues it.

**Thanks to SKGleba for the [iTLS-Enso](https://github.com/SKGleba/iTLS-Enso) plugin!** His work updating the Vita's certificates is the foundation of `vitals`, along with his original installer and module-redirection code. Existing author notices are preserved in the source.

**Thanks to Reiko Asakura for [reAuth](https://github.com/psv-plugins-archive/reAuth)!** `vitals-reauth` just follows `reAuth` approach: the same hook in the shell and the Store library, and the same host redirect.

Also special thanks to Team Molecule, for all of the and love they poured into the PS Vita, and to everyone who works on [VitaSDK](https://vitasdk.org) and its packages, which every part of `vitals` is built with.

## License

All contributions to vitals are released under the [Zero-Clause BSD license](LICENSE) (0BSD): you can use, copy, modify and distribute them for any purpose, with or without credit.

Some parts keep their own terms:

- **Code from tls_fixer** by devnoname120: most of vitals comes from [tls_fixer](https://github.com/devnoname120/vita_tls_fixer), which is published without a license. That code remains devnoname120's; the 0BSD license covers it only if he agrees to it.
- **Code from iTLS-Enso** by SKGleba: `vitals-plugin/main.c` (module redirection) and `vitals-app/install.c` (the install and uninstall operations) are derived from [iTLS-Enso](https://github.com/SKGleba/iTLS-Enso), which is published without a license. Its code remains SKGleba's ("All Rights Reserved"); the 0BSD license does not cover the original iTLS-Enso code.
- **Approach from reAuth** by Reiko Asakura: `vitals-reauth/main.c` follows [reAuth](https://github.com/psv-plugins-archive/reAuth)'s user module (the `sceHttpCreateConnection` hook in SceShell and SceNpCommerce2 and its host redirect). reAuth is published as "All Rights Reserved"; the credit for that approach remains Reiko Asakura's.
- **Third-party libraries and data:** under their own licenses, listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- **Sony material:** the Sony modules and certificate bundle in `vitals-app/assets/` are not covered by any license.
