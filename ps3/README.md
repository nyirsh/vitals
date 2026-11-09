# vitals for PS3

vitals' modern TLS for the PlayStation 3, on Evilnat's Cobra CFW and PS3HEN (firmware 4.9x): Sony's
libssl rewritten on Mbed TLS, so games and apps get TLS 1.2 and 1.3 instead of the console's TLS
1.0 (the XMB itself, with PSN and the browser, keeps Sony's: below). Early work: vitals' libssl loads in Sony's place, in RPCS3 and, on a
console, in games. It has Mbed TLS 4.2 in it, and the library's set-up and its connections (TLS 1.2
and 1.3, as Sony's libhttp calls them) are written, tested on a host; the certificate functions,
and so a connection libhttp checks, are next.

## Layout

| Folder         | What's in it                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `vitals-ssl/`  | libssl rewritten (`cellSsl`, the 114 functions of Sony's `libssl.sprx`): the library and SSL-C's error queue in [src/core.c](vitals-ssl/src/core.c), connections in [src/connection.c](vitals-ssl/src/connection.c) (from the Vita's vitals-ssl), the platform layer in `src/platform/` (liblv2's string functions, the pool, locks, sys_net, entropy and time), Mbed TLS 4.2 and its patches in `crypto/`; the functions not written yet say on the TTY that they're called ([src/spike.c](vitals-ssl/src/spike.c))                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `vitals-boot/` | the boot plugin Cobra loads into the XMB: points Sony's libssl and libhttp at vitals' with Cobra's path redirection, at every boot; vitals' modules keep Sony's names, and carry a marker (`common/vitals_marker.h`) that the app's test looks for in the modules its process loaded, to know which of vitals' parts are running and their release                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `vitals-xmb/`  | vitals' TLS for the XMB itself, off and never packaged (it takes the system down when a game starts): built into the boot plugin with `make plugin XMB=1`; [vitals_xmb.h](vitals-xmb/src/vitals_xmb.h), what the boot plugin asks libssl and libhttp for there, and [vsh_ssl.py](vitals-xmb/tools/vsh_ssl.py), which reads the XMB's own SSL-C |
| `vitals-http/` | libhttp rewritten (plan step 5): init and end ([src/core.c](vitals-http/src/core.c)), clients ([src/client.c](vitals-http/src/client.c)), transactions ([src/transaction.c](vitals-http/src/transaction.c)), https through libssl ([src/tls.c](vitals-http/src/tls.c)), header lists ([src/headers.c](vitals-http/src/headers.c)) and sys_net ([src/platform/](vitals-http/src/platform/platform_ps3.c)); the exports not written yet say they were called ([src/spike.c](vitals-http/src/spike.c)). Sony's two libraries are exported as Sony lays them out ([src/exports.S](vitals-http/src/exports.S), from the generated [src/cellhttp_exports.h](vitals-http/src/cellhttp_exports.h))                                                                                                                                                                                                                                                       |
| `vitals-app/`  | the vitals app, as the Vita's: installs, updates or removes vitals (libssl, libhttp, the boot plugin and the DNS kernel plugin, with example `redirects.txt` and `dns.txt` it never overwrites, and uninstalling leaves), turns each part on or off and picks its debug output (Options), updates Mozilla's certificates, tests connections and shows its changelog and credits as the Vita app does (BrowserLeaks, badssl.com and each host redirect, through Sony's libhttp; timeouts retried, redirects not followed; then each DNS rule, looked up through libnet), with the Vita app's look, drawn at the screen's own resolution; `assets/` has its Mozilla bundle (`make update-certs`) and the example lists, `tests/` its host tests, `host/` draws its screens on a Mac, and `pkg/` has its ICON0, XMB background and PARAM.SFO (category `CB`: the XMB lists it in the Network column) |
| `common/`      | what the modules share: [vitals_log.h](common/vitals_log.h), a log line on the TTY and in `/dev_hdd0/vitals/logs/vitals.log`; the files and switches' places (`vitals_paths.h`). The host redirect list's parser, DNS messages, the CA store's scanner (`ca_scan.c`) and Mozilla's part of it without Sony's (`store_certs.c`), and the app's changelog and input code are shared with the Vita, in `../shared/`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `tests/host/`  | the host tests: libssl built for this machine with a POSIX platform, called as Sony's libhttp calls it, against a local TLS server (as the Vita's); and in `http/`, the libhttp probe built with vitals' libhttp and libssl for this machine, with AddressSanitizer, its lines diffed against Sony's as an RPCS3 run's are: the differences are vitals' documented ones and the host's own, 64-bit pointers in header lists' sizes and a refused connection's real `ECONNREFUSED` (tests/http-probe/host-differences.txt)                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `tools/`       | reading Sony's modules: [prx.py](tools/prx.py), [nids.py](tools/nids.py), [prx_report.py](tools/prx_report.py), [ps3_disasm.py](tools/ps3_disasm.py) (a function with its calls and TOC loads named, or every call to an import), [vsh_ssl.py](vitals-xmb/tools/vsh_ssl.py) (the XMB's own SSL-C in `vsh.elf`: its bounds and who reaches it) and the name lists in `tools/names/`; [rpcs3_run.sh](tools/rpcs3_run.sh) runs an app in RPCS3 with vitals' libssl; [ps3_comms.py](tools/ps3_comms.py) puts vitals on a console and fetches its log                                                                                                                                                                                                                                               |

| `vitals-dns/` | the DNS rules (`dns.txt`), as the Vita's: a kernel plugin the boot plugin loads at every boot (not from `boot_plugins_kernel.txt`), which hooks lv2's `sendto` and `recvfrom` for every process (`kernel/`), on the Vita's rules engine and DNS message code (`src/`, tested on the host in `tests/host/dns`); 4.93's lv2 addresses and the signatures it checks before hooking in `src/lv2_493*.h` ([tools/lv2_symbols.py](tools/lv2_symbols.py) checks them against a dump) |

## On the console

Everything vitals keeps is in `/dev_hdd0/vitals`, which itself holds only what you might edit:

```
/dev_hdd0/vitals/
  redirects.txt   dns.txt   useragent.txt      your lists (installing never overwrites them)
  custom-certs.pem                              your own certificates, if any (none to start with)
  system/    libssl.sprx  libhttp.sprx  vitals_dns.bin  mozilla-certs.pem  installed.txt  ...
  flags/     tls.off  http.off  dns.off  redirects.off  debug.1 or debug.2
  logs/      vitals.log (debug builds)  vitals-app.log
  reports/   the app's connection test reports
```

`system/` is the installers' (don't edit it). The boot plugin itself is
`/dev_hdd0/plugins/vitals_boot.sprx`, where Cobra's `boot_plugins.txt` lists it.

**Switches:** an empty file in `flags/` turns a component off from the next boot, and deleting it
turns it back on:

| File            | Off from the next boot                                                                                   |
| --------------- | -------------------------------------------------------------------------------------------------------- |
| `tls.off`       | vitals' libssl for games and apps: Sony's stays, under vitals' libhttp too (which works on either)       |
| `http.off`      | vitals' libhttp for games and apps: Sony's stays (and with it the host redirects and the User-Agent)     |
| `dns.off`       | the DNS rules                                                                                            |
| `redirects.off` | the host redirects; vitals' libhttp stays                                                                |

The vitals app's **Options** screen turns TLS, HTTP and the DNS rules on or off with Left and Right
(and picks the debug output). HTTP has three: On (vitals' libhttp with the host redirects), Redirects
off (in orange: vitals' libhttp without them, `redirects.off`) and Off (Sony's libhttp, which has
none, `http.off`), as the redirects are vitals' libhttp's; START there ("Apply and reboot") writes the switches to `flags/` and installs the debug
output's builds, showing each step, then reboots the console after 3 seconds. Back leaves it all as
it was. The boot popup says which are off, as `TLS: Off`. The debug output is a marker there too,
`debug.1` for Basic or `debug.2` for Full (none for Off), which installing keeps. Uninstalling leaves
your lists, the switches in `flags/` and `reports/`. Installing over an earlier version moves its files to these folders (its
`dns.off`, its certificate update and its reports kept).

## Host redirects

Games whose official servers are gone can be sent to a community server by listing the old and
new host names in `/dev_hdd0/vitals/redirects.txt`, one pair per line, as on the Vita:

```
# old host                          new host
old.server.example                  new.server.example
```

Every game and app that uses Sony's HTTP library (with vitals' libhttp installed) then connects to
the new host: the scheme, port, path and query are kept, the `Host` header and the certificate
check are the new host's, and the URI the game reads back has it too. While
`/dev_hdd0/vitals/flags/redirects.off` is there, no host is redirected. A redirected host gets 30
seconds at least to answer. The vitals app's connection test requests each pair by its old name, as on
the Vita, when vitals' libhttp is the one loaded this boot. At most 32 pairs; lines that aren't two valid host names are skipped.
The list is read at each `cellHttpInit`, so changes apply the next time a game starts. The XMB's
own browsing (PSN, the store, the browser) uses the XMB's own HTTP stack, which the list doesn't
reach.

Installing vitals (the app, or `make install`) creates `redirects.txt` with these instructions when
there's none; it's never overwritten, and uninstalling leaves it in place, as on the Vita.

## DNS rules

`redirects.txt` is for Sony's HTTP library only. For every other lookup, by any game, app or the
system, put rules in `/dev_hdd0/vitals/dns.txt`, one `host target` pair per line, as on the Vita:

```
# host                      target
old.server.example          new.server.example
game.server.example         203.0.113.5
telemetry.example           block
```

A host name target is looked up in the host's place and its addresses given back for the original
name; an address is the answer; `block` makes the name not exist. Only the address changes: the
game still connects by the original name, so an HTTPS server needs a certificate for that name, and
a server that tells sites apart by name (Cloudflare, for one) has to know it, which is why
`redirects.txt` is the better place for games using Sony's HTTP library. Games that reach their
server by name over UDP or plain TCP are what DNS rules are for, and blocking.

The vitals app's connection test looks up each rule's host through libnet, as a game would, so the
kernel plugin sees its queries: a `block` rule passes when the name doesn't exist, an address when it's
the answer, and a host name when the answer shares an address with the target's own lookup (a server
may rotate its addresses). While `flags/dns.off` is there the rules aren't tested, and when every rule
tested got the server's own answer the test says "Not applied": the rules aren't running this boot
(the boot popup says why).

The rules are applied by a kernel plugin (`/dev_hdd0/vitals/system/vitals_dns.bin`), which hooks lv2's
`sendto` and `recvfrom` for every process. The boot plugin loads it as the boot starts, with
Cobra's syscall 8 as webMAN MOD loads one. **Don't list it in `/dev_hdd0/boot_plugins_kernel.txt`:**
the boot plugin's guards don't cover a load from there, and the installers take out any line an
earlier version put there (an early version froze the console at every boot from it). It isn't loaded on a boot after one that didn't end
properly (a power cut or a freeze), which the system's own marker tells: `/dev_hdd0/tmp/turnoff`,
which it writes a few seconds into each boot and deletes at a proper shutdown, is still there when
the boot plugin starts. Thirty seconds into each boot, the boot plugin shows what it did in the XMB's
notification popup, titled "vitals" and the installed version, then the app's debug output when it's on (as "vitals 2.0 - Basic
debug"): whether vitals' TLS is on (On, or Off and if not by a switch, why) and HTTP, how many host redirects
`redirects.txt` has and how many DNS rules are, with a check mark when all is on, a caution sign when something is
off and an error sign when something failed. So if it ever freezes the console, cutting the power gives a boot without
it, from which `dns.off` (or uninstalling) keeps it off. It reads `dns.txt` when it's loaded. It hooks nothing when:

- lv2 isn't the one its addresses are for (4.93 CEX): it checks lv2's code before calling into it;
- `/dev_hdd0/vitals/flags/dns.off` is there;
- `dns.txt` has no rules.

If a boot ever freezes because of a boot plugin, a USB stick with an empty list did _not_ help on
Evilnat's 4.93. What worked: Recovery Mode (hold power through the second beep, then until the
double beep; a wired controller, PS) and "Restart System" only, which boots with Cobra off; then
turn Cobra back on in Evilnat's CFW Tools in the XMB, and webMAN MOD's FTP is back.
Installing creates `dns.txt` with these instructions when there's none; it's never overwritten, and
uninstalling leaves it, as `redirects.txt`.

With debug output on, each DNS query goes in `vitals.log` as a `vitals-dns: [ms] query name=... type=...` line.
The kernel plugin's hooks can't write a file, so they keep the last 8 queries in memory and the boot plugin
reads them four times a second: the time is when a query was read, up to a quarter of a second late, the line
doesn't say which process asked, and a burst of more than 8 between two reads is counted as `N queries not logged`.

## User-Agent

A request carries `PS3Application libhttp/4.9.3-000 (CellOS)` unless the game sets its own. To send
something else in place of `libhttp/4.9.3-000 (CellOS)`, put it on a line of
`/dev_hdd0/vitals/useragent.txt`:

```
# replaces "libhttp/4.9.3-000 (CellOS)"
libhttp/4.9.3-000 (CellOS) MyFork/1.0
```

The first line that isn't empty or a `#` comment is used, trimmed, up to 127 printable ASCII
characters; a line with anything else is ignored. Games that set their own whole User-Agent keep
it, as on the Vita (Sony's PS3 libhttp adds nothing after a game's own agent).

A build can carry another default in place of `libhttp/4.9.3-000 (CellOS)`, as the Vita's
`USER_AGENT`: `make http USER_AGENT='libhttp/4.9.3-000 (CellOS) MyFork/1.0'` (1 to 127 printable
ASCII characters, without `" \ # $ ; `` ` `` '`); `useragent.txt` still takes its place.

## Custom certificates

To trust your own servers, for example a community server with a self-signed certificate, put their
certificates in `/dev_hdd0/vitals/custom-certs.pem`, one or more PEM blocks
(`-----BEGIN CERTIFICATE-----` … `-----END CERTIFICATE-----`), as on the Vita. Comments and anything
that isn't a certificate are ignored.

The file is optional. vitals' libssl reads it as it is, after Sony's certificates and Mozilla's, so
an edit applies to the next game or app you start: there's nothing to update. A block that isn't a
whole certificate is skipped without affecting the rest. Uninstalling leaves the file in place.

The store works as the Vita's: Sony's CAs first (on the PS3, the system's own in
`/dev_flash/data/cert`, never written), then Mozilla's certificates Sony's lack
(`system/mozilla-certs.pem`, which installing and **Update certificates** write, leaving Sony's
out), then yours. Updating from a version that kept `system/cacert.pem`, with your certificates
merged in, moves it there and takes the merged copy out.

A server's self-signed certificate is trusted as itself, exactly as it appears in the file, whether
or not it's marked as a certificate authority. For a server whose certificate was issued by a
certificate authority of your own, add that authority's certificate instead. Both were tried on the
console with badssl.com's: `self-signed.badssl.com`'s certificate, and the authority behind
`untrusted-root.badssl.com`, made the connection test load both. To make a self-signed certificate:

```
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout server.key -out server.crt \
    -subj "/CN=my.server.example" -addext "subjectAltName=DNS:my.server.example"
```

The certificate must also name the host games connect to: combined with
[host redirects](#host-redirects), that's the redirect's new host.

## The app

The vitals app is in the XMB's Network column. Under its version it shows what the console runs
(firmware, CEX or DEX, Cobra or PS3HEN, read as webMAN MOD reads them), and the connection test's
report has the same line. vitals is made and tested for **4.93 CEX with Cobra**: on any other system
the app says so and offers no Install, Update, Reinstall or Options (Uninstall, the test and the
documents stay). An empty `flags/unsupported.ok` lets it install anyway, for testing.

Its menu, as the Vita's:

- **Installation**: Left and Right pick Install, Update, Reinstall or Uninstall (as fits what's
  installed), and the confirm button (X, or O where the console confirms with O) does it.
- **Update certificates**: downloads Mozilla's CA bundle as curl publishes it
  (`https://curl.se/ca/cacert.pem`) and writes the certificates in it that Sony's lack. Its "Last update" date turns red once it's more than three
  months old. The app downloads it with its own curl and Mbed TLS, as the Vita's app does, trusting
  only the Mozilla bundle it carries, so it works with vitals' TLS switched off or not installed. Each
  certificate is read with Mbed TLS, as vitals' libssl reads the store, and one it can't read is left
  out; when the download fails, the store stays as it was (shared/app/ca_update.c, the Vita's too).
- The menu shows when GitHub or GitLab has a newer release than the app, found the same way.
- **Options**: TLS, HTTP (On, Redirects off, Off) and the DNS rules, and the debug output, applied with START (see
  [On the console](#on-the-console)).
- **Test connections**: the connection test, below.
- **Changelog** and **Credits** ([CREDITS.md](../CREDITS.md), both consoles').

**The connection test** goes through, in order:

1. TLS 1.3 to 1.0 against BrowserLeaks, through Sony's libhttp (the four tiles: 1.3 and 1.2 should
   connect, 1.1 and 1.0 be refused; a TLS 1.3 connection is what tells vitals is enabled).
2. BrowserLeaks' TLS report: what the server saw of the handshake.
3. badssl.com's 12 certificate checks: hosts that must load and hosts that must be refused.
4. Each host redirect in `redirects.txt`, requested by its old name, when vitals' libhttp is this
   boot's ([Host redirects](#host-redirects)).
5. Each DNS rule in `dns.txt`, looked up through libnet ([DNS rules](#dns-rules)).

Steps 2 to 5 each have a row under the tiles, with a mark and a count. Square goes through six detail
pages in the same order: request details, cipher suites, handshake details, certificate checks,
host redirects and DNS rules. While a run goes, the page follows it, scrolled to the latest host,
until Square or a scroll takes over. The confirm button runs it again, Triangle cancels it, and START
saves a run that finished to `/dev_hdd0/vitals/reports/` as text, with every result.

The screens are laid out at 1280x720 and drawn at the screen's own size when its frame is 16:9 and
720 lines or more (1920x1080 or 1280x720: 1080p, 1080i, 720p), so the text is sharp; other modes
(480p, 576p, and the narrower 1080 frames) get the 1280x720 drawing scaled by the RSX.

## Building and running

The [Makefile](Makefile) runs everything; the console's modules are built in a Docker image of
PS3DK, [nyirsh/vitals-ps3-sdk](https://hub.docker.com/r/nyirsh/vitals-ps3-sdk) on Docker Hub (also
`ghcr.io/nyirsh/vitals-ps3-sdk`), for arm64 and amd64, about 1.5 GB. Docker pulls it the first time
it's needed; to get a newer one:

```
make pull
```

The image's Dockerfile and its CI are [vitals-ps3-sdk](https://github.com/nyirsh/vitals-ps3-sdk); `make IMAGE=...` builds with
another image or tag.

Then:

|                                                                                          |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `make`                                                                                   | everything: the vitals app and all it carries (`make app`), as the Vita's |
| `make ssl DEBUG=1`                                                                         | libssl with a debug log on the TTY and in `/dev_hdd0/vitals/logs/vitals.log`: the calls: the CA store, each handshake's result, why a chain was refused and the server's alerts (`build/vitals-ssl-debug1`)                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `make ssl DEBUG=2`                                                                         | also the details: which CA the server's chain comes from, how it closed, the pool's use, every read and write (libhttp's one-byte reads of the headers as one line), and the HTTP headers that go by, secrets and query values as their length (`build/vitals-ssl-debug2`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `make http`                                                                              | vitals' libhttp (`build/vitals-http`); in RPCS3 with `VITALS_HTTP=build/vitals-http/libhttp.fake.sprx tools/rpcs3_run.sh …`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `make http-probe`, then `tools/http_probe.sh vitals build/vitals-http/libhttp.fake.sprx` | the libhttp probe in RPCS3, vitals' against Sony's recorded run (`tools/http_probe.sh sony` records Sony's again). With `VITALS_PROBE_SSL=sony`, both libhttps run on Sony's own libssl (`sony` first, then `vitals`), as vitals' libhttp does with `tls.off`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `make test`                                                                              | the host tests (this machine's compiler, Python 3 and openssl; Mbed TLS is the same). The libhttp probe's run needs PS3DK's `cell/http` and `cell/ssl` headers, which it copies out of the SDK image into `build/ps3dk-include` the first time (Docker); it serves on 127.0.0.1:18080, as `tools/http_probe.sh` does, so not both at once. Then the app's own (`vitals-app/tests`: the connection test's rules, BrowserLeaks parser, DNS rule judging and run following, Mozilla's part of the CA store without Sony's (the shared `store_certs.c` and `make install`'s, held to the same cases), `boot_plugins.txt`'s editing and the changelog in C with AddressSanitizer, `make update-certs` in Python, and the shared download and release check on the app's own curl and Mbed TLS against local HTTPS servers, the same tests the Vita's run, `shared/app/tests/release_fetch_tests.py`)                                                                                                        |
| `make rpcs3 APP=<app.elf> [DEBUG=N] [SECONDS=60]`                                        | an app in RPCS3 with that libssl in Sony's place, printing its TTY (the script puts Sony's back afterwards)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `make http [DEBUG=N] [USER_AGENT=...]`                                                   | vitals' libhttp (`build/vitals-http`); USER_AGENT replaces `libhttp/4.9.3-000 (CellOS)` in the default User-Agent, as the Vita's; with DEBUG its log in `vitals.log` as `vitals-http:` lines: 1 the calls that do something and their errors, each connection, handshake, certificate check and SSL callback answer, redirects; 2 also every getter, read and header, secrets and queries as their length (`build/vitals-http-debugN`)                                                                                                                                                                                                                                                                                                                                 |
| `make install [DEBUG=N] [SIGNED=1]`                                                      | that level's libssl, libhttp, boot plugin and DNS kernel plugin (not listed in `boot_plugins_kernel.txt`), Mozilla's CA bundle (when the console has none) with your `custom-certs.pem` after it, as the app merges it, and the example `redirects.txt` and `dns.txt` (when it has none) on the console, and `installed.txt` with the level, as the app writes it. Leave out `SIGNED=1` on a console: the PlayStation Store app hangs on a black screen loading the real-signed libssl and libhttp                                                                                                                                                                                                                              |
| `make plugin [DEBUG=N]`                                                                  | the boot plugin (`build/vitals-boot`); with DEBUG its log as `vitals-boot:` lines: 1 what happened at boot (the mappings, DNS loaded or why not, the popup's text), 2 also addresses, codes and times (`build/vitals-boot-debugN`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `make dns-plugin [DEBUG=N]`                                                              | the DNS kernel plugin, `build/vitals-dns/vitals_dns.bin`, checked to be the same image wherever it's linked and to make no indirect call but its own into lv2; with DEBUG its log as `vitals-dns:` lines: 1 the rules and whether it hooked, 2 also where it's loaded and its counters are (`build/vitals-dns-debugN`, which `tools/peek_dns.py` needs)                                                                                                                                                                                                                                                                                                                                                                                                                |
| `make update-certs`                                                                      | both apps' Mozilla CA bundle (`shared/assets/mozilla-certs.pem`) refreshed from curl and checked against curl's SHA-256; review and commit the result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `make fetch`                                                                             | copies the logs and the app's test reports into `../fetched/ps3/`, leaving them on the console (with `make log` and `app-log`, in that same folder); they can hold PSN details |
| `make uninstall`, `reboot`, `log`, `app-log`, `status`                                              | [ps3_comms.py](tools/ps3_comms.py)'s, on the console                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `make app [SIGNED=1]`                                                                    | the vitals app, `build/vitals-app/vitals-app.pkg`, carrying the three debug levels' builds of libssl, libhttp, the boot plugin and the DNS kernel plugin, its own Mozilla bundle (installed when the console has none, in case the certificate update can't run), the example `redirects.txt` and `dns.txt`, and the changelog                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `make upload-app [SIGNED=1]`                                                             | builds the app and uploads it to the console's `/dev_hdd0/packages/`, where Package Manager installs it                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `make preview`                                                                           | on a Mac: the app's screens with made-up data (`build/preview/`, at 1280x720 and, as `-1080`, at 1920x1080)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

The console's commands need its address: copy the repository's `.env.example` to `.env` at the top of
the repository (not committed; it holds the Vita's address too) and set `PS3_HOST` there, or pass it (`make reboot PS3_HOST=192.168.1.20`). Calls to functions not written
yet are logged in every build.

## Reading Sony's modules

Decrypted modules (RPCS3: Utilities → Decrypt PS3 Binaries) are kept in the repository's
`dumps/`, which git ignores (they're Sony's), a folder per console and firmware: `dumps/ps3/4.93-cex/`,
with the console's CA files in `cert/` for the libssl host test and the XMB in `vsh/<cfw>/` (a custom
firmware may patch it; the modules are Sony's on any), and the Vita's in `dumps/psv/3.65/`. Its
`SOURCE.txt` says where they came from. The addresses the code quotes from Sony's modules are 4.93's.

```
python3 tools/prx_report.py ../dumps/ps3/4.93-cex/libssl.prx --exports
python3 tools/prx_report.py ../dumps/ps3/4.93-cex/libhttp.prx --imports --library cellSsl
python3 tools/ps3_disasm.py ../dumps/ps3/4.93-cex/libssl.prx fn SSL_get_error
python3 tools/ps3_disasm.py ../dumps/ps3/4.93-cex/libhttp.prx callers SSL_do_handshake
```

## Thanks

The full credits, both consoles', are in [CREDITS.md](../CREDITS.md), which the vitals app shows under Credits.

## License

All contributions to vitals for PS3 are released under the [Zero-Clause BSD license](../LICENSE)
(0BSD): you can use, copy, modify and distribute them for any purpose, with or without credit.

Not covered by it:

- **Sony's material:** no Sony module or certificate is in the repository; the tools read the
  decrypted modules from outside it.
- **Function names** in `tools/names/` come from RPCS3's module tables (GPL-2.0); they are the
  names of Sony's API, not RPCS3's code.
- **PS3DK**, the build environment, is fetched and built by [vitals-ps3-sdk](https://github.com/nyirsh/vitals-ps3-sdk) under its
  own licenses (MIT for its own code, GPL for GCC and binutils), with vitals' patch to its prx-gen.
  Only the linker script derived from its own is in this repository, under its MIT license.
- **Mbed TLS**, which libssl links, is under the Apache License 2.0, and is downloaded at build time;
  the patches to it, one of them devnoname120's, are in `vitals-ssl/crypto/`
  ([THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)).
