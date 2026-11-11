# Helping vitals support your firmware

vitals is tested on firmware 4.93 with Evilnat's Cobra CFW. If you're on another firmware (for
example 4.92) or on PS3HEN, these steps collect what's needed to support it. Nothing here changes
your console until step 4, and you can undo step 4 from the vitals app.

You need: webMAN MOD running, the PS3 and a computer on the same network, and an FTP client on the
computer (FileZilla, or your file manager). Below, `PS3_IP` is your console's IP address (webMAN
shows it, or Settings > Network Settings > Settings and Connection Status List).

**Do steps 1 to 3 before installing vitals.** If vitals is already installed, uninstall it from the
vitals app first and reboot.

## 1. Your setup

Copy this and fill it in:

```
Firmware version (e.g. 4.92):
CEX or DEX:
CFW or HEN, and its version (e.g. Evilnat 4.92 Cobra, or PS3HEN 3.x):
webMAN MOD version:
```

## 2. Two file hashes

1. Connect to the PS3 with FTP (`PS3_IP`, port 21).
2. Download these two files to your computer:
   - `/dev_flash/sys/external/libssl.sprx`
   - `/dev_flash/sys/external/libhttp.sprx`
3. Get their SHA-256 hashes, in a terminal in the folder you saved them to:
   - Windows: `certutil -hashfile libssl.sprx SHA256` and `certutil -hashfile libhttp.sprx SHA256`
   - macOS: `shasum -a 256 libssl.sprx libhttp.sprx`
   - Linux: `sha256sum libssl.sprx libhttp.sprx`
4. Send the two hashes only, not the files (they're Sony's).

## 3. Seven lines of kernel memory

Open each of these addresses in a browser on your computer, replacing `PS3_IP`:

```
http://PS3_IP/peek.lv2?3000
http://PS3_IP/peek.lv2?3651F0
http://PS3_IP/peek.lv2?365210
http://PS3_IP/peek.lv2?320F20
http://PS3_IP/peek.lv2?320F60
http://PS3_IP/peek.lv2?122260
http://PS3_IP/peek.lv2?122460
```

Each page shows a table of hex numbers. Copy only the **first line** of each, the one that starts
with the address you opened, for example:

```
00003000 80 00 00 00 00 34 FB B0 80 00 00 00 00 35 57 A0
```

These are addresses inside the system's kernel, nothing personal. Please don't send a full kernel
dump (`/dump.ps3?lv2`): it can contain your console's unique IDs.

## 4. A test run

1. Install the vitals app: copy the vitals `.pkg` to the PS3 and install it from Package Manager.
2. The app only installs vitals on 4.93 CEX with Cobra; elsewhere it says "This system isn't
   supported". To install it anyway for this test, create an empty file named `unsupported.ok` in
   `/dev_hdd0/vitals/flags/` over FTP (create the `vitals` and `flags` folders if they aren't there;
   in FileZilla: right-click, Create new file). The app then says "installing anyway".
3. Open the vitals app (Network column), install vitals, then go to **Options**, set **Debug
   output** to **Full debug**, and press **START** (it reboots the console).
4. **Don't sign in to PSN** for this test: the debug log records network traffic.
5. About 30 seconds after the console starts, a "vitals" popup appears. Write down what it says
   (TLS, HTTP, Redirects, DNS rules), or take a photo. If no popup appears within a minute, say so.
6. Open the vitals app, run the **connection test**, and press **START** when it's done to save its
   report.
7. Over FTP, download:
   - `/dev_hdd0/vitals/logs/vitals.log`
   - the newest file in `/dev_hdd0/vitals/reports/`
8. Send the popup's text, `vitals.log` and the report. The report's `console=` line has your
   firmware, CEX or DEX, and Cobra or PS3HEN, as the app read them.
9. Back in the vitals app, set **Debug output** to **Off** in Options and press **START**.

If the console freezes during the test, hold the power button until it turns off, then turn it on
again: after a boot that didn't end properly, vitals leaves out the part that could cause it.

## If you're on PS3HEN

Please also say:

```
Which plugin list does your HEN read (/dev_hdd0/boot_plugins.txt, boot_plugins_hen.txt, other)?
Did the vitals popup appear after enabling HEN?
```

## For maintainers: 4.93 CEX (Evilnat Cobra), for comparison

```
libssl.sprx   192798 bytes  c624069e5192d6b31bbe2dc73af8a41e31f39c4657975ff23d435004ab4f00ab
libhttp.sprx  121490 bytes  7e316dcf5ebd5e687c7d7846f1cca5e289a47355c1940091b389ddde7492a32e

00003000 80 00 00 00 00 34 FB B0 80 00 00 00 00 35 57 A0   lv2's TOC (LV2_TOC_SLOT -> LV2_TOC)
003651F0 80 00 00 00 00 32 0F 80 80 00 00 00 00 32 0F 68   syscall 707's descriptor (second word)
00365210 80 00 00 00 00 32 0F 20 80 00 00 00 00 32 0F 08   syscall 710's descriptor (first word)
00320F20 80 00 00 00 00 12 22 60 80 00 00 00 00 34 FB B0   sendto's handler and TOC
00320F60 00 00 00 00 00 00 00 00 80 00 00 00 00 12 24 64   recvfrom's handler (second word)
00122260 F8 21 FF 61 7C 08 02 A6 FB 41 00 70 FB 61 00 78   sendto's first instructions
00122460 4E 80 00 20 F8 21 FF 61 7C 08 02 A6 FB 41 00 70   recvfrom's first instructions (from 0x122464)
```

All seven matching means the DNS plugin's addresses (vitals-dns/src/lv2_493.h) hold on that
firmware too; the plugin still checks its function signatures itself at load, and the test run's
vitals.log says whether it hooked. Taken with vitals' DNS plugin loaded but not hooked (no rules),
so the syscall table held lv2's own descriptors.
