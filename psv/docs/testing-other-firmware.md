# Helping vitals support your firmware

vitals is built and tested on PS Vita firmware 3.60 and 3.65. If you're on another firmware (for
example 3.74), these steps collect what's needed to look at supporting it. **Nothing here changes
your system**: vitals can't be installed on another firmware, and there's no way to force it, because
its kernel plugin and browser provider only recognise those firmwares' exact modules.

You need: a hacked Vita with VitaShell, the Vita and a computer on the same network, and an FTP client
on the computer (FileZilla, or your file manager). In VitaShell, **SELECT** starts its FTP server and
shows the address and port (usually 1337).

## 1. Your setup

Copy this and fill it in:

```
Firmware version (Settings > System > System Information):
Model (PCH-1000, PCH-2000 or PS TV):
Retail, testkit or devkit:
How it's hacked (Ensō, h-encore, HENlo, other), and its version:
```

## 2. Two file hashes

1. Connect to the Vita with FTP.
2. Download these two files to your computer:
   - `/vs0:/sys/external/libssl.suprx`
   - `/vs0:/sys/external/libhttp.suprx`
3. Get their SHA-256 hashes, in a terminal in the folder you saved them to:
   - Windows: `certutil -hashfile libssl.suprx SHA256` and `certutil -hashfile libhttp.suprx SHA256`
   - macOS: `shasum -a 256 libssl.suprx libhttp.suprx`
   - Linux: `sha256sum libssl.suprx libhttp.suprx`
4. Send the two hashes only, not the files (they're Sony's).

## 3. Your plugins

Over FTP, open `/ur0:/tai/config.txt` and send the lines that don't start with `#`. Plugins that replace
the same system modules, such as `iTLS-Enso` or `reAuth`, matter for vitals.

## 4. A test run

This uses Sony's own TLS, so it shows what your firmware does today.

1. Copy `vitals-app.vpk` from the releases page to the Vita and install it with VitaShell.
2. Open the vitals app. It should say "This system isn't supported" and offer only the connection test
   and the documents. Write down the firmware it shows at the top.
3. Run the **connection test**, and press **START** when it's done to save its report.
4. Over FTP, download the newest file in `/ux0:/data/vitals/reports/`. It lists every request the test
   made, so read through it first if you'd like to.
5. Send the report and what the app said.

You can delete the app's bubble afterwards.

## For maintainers: what a firmware needs

The firmware's modules don't have to come from users: Sony's own update files have them
(`dumps/psv/<version>/PSP2UPDAT.PUP`, see `dumps/psv/SOURCE.txt`). What vitals recognises is in
[vitals/firmware_profiles.h](../common/include/vitals/firmware_profiles.h):

| Module | What's checked | 3.60 NID | 3.65 NID |
| --- | --- | --- | --- |
| SceKernelModulemgr | module NID, text size, metadata offset, and its family | `0x726C6635` | `0x781C6F50` |
| SceWebKit, retail | module NID, segment sizes, metadata, callback and vtable offsets, the callback's bytes | `0x20163DF2` | `0xA33A93F7` |
| SceWebKit, testkit | as retail | `0x87F5A440` | `0xE32C493D` |
| SceWebKit, devkit | as retail | `0x1A29EF0D` | `0x8DECCD66` |

SceKernelModulemgr comes in two families, 3.60 and 3.61, and 3.63 and later. A firmware in a known
family may still need its own bytes in [hook_guard.c](../vitals-boot/hook_guard.c). The installer's own
list is `supported_firmware` in [install.c](../vitals-app/install.c), which is the last thing to change.
The app's "isn't supported" check has no override on the Vita (`console_unsupported_allowed`), unlike
the PS3's `unsupported.ok`.

Reference hashes for the two libraries on 3.60 and 3.65 aren't recorded here yet: compare against the
files in that firmware's update, or a known-good console.
