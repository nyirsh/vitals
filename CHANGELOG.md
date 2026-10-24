# Changelog

Every release of vitals, newest first.

## 1.4 (2026-10-24)

- A Changelog page in the menu lists what changed in each version
- The installer finds vitals in config.txt wherever you moved its line under *KERNEL, and no longer adds it a second time
- Uninstalling removes vitals' line from config.txt wherever it is, not only from its own block

## 1.3 (2026-10-23)

- Firmware 3.60 is now supported, as well as 3.65
- The app shows which version of vitals is installed, and offers an update when it differs from the one the app carries
- The app checks GitHub and GitLab for a newer release when it opens
- Debug output can be switched between Off, Basic and Full from the menu
- You can add your own certificates in ux0:data/vitals/custom-certs.pem, for example for a community server with a self-signed certificate
- A self-signed certificate is trusted when it matches one in the store exactly
- The connection test now also checks every host on the redirect list, and shows those results more clearly
- The connection test's detail pages show which page you're on
- Fixed a second run of the connection test failing
- Fixed a small display glitch in the installed-version detection
- The confirm and back buttons follow the system setting, so Circle confirms on Japanese consoles
- The menu can be used with either analog stick too
- Improved layout, and extended credits

## 1.2 (2026-10-22)

- Fixed a crash with Adrenaline: vitals now leaves Adrenaline alone

## 1.1 (2026-10-22)

- Fixed games being unable to read the redirect list from inside their sandbox
- The PSN sign-in redirect now follows the same redirect list as everything else, so it can be changed if Sony's servers move again

## 1.0 (2026-10-22)

- First release
