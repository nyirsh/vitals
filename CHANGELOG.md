# Changelog

Every release of vitals, newest first.

## 1.4

- Added this very same changelog!
- The installer finds vitals in config.txt wherever you moved its line under \*KERNEL, and no longer adds it a second time
- Uninstalling removes vitals' line from config.txt wherever it is, not only from its own block
- When installing, reinstalling or updating, it is now possible to choose where to place the line in config.txt

## 1.3

- Added support for Firmware 3.60
- The app shows which version of vitals is installed, and if updates are available
- Debug output can be switched between Off, Basic and Full from the menu
- You can add your own certificates in ux0:data/vitals/custom-certs.pem to be trusted, even if self-signed
- The connection test now also checks every host on the redirect list
- Fixed a second run of the connection test failing
- Overall UI improved

## 1.2

- Fixed a crash with Adrenaline

## 1.1

- Fixed games being unable to read the redirect list from inside their sandbox
- The PSN sign-in redirect now follows the same redirect list as everything else, so it can be changed if Sony's servers move again

## 1.0

- First release
