# Changelog

## 1.6

- Added support for http proxies

## 1.5

- Sony's HTTP library is replaced by vitals own full rewrite in every app, game and the system itself
- Redirected hosts get a higher timeout, in case community servers are slow to answer
- Added DNS resolution redirection
- Added the ability to change User-Agent
- Removed reauth for it is now redundant, the PlayStation Store works with vitals' own HTTP library too!
- Fixed an issue with the browser that allowed websites with a bad certificate to load in case after a refresh
- The connection test now checks certificates against badssl.com
- Apps and games now use the proxy set in the network settings, as they do without vitals

## 1.4

- Added this very same changelog!
- The installer finds vitals in config.txt wherever you moved its line under \*KERNEL, and no longer adds it a second time
- Uninstalling removes vitals' line from config.txt wherever it is, not only from its own block
- When installing, reinstalling or updating, it is now possible to choose where to place the line in config.txt
- The app now shows when the certificates were last updated
- The connection test saves its log only when you press START
- UI improvements

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
