# Changelog

## 2.1

- (PS3) Brought vitals to PS3 too with the same functionalities, except that the XMB is not yet supported
- (RPCS3) Installers for Windows, macOS and Linux
- (vitals-app) Improved app UI, added DNS redirection tests too
- (vitals-app) Added options, you can now disable specific functions on the fly
- (Vita) All vitals files are moved to ux0:data/vitals/system: not writing to vs0 anymore makes it safer

## 2.0

- (Vita) Sony's SSL library has been replaced by vitals own full rewrite
- (Vita) Vitals's HTTP library now uses the SSL library just like any other Vita's module would do and it has been stripped of MBed TLS entirely
- (Vita) Updated MBed TLS to version 4.2.0 thanks to devnoname120's patches

## 1.6

- (Vita) Added support for http proxies

## 1.5

- (Vita) Sony's HTTP library has been replaced by vitals own full rewrite
- (Vita) Redirected hosts get a higher timeout, in case community servers are slow to answer
- (Vita) Added DNS resolution redirection
- (Vita) Added the ability to change User-Agent
- (Vita) Removed reauth for it is now redundant, the PlayStation Store works with vitals' own HTTP library too!
- (Vita) Fixed an issue with the browser that allowed websites with a bad certificate to load in case after a refresh
- (Vita) The connection test now checks certificates against badssl.com
- (Vita) Apps and games now use the proxy set in the network settings, as they do without vitals

## 1.4

- (Vita) Added this very same changelog!
- (Vita) The installer finds vitals in config.txt wherever you moved its line under \*KERNEL, and no longer adds it a second time
- (Vita) Uninstalling removes vitals' line from config.txt wherever it is, not only from its own block
- (Vita) When installing, reinstalling or updating, it is now possible to choose where to place the line in config.txt
- (Vita) The app now shows when the certificates were last updated
- (Vita) The connection test saves its log only when you press START
- (Vita) UI improvements

## 1.3

- (Vita) Added support for Firmware 3.60
- (Vita) The app shows which version of vitals is installed, and if updates are available
- (Vita) Debug output can be switched between Off, Basic and Full from the menu
- (Vita) You can add your own certificates in ux0:data/vitals/custom-certs.pem to be trusted, even if self-signed
- (Vita) The connection test now also checks every host on the redirect list
- (Vita) Fixed a second run of the connection test failing
- (Vita) Overall UI improved

## 1.2

- (Vita) Fixed a crash with Adrenaline

## 1.1

- (Vita) Fixed games being unable to read the redirect list from inside their sandbox
- (Vita) The PSN sign-in redirect now follows the same redirect list as everything else, so it can be changed if Sony's servers move again

## 1.0

- (Vita) First release
