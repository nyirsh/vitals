# Credits

## nyirsh

- vitals for PS3 and PSV was made by nyirsh: modern TLS, HTTP and DNS for games and apps (on a PS3 with Cobra), or system-wide on Vita
- System modules rewritten from scratch: libssl and libhttp, to completely replace Sony's on both consoles (vitals-ssl and vitals-http)
- Custom http and dns redirections, with the ability to also provide custom certificates to the bundle

## Where vitals original idea comes from

- devnoname120: vitals originally started from his tls_fixer for the PS Vita, and the idea is his, modern TLS by running Mbed TLS where Sony's old TLS stack was. It then grew to become its very own distinct project. What the Vita's still carries from tls_fixer is the browser's TLS provider, the kernel plugin's injection, the certificate merging and updating and the original connection test applet; both consoles carry, other than the spirit, the patch that puts TLS 1.2's RSA key exchange back into Mbed TLS

## Vita homebrew

- SKGleba, for the iTLS-Enso plugin: his work updating the Vita's certificates is the foundation of vitals, along with his original installer and module-redirection code
- Reiko Asakura, for reAuth: its PSN sign-in redirect is what the starter redirect list does
- Team Molecule, for all of the love they poured into the PS Vita

## PS3 homebrew

- aldostools, webMAN MOD's creator: the boot popup finds the XMB's notification functions the way webMAN MOD does, and shows its icon the way webMAN MOD's show_msg_with_icon does. webMAN MOD's lv2 peek, kernel plugin loader and FTP server are what made the DNS plugin's work on the console possible, and his Mamba showed how Cobra's kernel plugins are loaded
- PHTNC, for the code behind webMAN MOD's notifications with icons
- Mysis, for the research into the XMB's explore_plugin on psdevwiki
- Evilnat, for the CFW vitals runs on, and everyone behind Cobra, whose path redirection and payload loading put vitals' modules in place

## Tools and libraries

- Mbed TLS and TF-PSA-Crypto, the TLS in vitals' libssl and in the apps' own downloads, under the Apache License 2.0
- Everyone who works on VitaSDK and its packages, and on PS3DK and PSL1GHT, which every part of vitals is built with
- RPCS3, for running and testing vitals, and for the names of Sony's functions in its module tables
- Mozilla's CA certificates, as curl publishes them
- Everyone who documents the PS3 on psdevwiki
