# Credits

## nyirsh

- vitals for PS3 and PSV was made by nyirsh: modern TLS, HTTP and DNS for games and apps (on a PS3 with Cobra), or system-wide on Vita
- Sony's HTTP library rewritten from scratch as vitals-http, with vitals-ssl in place of Sony's libssl
- Custom http and dns redirections, with the ability to also provide custom certificates to the bundle

## Where vitals original idea comes from

- devnoname120: vitals originally started from his tls_fixer for the PS Vita, and the idea is his, modern TLS by running Mbed TLS where Sony's old TLS stack was. It then grew to become its very own distinct project. What it still carries from tls_fixer is the browser's TLS provider, the kernel plugin's injection, the certificate merging and updating, the original connection test applet and the patch that puts TLS 1.2's RSA key exchange back into Mbed TLS

## Vita homebrew

- SKGleba, for the iTLS-Enso plugin: his work updating the Vita's certificates is the foundation of vitals, along with his original installer and module-redirection code
- Reiko Asakura, for reAuth: its PSN sign-in redirect is what the starter redirect list does
- Team Molecule, for all of the love they poured into the PS Vita

## Tools and libraries

- Mbed TLS and TF-PSA-Crypto, the TLS in vitals-ssl, under the Apache License 2.0
- Everyone who works on VitaSDK and its packages, which every part of vitals is built with
- Mozilla's CA certificates, as curl publishes them
