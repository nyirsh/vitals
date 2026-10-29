# vitals-ssl

Sony's SSL library (`SceLibSsl`, the `sceSsl` API) to be written from scratch, as a user module
exported under libssl's own library and function NIDs ([libssl_api.yml.in](libssl_api.yml.in)),
all 109 of them. For now it's a skeleton: every export logs its name (with `DEBUG=1` or `2`) and
fails with `SCE_SSL_ERROR_INTERNAL` (`0x80435026`), or returns `NULL` where it returns a pointer.
Nothing installs it; the app still installs the copy of Sony's libssl it bundles
([docs/libssl.md](../docs/libssl.md)).

## Building

```bash
make            # build/vitals-ssl/libssl.suprx
make DEBUG=1    # build/vitals-ssl-debug1/: start-up and every call to an export that isn't written yet
```

## Exports

The NIDs are those of the libssl the app bundles ([vitals-app/assets/lssl.suprx](../vitals-app/assets/lssl.suprx)),
read from its export table, and so is the module NID (`0xB1620F91`; the NID database's 3.60
entry gives `0x9CD6CA85`). Each stub's comment gives its NID and the address of Sony's function in
that copy, whose code is mapped at `0x81000000`, as the starting point for working out what it does.

| Library | NID | Functions | Named |
| --- | --- | --- | --- |
| `SceSsl` | `0xCAF5F2E9` | 11 | all, as `<psp2/libssl.h>` declares them ([src/ssl.c](src/ssl.c)) |
| `SceSslInternal` | `0x68D6C3FF` | 98 | 3 from the NID database: `sceSslInternalGetCertificateAuthority`, `sceSslInternalIsInitalized` (its spelling) and `sceSslInternalWrite`; the others are `sceSslInternal<NID>` ([src/internal.c](src/internal.c)) |

`SceSslInternal` is the part Sony's own modules use for their TLS: Sony's libhttp alone imports 65
of its functions. None of their arguments are known yet, so their stubs take none.

## Layout

| File | Role |
|---|---|
| [src/ssl.c](src/ssl.c) | `SceSsl`, and the stub every unwritten export calls |
| [src/internal.c](src/internal.c) | `SceSslInternal` |
| [src/platform_vita.c](src/platform_vita.c) | module start and stop |
