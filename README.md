# ps5-localsend

A native PlayStation 5 ELF payload implementing the [LocalSend protocol](https://github.com/localsend/protocol) using the [PS5 payload SDK](https://github.com/ps5-payload-dev/sdk). It appears as **PS5 LocalSend** on the local network and receives files from LocalSend clients into `/data/localsend`.

## Current support

- LocalSend v2 discovery on UDP multicast `224.0.0.167:53317`, plus HTTP `/register` and `/info`.
- HTTP `/prepare-upload`, `/upload`, and `/cancel` with per-file session tokens, size checks, SHA-256 verification, and filename sanitization.
- Headless receiving into `/data/localsend`. Uploaded files get a random prefix to avoid replacing existing files.

Outbound sending, HTTPS, PIN approval, and an on-console user interface are not implemented yet. The payload currently advertises `protocol: http` and `download: false`; clients must support unencrypted LocalSend peers. Use only on a trusted LAN. This is an independent native protocol implementation rather than a build of LocalSend's Flutter interface.

## Build

Download and install [ps5-payload-sdk v0.44](https://github.com/ps5-payload-dev/sdk/releases/tag/v0.44), then:

```sh
PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk make
```

The output is `ps5-localsend.elf`. To run host integration tests:

```sh
make HOST=1 test
```

Deploy the ELF using a supported PS5 ELF loader. The payload stays running, discovers LocalSend peers, and auto accepts uploads. A writable `/data` partition is required. On a host, `LOCALSEND_DIR`, `LOCALSEND_PORT`, and `LOCALSEND_ALIAS` can override the defaults; these environment variables also work if provided by a payload loader.

## Releases

GitHub Actions builds and tests on pushes. Publishing a GitHub release builds a new PS5 ELF with the pinned SDK and attaches the ELF and SHA-256 checksum to that release.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
