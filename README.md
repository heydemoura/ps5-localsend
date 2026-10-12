# ps5-localsend

A native PlayStation 5 ELF payload implementing the [LocalSend protocol](https://github.com/localsend/protocol) using the [PS5 payload SDK](https://github.com/ps5-payload-dev/sdk). It appears as **PS5 LocalSend** on the local network and receives files from LocalSend clients into `/data/localsend`.

## Current support

- LocalSend v2 discovery on UDP multicast `224.0.0.167:53317`, plus HTTP `/register` and `/info`.
- HTTP `/prepare-upload`, `/upload`, and `/cancel` with per-file session tokens, size checks, SHA-256 verification, and filename sanitization.
- Headless receiving into `/data/localsend`. Uploaded files get a random prefix to avoid replacing existing files.
- Command-line sending to HTTP or HTTPS LocalSend peers with the standard prepare/upload flow. HTTPS uses the PS5's `libSceHttp` and has not yet been tested on hardware.
- PIN-protected LocalSend `/prepare-download` and `/download` API, plus a simple browser page for retrieving files from the PS5.

HTTPS receiving, peer discovery for outbound sends, approval for incoming uploads, and an on-console user interface are not implemented yet. The payload advertises `protocol: http` and `download: true`; clients sending to it must support unencrypted LocalSend peers. HTTPS outbound mode accepts self-signed peer certificates without verifying a remembered fingerprint. Use only on a trusted LAN. This is an independent native protocol implementation rather than a build of LocalSend's Flutter interface.

## Build

Download and install [ps5-payload-sdk v0.44](https://github.com/ps5-payload-dev/sdk/releases/tag/v0.44), then:

```sh
PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk make
```

The output is `ps5-localsend.elf`. To run host integration tests:

```sh
make HOST=1 test
```

Deploy the ELF using a supported PS5 ELF loader. The payload stays running, discovers LocalSend peers, and auto accepts uploads. A writable `/data` partition is required. The payload shows a six-digit download PIN in a PS5 notification and writes it to the loader log. Open `http://<PS5-IP>:53317/` in a browser and enter the PIN to download files from `/data/localsend`. LocalSend clients can use that PIN with `/prepare-download`.

`LOCALSEND_DIR`, `LOCALSEND_PORT`, `LOCALSEND_ALIAS`, and `LOCALSEND_PIN` can override the defaults if provided by the loader. `LOCALSEND_PIN` must contain exactly six digits. This also makes local testing easier.

To send a file from the PS5, start another instance with arguments (for example using a loader that supports payload arguments):

```text
ps5-localsend.elf --send /data/localsend/example.bin 192.168.1.50 53317 --https
```

The port is optional and defaults to 53317. Omit `--https` to send to a peer using LocalSend's unencrypted HTTP mode.

## Releases

GitHub Actions builds and tests on pushes. Publishing a GitHub release builds a new PS5 ELF with the pinned SDK and attaches the ELF and SHA-256 checksum to that release.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
