# ps5-localsend

A native PlayStation 5 ELF payload implementing the [LocalSend protocol](https://github.com/localsend/protocol) using the [PS5 payload SDK](https://github.com/ps5-payload-dev/sdk). It appears under the PS5's console name (for example, `PS5-090`) on the local network and receives files from LocalSend clients into `/data/localsend`.

## Current support

- LocalSend v2 discovery on UDP multicast `224.0.0.167:53317`, plus HTTP `/register` and `/info`.
- HTTP `/prepare-upload`, `/upload`, and `/cancel` with per-file session tokens, content-length or chunked uploads, size checks, SHA-256 verification, and filename sanitization.
- Headless receiving into `/data/localsend`. Uploaded files get a random prefix to avoid replacing existing files. Transfers stay disabled until a PIN is configured.
- Command-line sending to HTTP or HTTPS LocalSend peers with the standard prepare/upload flow. HTTPS uses the PS5's `libSceHttp`.
- PIN-protected LocalSend `/prepare-download` and `/download` API, plus a responsive browser dashboard for downloading PS5 files and sending them to a discovered peer or a manually entered IPv4 address.

HTTPS receiving, approval for incoming uploads, and an on-console user interface are not implemented yet. The payload advertises `protocol: http`; it advertises `download: true` after PIN setup. Clients sending to it must support unencrypted LocalSend peers. HTTPS outbound mode accepts self-signed peer certificates without verifying a remembered fingerprint. Use only on a trusted LAN. This is an independent native protocol implementation rather than a build of LocalSend's Flutter interface.

## Build

Download and install [ps5-payload-sdk v0.44](https://github.com/ps5-payload-dev/sdk/releases/tag/v0.44), then:

```sh
PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk make
```

The output is `ps5-localsend.elf`. To run host integration tests:

```sh
make HOST=1 test
```

Deploy the ELF using a supported PS5 ELF loader. The payload stays running and discovers LocalSend peers. A writable `/data` partition is required. On first startup it installs a **LocalSend** shortcut in the PS5 Media tab; opening the tile loads the dashboard at `http://127.0.0.1:53317/`. The dashboard opens without a PIN. On first run, open it from the **PS5 Media tile** and choose a six-digit PIN. Setup is restricted to the console's loopback address; LAN browsers can view the setup message but cannot claim the PIN. Until setup is complete, the payload rejects file upload, download, and send requests. A salted PBKDF2-SHA-256 PIN hash is stored in `/data/localsend/config` with owner-only permissions and survives a payload restart. The directory is restricted to the payload owner. Existing `.pin` files are migrated on startup and removed after the config is saved.

After setup, open the tile or `http://<PS5-IP>:53317/` in a browser and enter the PIN to view files, download them, or send one to a discovered peer or manual IPv4 address. The dashboard itself remains accessible without entering a PIN. The page uses HTTP, so enter the PIN only on a trusted LAN. LocalSend clients can also use the PIN with `/prepare-download`.

`LOCALSEND_DIR`, `LOCALSEND_PORT`, `LOCALSEND_ALIAS`, and `LOCALSEND_PIN` can override the defaults if provided by the loader. Without `LOCALSEND_ALIAS`, the payload reads the console name from `libSceSystemService`. `LOCALSEND_PIN` must contain exactly six digits; when set, it takes precedence over the stored PIN and skips first-run setup. This also makes local testing easier.

To send a file from the PS5, start another instance with arguments (for example using a loader that supports payload arguments):

```text
ps5-localsend.elf --send /data/localsend/example.bin 192.168.1.50 53317 --https
```

The port is optional and defaults to 53317. Omit `--https` to send to a peer using LocalSend's unencrypted HTTP mode.

## Releases

GitHub Actions builds and tests on pushes. Publishing a GitHub release builds a new PS5 ELF with the pinned SDK and attaches the ELF, SHA-256 checksum, GPLv3 text, third-party notices, LocalSend's Apache-2.0 license texts, and source directions to that release.

## Validation

`make HOST=1 test` exercises discovery data, content-length and chunked uploads, download, first-run PIN setup and persistence, browser controlled sending, and SHA-256 checks. The ELF also built with SDK v0.44 and completed live send and receive smoke tests on a jailbroken PS5 using HTTP. A live chunked upload passed with its stored SHA-256 verified. HTTPS outbound passed a live upload to a self-signed test endpoint on the LAN. The PS5 system service returned the console name, the Media tile opened the dashboard, first-run PIN setup worked on hardware, and the official LocalSend app successfully sent an image in a prior build.

## License and source

Copyright (C) 2026 heydemoura. The project code is distributed under **GPL-3.0-only**; see [LICENSE](LICENSE). The official LocalSend icon is included under Apache-2.0, with the original copyright and license retained. The dashboard uses the official website's light and dark color values. Asset provenance, licensing, the adapted Media launcher, and the SDK's license are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

This is an independent LocalSend protocol implementation and is not affiliated with or endorsed by the LocalSend maintainers or Sony Interactive Entertainment. The embedded dashboard is original project code; no LocalSend app or web app code was copied.

When distributing the ELF, provide the corresponding source from the same release tag and follow [RELEASING.md](RELEASING.md). Contributions are covered by [CONTRIBUTING.md](CONTRIBUTING.md).
