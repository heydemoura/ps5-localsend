# Public release checklist

1. Keep this repository, the GPLv3 text in `LICENSE`, `THIRD_PARTY_NOTICES.md`, both `THIRD_PARTY_LICENSES/LocalSend-*.txt` files, the official icon PNG, the tests, and the build workflow available at the released tag.
2. Confirm every included or adapted third-party component is recorded in `THIRD_PARTY_NOTICES.md`, with its license and upstream source. Do not add copied code or artwork without compatible redistribution terms.
3. Run `make HOST=1 test` and build the PS5 ELF with the SDK version pinned in `.github/workflows/build.yml`. Check the SDK URL and SHA-256 when changing versions.
4. Publish a release from a tag on the source commit. GitHub provides source archives for the tag. The release workflow attaches the ELF, its SHA-256 checksum, a source directions file linking to this repository's tagged source and the pinned SDK source, the GPLv3 text, the third-party notices, and both LocalSend Apache-2.0 license texts.
5. Verify the release workflow actually finishes and all seven attached files download correctly. Keep the tagged source and the SDK source link accessible while the binary is offered for download.

The release program code is GPL-3.0-only; the embedded official LocalSend logo retains its Apache-2.0 license. Recipients must be able to obtain the complete corresponding source, including the code and build scripts for this ELF and the source for any linked SDK components. The PS5's own system libraries are loaded at runtime and are not bundled in the release.
