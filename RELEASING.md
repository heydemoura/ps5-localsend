# Public release checklist

1. Keep this repository, the GPLv3 text in `LICENSE`, `THIRD_PARTY_NOTICES.md`, the icon's SVG source, the tests, and the build workflow available at the released tag.
2. Confirm every included or adapted third-party component is recorded in `THIRD_PARTY_NOTICES.md`, with its license and upstream source. Do not add copied code or artwork without compatible redistribution terms.
3. Run `make HOST=1 test` and build the PS5 ELF with the SDK version pinned in `.github/workflows/build.yml`. Check the SDK URL and SHA-256 when changing versions.
4. Publish a release from a tag on the source commit. GitHub provides source archives for the tag. The release workflow attaches the ELF, its SHA-256 checksum, a source directions file linking to this repository's tagged source and the pinned SDK source, the GPLv3 text, and the third-party notices.
5. Verify the release workflow actually finishes and the five attached files download correctly. Keep the tagged source and the SDK source link accessible while the binary is offered for download.

The release binary is GPL-3.0-only. Recipients must be able to obtain the complete corresponding source, including the code and build scripts for this ELF and the source for any linked SDK components. The PS5's own system libraries are loaded at runtime and are not bundled in the release.
