# Third-party notices

The `ps5-localsend` payload is an independent implementation of the LocalSend protocol. It does not include the LocalSend app's source code, logo, or artwork. The project is not affiliated with the LocalSend maintainers or Sony Interactive Entertainment.

## Code adapted for the Media launcher

`src/launcher.c` adapts the PS5 Media shortcut installation approach from these projects. It was modified to install a LocalSend shortcut, use this project's own icon, update the URL when the payload port changes, and keep launcher installation inside this ELF.

| Project | Upstream source | License |
| --- | --- | --- |
| `kvnhrt/ps5-browser-app` | [`src/app_installer.c`](https://github.com/kvnhrt/ps5-browser-app/blob/d427877/src/app_installer.c) | GPL-3.0-only ([license](https://github.com/kvnhrt/ps5-browser-app/blob/d427877/LICENSE)) |
| `owendswang/ps5-web-file-manager` | [`src/app_installer.c`](https://github.com/owendswang/ps5-web-file-manager/blob/3659cbb/src/app_installer.c) | GPL-3.0-or-later ([license](https://github.com/owendswang/ps5-web-file-manager/blob/3659cbb/LICENSE), [license statement](https://github.com/owendswang/ps5-web-file-manager/blob/3659cbb/README.md#license)) |

The combined `ps5-localsend` payload is distributed under GPL-3.0-only. The complete GPLv3 text is in [LICENSE](LICENSE). The original projects retain their own copyrights and licenses.

## Build dependency

The project builds with [`ps5-payload-dev/sdk` v0.44](https://github.com/ps5-payload-dev/sdk/tree/v0.44). Its [README license section](https://github.com/ps5-payload-dev/sdk/tree/v0.44#license) states GPLv3-or-later for most files and BSD licenses for FreeBSD headers. The SDK is downloaded by the build workflow and is not vendored in this repository. Source for the pinned SDK version is available in its [v0.44 source archive](https://github.com/ps5-payload-dev/sdk/archive/refs/tags/v0.44.tar.gz).

## Protocol reference

The [LocalSend protocol](https://github.com/localsend/protocol) and the [LocalSend app](https://github.com/localsend/localsend) were used as interoperability references. The LocalSend app is licensed under [Apache-2.0](https://github.com/localsend/localsend/blob/main/LICENSE). This repository does not include code or assets from that app.

The `assets/icon0.svg` source and its generated `assets/icon0.png` are original project assets and are licensed under GPL-3.0-only with the rest of this project.
