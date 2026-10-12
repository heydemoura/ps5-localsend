# Third-party notices

The `ps5-localsend` payload is an independent implementation of the LocalSend protocol. It includes the official LocalSend logo under Apache-2.0 and uses colors from the official LocalSend website. It does not include LocalSend app or website code. This unofficial PS5 port is not affiliated with or endorsed by the LocalSend maintainers or Sony Interactive Entertainment.

## Official LocalSend logo and website palette

`assets/icon0.png` is an unmodified copy of [`app/assets/img/logo-512.png`](https://github.com/localsend/localsend/blob/14f3a87426eedffaa9d87d011132eca5501abeb8/app/assets/img/logo-512.png) from `localsend/localsend` at commit `14f3a87426eedffaa9d87d011132eca5501abeb8` (SHA-256 `d7e6016dd11ff9ce48ed6f1f24d8090b85d70982a450f1f1e51943739e166a48`). Copyright 2022-2026 Tien Do Nam, as stated in [the upstream Apache-2.0 license](https://github.com/localsend/localsend/blob/14f3a87426eedffaa9d87d011132eca5501abeb8/LICENSE). That license is copied at [`THIRD_PARTY_LICENSES/LocalSend-APACHE-2.0.txt`](THIRD_PARTY_LICENSES/LocalSend-APACHE-2.0.txt). The ELF embeds the PNG for the PS5 Media tile and serves the same bytes as `/icon.png` in the dashboard.

The dashboard's light and dark color values are taken from [`localsend/website`'s stylesheet](https://github.com/localsend/website/blob/570575e939211e42bc77344e704b76f985ecc317/app/assets/css/style.css) at commit `570575e939211e42bc77344e704b76f985ecc317`. The website's [Apache-2.0 license](https://github.com/localsend/website/blob/570575e939211e42bc77344e704b76f985ecc317/LICENSE), including its Copyright 2022-2026 Tien Nam Do notice, is copied to [`THIRD_PARTY_LICENSES/LocalSend-website-APACHE-2.0.txt`](THIRD_PARTY_LICENSES/LocalSend-website-APACHE-2.0.txt). The [homepage](https://localsend.org/) credits Skyade for its design. No layout, JavaScript, or other website code was copied.

The project code remains GPL-3.0-only. The LocalSend logo retains its Apache-2.0 license and original copyright. The licenses do not grant an endorsement or trademark permission.

## Code adapted for the Media launcher

`src/launcher.c` adapts the PS5 Media shortcut installation approach from these projects. It was modified to install a LocalSend shortcut, use the official LocalSend logo above, update the URL when the payload port changes, and keep launcher installation inside this ELF.

| Project | Upstream source | License |
| --- | --- | --- |
| `kvnhrt/ps5-browser-app` | [`src/app_installer.c`](https://github.com/kvnhrt/ps5-browser-app/blob/d427877/src/app_installer.c) | GPL-3.0-only ([license](https://github.com/kvnhrt/ps5-browser-app/blob/d427877/LICENSE)) |
| `owendswang/ps5-web-file-manager` | [`src/app_installer.c`](https://github.com/owendswang/ps5-web-file-manager/blob/3659cbb/src/app_installer.c) | GPL-3.0-or-later ([license](https://github.com/owendswang/ps5-web-file-manager/blob/3659cbb/LICENSE), [license statement](https://github.com/owendswang/ps5-web-file-manager/blob/3659cbb/README.md#license)) |

The combined `ps5-localsend` program code is distributed under GPL-3.0-only. The complete GPLv3 text is in [LICENSE](LICENSE). The original projects retain their own copyrights and licenses; the official logo retains Apache-2.0 as described above.

## Build dependency

The project builds with [`ps5-payload-dev/sdk` v0.44](https://github.com/ps5-payload-dev/sdk/tree/v0.44). Its [README license section](https://github.com/ps5-payload-dev/sdk/tree/v0.44#license) states GPLv3-or-later for most files and BSD licenses for FreeBSD headers. The SDK is downloaded by the build workflow and is not vendored in this repository. Source for the pinned SDK version is available in its [v0.44 source archive](https://github.com/ps5-payload-dev/sdk/archive/refs/tags/v0.44.tar.gz).

## Protocol reference

The [LocalSend protocol](https://github.com/localsend/protocol) and the [LocalSend app](https://github.com/localsend/localsend) were used as interoperability references. The LocalSend app is licensed under [Apache-2.0](https://github.com/localsend/localsend/blob/main/LICENSE). Apart from the attributed logo above, this repository does not include code or assets from that app.

The `assets/webui.html` dashboard implementation is original project code and is licensed under GPL-3.0-only. It does not incorporate code from the separate LocalSend web app.
