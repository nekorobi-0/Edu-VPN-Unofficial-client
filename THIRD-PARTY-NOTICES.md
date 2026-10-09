# Third-party notices

Original project code and documentation are licensed under the MIT license in [LICENSE](LICENSE). This license does not replace the licenses of the following components. Full upstream license texts and copyright notices are preserved in [licenses/](licenses/).

| Component | Pinned version | License | Source |
|---|---|---|---|
| wireguard-go, unmodified | `v0.0.0-20261006164505-2631ce99a06f` | MIT | https://git.zx2c4.com/wireguard-go/ |
| gVisor | `v0.0.0-20250503011706-39ed1f5ac29c` | Apache-2.0 | https://gvisor.dev/ |
| golang.org/x/crypto | `v0.37.0` | BSD-3-Clause | https://go.googlesource.com/crypto/ |
| golang.org/x/net | `v0.39.0` | BSD-3-Clause | https://go.googlesource.com/net/ |
| golang.org/x/sys | `v0.32.0` | BSD-3-Clause | https://go.googlesource.com/sys/ |
| golang.org/x/time | `v0.7.0` | BSD-3-Clause | https://go.googlesource.com/time/ |
| github.com/google/btree | `v1.1.2` | Apache-2.0 | https://github.com/google/btree |
| golang.zx2c4.com/wintun Go bindings | `v0.0.0-20230126152724-0fa3db229ce2` | MIT | https://git.zx2c4.com/wintun-go/ |
| github.com/wmnsk/milenage | `v1.2.1` | MIT | https://github.com/wmnsk/milenage |
| Go standard library and runtime | build toolchain; CI uses Go 1.27.2 | BSD-3-Clause plus notices accompanying Go | https://go.dev/ |

## Build-only resource generator

The manifest generator under `tools/windowsmanifest/` uses `github.com/tc-hib/winres` v0.3.1 (0BSD, https://github.com/tc-hib/winres), `github.com/nfnt/resize` v0.0.0-20180221191011-83c6a9932646 (MIT, https://github.com/nfnt/resize), and `golang.org/x/image` v0.12.0 (BSD-3-Clause, https://go.googlesource.com/image/). These dependencies run only during builds; their code is not linked into the client executable. Their notices are preserved under `licenses/build-tools/`.

## Signed Wintun driver

Windows executables embed the unmodified official signed Wintun 0.14.1 DLLs and use them through the Wintun API via the Go bindings. The signed binaries have their own [Prebuilt Binaries License](internal/assets/WINTUN-LICENSE.txt); they are not relicensed under this project's MIT license. The Wintun source-code GPL license is distinct from the prebuilt-binary license.

The build downloads https://www.wintun.net/builds/wintun-0.14.1.zip and verifies SHA-256:

```text
07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
```

Official distribution and API references: https://www.wintun.net/ . Driver DLLs are generated build inputs and are not checked into this repository. Linux and macOS executables do not embed Wintun.

## Authentication implementation

The SIM protocol is implemented in original Go code. Protocol interoperability was investigated using locally supplied client software. Proprietary client binaries, decompiled source, disassembly dumps and user authentication material are not distributed with this project. The project does not include or link wireguard-tools.

## Distribution

`tools/copy_licenses.py` preserves upstream LICENSE/COPYING/NOTICE/AUTHORS/COPYRIGHT files for all Go modules linked on the supported operating systems, as well as the Go toolchain license and supplementary notices. `build.sh` includes these texts, this notice and the project license in its output. Windows executables additionally embed the combined notice for the tray's license menu.
