#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
GO_BIN="${GO_BIN:-go}"
python3 tools/fetch_wintun.py
mkdir -p dist
GO_BIN="$GO_BIN" python3 tools/copy_licenses.py
outputs=()
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  target_os="${target%/*}"
  target_arch="${target#*/}"
  output="dist/ynu-wg-${target_os}-${target_arch}"
  if [[ "$target_os" == windows ]]; then output="${output}.exe"; fi
  flags="-s -w"
  if [[ "$target_os" == windows ]]; then flags="$flags -H windowsgui"; fi
  outputs+=("$output")
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" "$GO_BIN" build -trimpath -ldflags="$flags" -o "$output" ./cmd/ynu-wg
done
cp LICENSE README.md THIRD-PARTY-NOTICES.md dist/
cp internal/assets/WINTUN-LICENSE.txt dist/WINTUN-LICENSE.txt
python3 - <<'PY'
from pathlib import Path
import zipfile
root = Path('.')
with zipfile.ZipFile('dist/licenses.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
    for name in ['LICENSE', 'THIRD-PARTY-NOTICES.md', 'internal/assets/WINTUN-LICENSE.txt']:
        archive.write(name, name)
    for path in sorted(Path('licenses').rglob('*')):
        if path.is_file(): archive.write(path, path.as_posix())
PY
sha256sum "${outputs[@]}" dist/licenses.zip | sed 's|dist/||' > dist/SHA256SUMS
