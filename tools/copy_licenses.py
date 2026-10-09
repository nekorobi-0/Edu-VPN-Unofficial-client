#!/usr/bin/env python3
"""Copy license and copyright notices of the pinned Go build dependencies."""
import json
import os
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[1]
go = os.environ.get("GO_BIN", "go")
selected = set()
for target_os in ("linux", "darwin", "windows"):
    env = dict(os.environ, GOOS=target_os, GOARCH="amd64", CGO_ENABLED="0")
    packages = subprocess.run([go, "list", "-deps", "-f", "{{if .Module}}{{.Module.Path}}{{end}}", "./cmd/ynu-wg"],
                              cwd=root, env=env, check=True, text=True, capture_output=True)
    selected.update(packages.stdout.splitlines())
result = subprocess.run([go, "list", "-m", "-json", "all"],
                        cwd=root, check=True, text=True, capture_output=True)
decoder = json.JSONDecoder()
remaining = result.stdout
out = root / "dist" / "licenses"
out.mkdir(parents=True, exist_ok=True)
while remaining.strip():
    item, end = decoder.raw_decode(remaining.lstrip())
    remaining = remaining.lstrip()[end:]
    if item.get("Main") or item["Path"] not in selected:
        continue
    module_dir = item.get("Replace", item).get("Dir")
    if not module_dir:
        raise RuntimeError("dependency not downloaded: " + item["Path"])
    directory = Path(module_dir)
    if not directory.is_dir():
        raise RuntimeError("dependency not downloaded: " + item["Path"])
    notices = [p for p in directory.iterdir() if p.is_file() and
               p.name.upper().startswith(("LICENSE", "COPYING", "NOTICE", "AUTHORS", "COPYRIGHT", "PATENTS"))]
    if not any(p.name.upper().startswith(("LICENSE", "COPYING")) for p in notices):
        raise RuntimeError("no license located for " + item["Path"])
    destination = out / item["Path"].replace("/", "_")
    destination.mkdir(exist_ok=True)
    for p in notices:
        shutil.copyfile(p, destination / p.name)

# Include Go's runtime/standard-library notices and the project license in the
# combined Windows notice. Module paths, not machine-local paths, label entries.
goroot = Path(subprocess.run([go, 'env', 'GOROOT'], cwd=root, check=True,
                              capture_output=True, text=True).stdout.strip())
go_notices = out / 'Go'
go_notices.mkdir(exist_ok=True)
for name in ('LICENSE', 'PATENTS', 'NOTICE'):
    if (goroot / name).is_file():
        shutil.copyfile(goroot / name, go_notices / name)
# Preserve build-only resource generator dependencies separately.
tool_packages = subprocess.run([go, 'list', '-deps', '-f', '{{if .Module}}{{.Module.Path}}{{end}}', '.'],
                               cwd=root / 'tools/windowsmanifest', check=True,
                               capture_output=True, text=True)
tool_selected = set(tool_packages.stdout.splitlines())
tool_result = subprocess.run([go, 'list', '-m', '-json', 'all'],
                             cwd=root / 'tools/windowsmanifest', check=True,
                             capture_output=True, text=True)
tool_remaining = tool_result.stdout
while tool_remaining.strip():
    item, end = decoder.raw_decode(tool_remaining.lstrip())
    tool_remaining = tool_remaining.lstrip()[end:]
    if item.get('Main') or item['Path'] not in tool_selected:
        continue
    directory = Path(item['Dir'])
    destination = out / 'build-tools' / item['Path'].replace('/', '_')
    destination.mkdir(parents=True, exist_ok=True)
    for path in directory.iterdir():
        if path.is_file() and path.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE', 'AUTHORS', 'COPYRIGHT', 'PATENTS')):
            shutil.copyfile(path, destination / path.name)
repository_notices = root / 'licenses'
if repository_notices.exists():
    shutil.rmtree(repository_notices)
shutil.copytree(out, repository_notices)
sections = [root / 'LICENSE', root / 'THIRD-PARTY-NOTICES.md',
            root / 'internal/assets/WINTUN-LICENSE.txt']
sections += sorted(repository_notices.rglob('*'))
combined = []
for path in sections:
    if path.is_file():
        combined.append('\n===== ' + path.relative_to(root).as_posix() + ' =====\n\n' +
                        path.read_text(encoding='utf-8'))
(root / 'internal/desktop/licenses.txt').write_text(''.join(combined), encoding='utf-8')
