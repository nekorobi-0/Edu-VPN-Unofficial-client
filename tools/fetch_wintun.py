#!/usr/bin/env python3
"""Fetch unmodified signed Wintun binaries from the checksum-pinned official ZIP."""
import hashlib
import io
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
URL = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
SHA256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'


def main():
    request = urllib.request.Request(URL, headers={'User-Agent': 'YNU-WG-build/0.1'})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(16_000_001)
    if len(data) > 16_000_000 or hashlib.sha256(data).hexdigest() != SHA256:
        raise RuntimeError('official Wintun ZIP checksum mismatch; nothing extracted')
    destination = ROOT / 'internal/assets'
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for arch in ('amd64', 'arm64'):
            (destination / ('wintun-' + arch + '.dll')).write_bytes(
                archive.read('wintun/bin/' + arch + '/wintun.dll'))
        (destination / 'WINTUN-LICENSE.txt').write_bytes(archive.read('wintun/LICENSE.txt'))
    print('Verified official Wintun 0.14.1 ZIP; prepared amd64/arm64 build assets.')


if __name__ == '__main__':
    main()
