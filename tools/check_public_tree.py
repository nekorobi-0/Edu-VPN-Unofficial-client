#!/usr/bin/env python3
"""Reject private/runtime files and accidental binaries in the tracked Git tree."""
from pathlib import Path, PurePosixPath
import subprocess
import re

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {'.kkm', '.sim', '.key', '.pem', '.p12', '.pfx', '.log', '.dll',
                      '.syso', '.exe', '.msi', '.cab', '.zip', '.pcap', '.pcapng', '.dmp'}
FORBIDDEN_ROOTS = {'analysis', 'dist', 'bin', 'runtime', 'wireguard-go', 'wireguard-tools', 'launchers'}
FORBIDDEN_NAMES = {'config.json', 'desktop.json', 'startup-task.xml', '.env', 'profile.json'}


def main():
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).split(b'\0')
    count = 0
    for raw in names:
        if not raw:
            continue
        name = raw.decode('utf-8')
        path = PurePosixPath(name)
        lower = path.name.lower()
        if (path.parts[0].lower() in FORBIDDEN_ROOTS or path.suffix.lower() in FORBIDDEN_SUFFIXES
                or lower in FORBIDDEN_NAMES or lower.startswith('.env.')
                or lower.startswith('profile') and path.suffix.lower() == '.json'):
            raise SystemExit('Refusing private or generated file: ' + name)
        file = ROOT / name
        if file.is_symlink():
            raise SystemExit('Refusing symlink: ' + name)
        data = file.read_bytes()
        if b'\0' in data or data.startswith((b'MZ', b'\x7fELF')):
            raise SystemExit('Refusing binary content: ' + name)
        if re.search(br'(?m)^-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----\r?$', data):
            raise SystemExit('Refusing private key material: ' + name)
        count += 1
    print('Public source hygiene passed for', count, 'tracked files.')


if __name__ == '__main__':
    main()
