#!/usr/bin/env python3
"""Build a reproducible source release; exclude ignored and private runtime files."""
import argparse
import gzip
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def build(output):
    import sys
    sys.path.insert(0, str(ROOT))
    from core import __version__
    manifest = json.loads((ROOT / 'extension/manifest.json').read_text())
    if manifest['version'] != __version__:
        raise SystemExit('Backend and extension versions differ')
    paths = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT).decode().split('\0')
    output.mkdir(parents=True, exist_ok=True)
    archive = output / 'greytab-linux-x86_64.tar.gz'
    with archive.open('wb') as raw:
        with gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as tar:
                for path in sorted(set(filter(None, paths))):
                    source = ROOT / path
                    if not source.is_file() or source.is_symlink() or output.resolve() in source.resolve().parents:
                        continue
                    # Runtime artifacts are never release inputs, even if accidentally staged.
                    if path.split('/')[0] in {'.git', '.codex', '.agents', '.aws', '.venv', 'venv', '.runtime', 'browser', 'profile', 'certs', 'logs', 'data', 'sessions', 'wordlists'}:
                        continue
                    info = tar.gettarinfo(str(source), arcname=path)
                    info.uid = info.gid = 0; info.uname = info.gname = ''; info.mtime = 0
                    info.mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
                    with source.open('rb') as content: tar.addfile(info, content)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / 'SHA256SUMS').write_text(f'{digest}  {archive.name}\n')
    print(f'GreyTab {__version__}: {archive} ({archive.stat().st_size} bytes)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    build(parser.parse_args().output)
