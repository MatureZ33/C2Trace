"""Extract the checked-in research data and variant sources without network access."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    manifest = json.loads((ROOT / 'archives/manifest.json').read_text(encoding='utf-8'))
    for item in manifest:
        archive = ROOT / item['path']
        if hashlib.sha256(archive.read_bytes()).hexdigest() != item['sha256']:
            raise ValueError(f'Archive checksum mismatch: {archive.name}')
        with zipfile.ZipFile(archive) as z:
            for member in z.infolist():
                dest = (ROOT / member.filename).resolve()
                if not dest.is_relative_to(ROOT) or ':' in member.filename or '\\' in member.filename:
                    raise ValueError(f'Invalid archive path: {member.filename}')
                if ((member.external_attr >> 16) & 0o170000) == 0o120000:
                    raise ValueError('Archive symlinks are not accepted')
            z.extractall(ROOT)
        print(f'Extracted {item["path"]} ({item["files"]} files)')

if __name__ == '__main__':
    main()
