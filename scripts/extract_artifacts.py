"""Extract the checked-in research data and variant sources without network access."""
from pathlib import Path
import hashlib
import io
import json
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    manifest = json.loads((ROOT / 'archives/manifest.json').read_text(encoding='utf-8'))
    for item in manifest:
        if item.get('parts'):
            chunks = []
            for part in item['parts']:
                path = (ROOT / part['path']).resolve()
                if not path.is_relative_to(ROOT):
                    raise ValueError('Invalid archive part path')
                data = path.read_bytes()
                if hashlib.sha256(data).hexdigest() != part['sha256']:
                    raise ValueError(f'Archive part checksum mismatch: {part["path"]}')
                chunks.append(data)
            data = b''.join(chunks)
        else:
            archive = (ROOT / item['path']).resolve()
            if not archive.is_relative_to(ROOT):
                raise ValueError('Invalid archive path')
            data = archive.read_bytes()
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError(f'Archive checksum mismatch: {item["path"]}')
        with zipfile.ZipFile(io.BytesIO(data)) as z:
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
