import os
import shutil
import hashlib
import tempfile

def secure_copy(source_path: str) -> str:
    temp_dir = tempfile.mkdtemp(prefix="sqlite_ghost_")
    dest_path = os.path.join(temp_dir, os.path.basename(source_path))
    shutil.copy2(source_path, dest_path)
    return dest_path

def generate_hashes(filepath: str) -> dict:
    if not os.path.exists(filepath):
        return {'md5': 'N/A', 'sha256': 'N/A'}
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            md5.update(chunk)
            sha256.update(chunk)
    return {
        'md5': md5.hexdigest(),
        'sha256': sha256.hexdigest()
    }

def generate_hex_dump(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        hex_str = hex_str.ljust(47)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f"{i:04x}  {hex_str}  |{ascii_str}|")
    return '\n'.join(lines)
