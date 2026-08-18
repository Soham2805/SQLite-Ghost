import struct
import pytest
from sqlite_ghost.core.wal_engine import parse_wal_header, read_wal_frames

def test_parse_wal_header():
    header = bytearray(32)
    struct.pack_into('>I', header, 0, 0x377f0682) # Magic
    struct.pack_into('>I', header, 8, 4096) # Page size
    
    parsed = parse_wal_header(bytes(header))
    assert parsed['magic'] == 0x377f0682
    assert parsed['page_size'] == 4096
    assert parsed['endian'] == '>'

def test_read_wal_frames():
    # Mock a WAL file with header and 1 frame
    wal_data = bytearray(32 + 24 + 4096)
    
    # Header
    struct.pack_into('>I', wal_data, 0, 0x377f0682) # Magic
    struct.pack_into('>I', wal_data, 8, 4096) # Page size
    
    # Frame 1
    struct.pack_into('>I', wal_data, 32, 2) # Page number 2
    struct.pack_into('>I', wal_data, 36, 5) # Commit size
    # Frame data is just 0s
    
    frames = read_wal_frames(bytes(wal_data), 4096, '>')
    assert len(frames) == 1
    assert frames[0].page_number == 2
    assert frames[0].commit_size == 5
    assert len(frames[0].data) == 4096
