import struct
from typing import List, Dict, Any

class WALFrame:
    def __init__(self, page_number: int, commit_size: int, data: bytes):
        self.page_number = page_number
        self.commit_size = commit_size
        self.data = data

def parse_wal_header(header: bytes) -> Dict[str, Any]:
    if len(header) < 32:
        raise ValueError("WAL header too small")
        
    magic = struct.unpack_from('>I', header, 0)[0]
    if magic not in (0x377f0682, 0x377f0683, 0x82067f37, 0x83067f37):
        raise ValueError("Invalid WAL magic number")
        
    # The endianness depends on the magic number
    endian = '>' if magic in (0x377f0682, 0x377f0683) else '<'
    page_size = struct.unpack_from(endian + 'I', header, 8)[0]
    
    return {
        'magic': magic,
        'page_size': page_size,
        'endian': endian
    }

def read_wal_frames(wal_data: bytes, page_size: int, endian: str = '>') -> List[WALFrame]:
    frames = []
    offset = 32 # Skip header
    
    frame_size = 24 + page_size
    while offset + frame_size <= len(wal_data):
        frame_header = wal_data[offset:offset+24]
        page_number = struct.unpack_from(endian + 'I', frame_header, 0)[0]
        commit_size = struct.unpack_from(endian + 'I', frame_header, 4)[0]
        
        page_data = wal_data[offset+24:offset+frame_size]
        frames.append(WALFrame(page_number, commit_size, page_data))
        
        offset += frame_size
        
    return frames
