import struct
import pytest
from sqlite_ghost.core.btree_parser import parse_database_header, parse_page

def test_parse_database_header():
    # Construct a 100-byte valid header
    header = bytearray(100)
    header[0:16] = b"SQLite format 3\x00"
    struct.pack_into('>H', header, 16, 4096) # Page size
    header[20] = 0 # reserved bytes
    struct.pack_into('>I', header, 32, 1) # freelist trunk
    struct.pack_into('>I', header, 36, 10) # total freelist
    
    parsed = parse_database_header(bytes(header))
    assert parsed['page_size'] == 4096
    assert parsed['reserved_bytes'] == 0
    assert parsed['freelist_trunk'] == 1
    assert parsed['total_freelist'] == 10

def test_parse_page():
    # Table leaf page (0x0D)
    page = bytearray(4096)
    page[0] = 0x0D
    struct.pack_into('>H', page, 3, 0) # cell count = 0
    struct.pack_into('>H', page, 5, 0) # cell content start
    page[7] = 0 # free bytes
    
    parsed = parse_page(bytes(page), is_page_1=False)
    assert parsed.page_type == 0x0D
    assert parsed.cell_count == 0
    assert parsed.cell_content_start == 65536
