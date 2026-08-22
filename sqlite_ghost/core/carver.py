import struct
from typing import List, Dict, Any
from .varint import decode_varint
from .btree_parser import BTreePage
from .serial_types import parse_serial_type

import re

def find_serial_type_clusters(buffer: bytes, start_offset: int, end_offset: int) -> List[Dict[str, Any]]:
    carved = []
    
    # Robust Forensic String Carving
    # Because deleted cells are overwritten with freeblock pointers, their headers are destroyed.
    # Trying to parse serial types leads to false positives that swallow multiple messages.
    # Instead, we directly carve contiguous printable text payloads from the unallocated space!
    
    search_area = buffer[start_offset:end_offset]
    
    # Match any contiguous block of printable ASCII/UTF-8 characters (length >= 10)
    for match in re.finditer(b'[\x20-\x7E]{10,}', search_area):
        s = match.group(0)
        try:
            decoded = s.decode('utf-8')
            carved.append({
                'offset': start_offset + match.start(),
                'data': [decoded],
                'raw': s
            })
        except:
            pass
            
    return carved

def carve_slack_space(page_data: bytes, page: BTreePage, is_page_1: bool = False) -> List[Dict[str, Any]]:
    header_offset = 100 if is_page_1 else 0
    header_size = 12 if page.page_type in (0x05, 0x02) else 8
    pointer_array_end = header_offset + header_size + (page.cell_count * 2)
    cell_content_start = page.cell_content_start
    
    if pointer_array_end >= cell_content_start:
        return []
        
    return find_serial_type_clusters(page_data, pointer_array_end, cell_content_start)

def carve_freelist(db_data: bytes, trunk_page_num: int, page_size: int) -> List[Dict[str, Any]]:
    carved = []
    current_trunk = trunk_page_num
    
    while current_trunk != 0:
        offset = (current_trunk - 1) * page_size
        if offset + page_size > len(db_data):
            break
            
        trunk_data = db_data[offset:offset + page_size]
        next_trunk = struct.unpack_from('>I', trunk_data, 0)[0]
        leaf_count = struct.unpack_from('>I', trunk_data, 4)[0]
        
        carved.extend(find_serial_type_clusters(trunk_data, 8, page_size))
        
        for i in range(leaf_count):
            if 8 + (i * 4) + 4 > len(trunk_data):
                break
            leaf_page_num = struct.unpack_from('>I', trunk_data, 8 + (i * 4))[0]
            leaf_offset = (leaf_page_num - 1) * page_size
            if leaf_offset + page_size <= len(db_data):
                leaf_data = db_data[leaf_offset:leaf_offset + page_size]
                carved.extend(find_serial_type_clusters(leaf_data, 0, page_size))
                
        current_trunk = next_trunk
        
    return carved
