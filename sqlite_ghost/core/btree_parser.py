import struct
from typing import Dict, Any, List, Optional
from .varint import decode_varint
from .serial_types import parse_serial_type

class BTreePage:
    def __init__(self, page_type: int, cell_count: int, cell_content_start: int, 
                 free_bytes: int, right_pointer: int = 0):
        self.page_type = page_type
        self.cell_count = cell_count
        self.cell_content_start = cell_content_start
        self.free_bytes = free_bytes
        self.right_pointer = right_pointer
        self.cell_pointers = []
        self.cells = []

def parse_database_header(header: bytes) -> Dict[str, Any]:
    if len(header) < 100:
        raise ValueError("Header too small")
    if header[:16] != b"SQLite format 3\x00":
        raise ValueError("Invalid SQLite magic header")
        
    page_size = struct.unpack_from('>H', header, 16)[0]
    if page_size == 1:
        page_size = 65536
        
    reserved_bytes = header[20]
    freelist_trunk = struct.unpack_from('>I', header, 32)[0]
    total_freelist = struct.unpack_from('>I', header, 36)[0]
    
    return {
        'page_size': page_size,
        'reserved_bytes': reserved_bytes,
        'freelist_trunk': freelist_trunk,
        'total_freelist': total_freelist
    }

def parse_payload(payload: bytes) -> List[Any]:
    if not payload:
        return []
        
    header_size, bytes_read = decode_varint(payload, 0)
    
    # Read serial types
    serial_types = []
    current_offset = bytes_read
    while current_offset < header_size:
        stype, stype_len = decode_varint(payload, current_offset)
        serial_types.append(stype)
        current_offset += stype_len
        
    # Read values
    values = []
    data_offset = header_size
    for stype in serial_types:
        val, val_len = parse_serial_type(stype, payload, data_offset)
        values.append(val)
        data_offset += val_len
        
    return values

def parse_page(page_data: bytes, is_page_1: bool = False) -> BTreePage:
    offset = 100 if is_page_1 else 0
    
    if len(page_data) < offset + 8:
        raise ValueError("Page data too small to contain header")
        
    page_type = page_data[offset]
    
    cell_count = struct.unpack_from('>H', page_data, offset + 3)[0]
    cell_content_start = struct.unpack_from('>H', page_data, offset + 5)[0]
    if cell_content_start == 0:
        cell_content_start = 65536
        
    free_bytes = page_data[offset + 7]
    
    right_pointer = 0
    if page_type in (0x05, 0x02):  # Interior pages
        right_pointer = struct.unpack_from('>I', page_data, offset + 8)[0]
        header_size = 12
    else:
        header_size = 8
        
    page = BTreePage(page_type, cell_count, cell_content_start, free_bytes, right_pointer)
    
    pointer_array_start = offset + header_size
    for i in range(cell_count):
        ptr_offset = pointer_array_start + (i * 2)
        if ptr_offset + 2 > len(page_data):
            break
        cell_ptr = struct.unpack_from('>H', page_data, ptr_offset)[0]
        page.cell_pointers.append(cell_ptr)
        
    if page_type == 0x0D:
        for ptr in page.cell_pointers:
            if ptr >= len(page_data):
                continue
            payload_size, bytes_read = decode_varint(page_data, ptr)
            row_id, row_id_bytes = decode_varint(page_data, ptr + bytes_read)
            
            payload_start = ptr + bytes_read + row_id_bytes
            payload_buffer = page_data[payload_start : payload_start + payload_size]
            
            parsed_payload = parse_payload(payload_buffer)
            page.cells.append({
                'row_id': row_id,
                'payload_size': payload_size,
                'data': parsed_payload,
                'raw_payload': payload_buffer
            })
            
    return page
