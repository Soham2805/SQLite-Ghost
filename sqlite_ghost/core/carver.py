import struct
from typing import List, Dict, Any
from .varint import decode_varint
from .btree_parser import BTreePage
from .serial_types import parse_serial_type

def find_serial_type_clusters(buffer: bytes, start_offset: int, end_offset: int) -> List[Dict[str, Any]]:
    carved = []
    i = start_offset
    while i < end_offset - 4:
        try:
            header_size, hs_bytes = decode_varint(buffer, i)
            if 3 <= header_size <= min(end_offset - i, 100):
                current_offset = i + hs_bytes
                serial_types = []
                valid_cluster = True
                
                while current_offset < i + header_size:
                    stype, st_bytes = decode_varint(buffer, current_offset)
                    if st_bytes == 0:
                        valid_cluster = False
                        break
                    serial_types.append(stype)
                    current_offset += st_bytes
                
                if valid_cluster and current_offset == i + header_size:
                    values = []
                    data_offset = i + header_size
                    for stype in serial_types:
                        val, val_len = parse_serial_type(stype, buffer, data_offset)
                        if val_len == 0 and stype not in (0, 8, 9, 10, 11):
                            valid_cluster = False
                            break
                        values.append(val)
                        data_offset += val_len
                        
                    if valid_cluster and values:
                        carved.append({
                            'offset': i,
                            'data': values,
                            'raw': buffer[i:data_offset]
                        })
                        i = data_offset - 1
        except Exception:
            pass
        i += 1
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
