import struct
from typing import Any, Tuple

def parse_serial_type(serial_type: int, payload_buffer: bytes, offset: int) -> Tuple[Any, int]:
    """
    Parses a payload value based on its Serial Type.
    
    Args:
        serial_type (int): The serial type code from the payload header.
        payload_buffer (bytes): The raw payload bytes.
        offset (int): The starting offset for this value in the payload buffer.
        
    Returns:
        Tuple[Any, int]: The parsed value and the number of bytes read.
    """
    if serial_type == 0:
        return None, 0
    elif serial_type == 1:
        if offset + 1 > len(payload_buffer):
            return None, 0
        value = struct.unpack_from('>b', payload_buffer, offset)[0]
        return value, 1
    elif serial_type == 2:
        if offset + 2 > len(payload_buffer):
            return None, 0
        value = struct.unpack_from('>h', payload_buffer, offset)[0]
        return value, 2
    elif serial_type == 3:
        if offset + 3 > len(payload_buffer):
            return None, 0
        raw = payload_buffer[offset:offset+3]
        # Sign extend 24-bit
        if raw[0] & 0x80:
            raw = b'\xff' + raw
        else:
            raw = b'\x00' + raw
        value = struct.unpack('>i', raw)[0]
        return value, 3
    elif serial_type == 4:
        if offset + 4 > len(payload_buffer):
            return None, 0
        value = struct.unpack_from('>i', payload_buffer, offset)[0]
        return value, 4
    elif serial_type == 5:
        if offset + 6 > len(payload_buffer):
            return None, 0
        raw = payload_buffer[offset:offset+6]
        if raw[0] & 0x80:
            raw = b'\xff\xff' + raw
        else:
            raw = b'\x00\x00' + raw
        value = struct.unpack('>q', raw)[0]
        return value, 6
    elif serial_type == 6:
        if offset + 8 > len(payload_buffer):
            return None, 0
        value = struct.unpack_from('>q', payload_buffer, offset)[0]
        return value, 8
    elif serial_type == 7:
        if offset + 8 > len(payload_buffer):
            return None, 0
        value = struct.unpack_from('>d', payload_buffer, offset)[0]
        return value, 8
    elif serial_type == 8:
        return 0, 0
    elif serial_type == 9:
        return 1, 0
    elif serial_type in (10, 11):
        # Reserved for internal SQLite extensions
        return None, 0
    elif serial_type >= 12 and serial_type % 2 == 0:
        length = (serial_type - 12) // 2
        if offset + length > len(payload_buffer):
            return None, 0
        value = payload_buffer[offset:offset+length]
        return value, length
    elif serial_type >= 13 and serial_type % 2 != 0:
        length = (serial_type - 13) // 2
        if offset + length > len(payload_buffer):
            return None, 0
        raw_value = payload_buffer[offset:offset+length]
        try:
            value = raw_value.decode('utf-8')
        except UnicodeDecodeError:
            # Fallback for arbitrary bytes that aren't valid UTF-8
            value = raw_value.decode('latin1')
        return value, length
    
    return None, 0
