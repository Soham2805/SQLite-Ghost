def decode_varint(buffer: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decodes an SQLite variable-length integer (Varint).
    
    SQLite varints are 1 to 9 bytes long:
    - Bytes 1-8: MSB indicates if another byte follows. Lower 7 bits are payload.
    - Byte 9: All 8 bits are payload data.
    
    Args:
        buffer: The byte stream containing the varint.
        offset: The starting index in the buffer.
        
    Returns:
        tuple: (decoded_value, bytes_read)
    """
    if not buffer or offset >= len(buffer):
        return 0, 0

    value = 0
    bytes_read = 0

    for i in range(9):
        if offset + i >= len(buffer):
            break
            
        byte = buffer[offset + i]
        bytes_read += 1
        
        if i == 8:
            # The 9th byte uses all 8 bits
            value = (value << 8) | byte
            break
        else:
            # Lower 7 bits are data
            value = (value << 7) | (byte & 0x7F)
            
            # Check MSB
            if not (byte & 0x80):
                break

    return value, bytes_read
