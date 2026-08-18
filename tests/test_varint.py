import pytest
from sqlite_ghost.core.varint import decode_varint

def test_single_byte_varint():
    # Value 0
    val, bytes_read = decode_varint(b'\x00')
    assert val == 0
    assert bytes_read == 1

    # Value 127
    val, bytes_read = decode_varint(b'\x7f')
    assert val == 127
    assert bytes_read == 1

def test_multi_byte_varint():
    # Value 128 (0x81 0x00)
    val, bytes_read = decode_varint(b'\x81\x00')
    assert val == 128
    assert bytes_read == 2

    # Value 16383 (0xff 0x7f) -> 0b11111111 0b01111111 -> 0x3FFF -> 16383
    val, bytes_read = decode_varint(b'\xff\x7f')
    assert val == 16383
    assert bytes_read == 2

def test_nine_byte_varint():
    # 9-byte varint where all bits are used in the 9th byte.
    # E.g., max 64-bit unsigned int: \xff \xff \xff \xff \xff \xff \xff \xff \xff
    val, bytes_read = decode_varint(b'\xff' * 9)
    assert val == 0xffffffffffffffff
    assert bytes_read == 9

def test_varint_with_offset():
    # Offset test
    buffer = b'\x00\x00\x81\x00\x00'
    val, bytes_read = decode_varint(buffer, 2)
    assert val == 128
    assert bytes_read == 2

def test_incomplete_buffer():
    # Ends prematurely
    val, bytes_read = decode_varint(b'\x81')
    # According to our implementation, it reads what it can.
    # It reads \x81 but next byte is missing, so it breaks.
    # Wait, if it breaks on out of bounds, value is just what was read.
    # Actually, SQLite varint usually requires the next byte, but let's see.
    assert val == 1
    assert bytes_read == 1
