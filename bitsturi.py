#!/usr/bin/env python3

import sys
import struct
import re
import os

DEBUG = 0


def debug(*args):
    if DEBUG:
        print(args)


def chunks(lst, n):
    """Expand successive n-sized chunks from lst."""
    return [lst[i - n : i] for i in range(n, len(lst) + n, n)]


def add(codes, counts, buf):
    debug(buf)
    bits = ""
    for k, v in counts.items():
        code = codes[k]
        for _ in range(v):
            if type(code) == bytes:
                code = str(code, encoding="ascii")
            buf = code + buf
            if len(buf) > 8:
                bits += buf[-8:]
                buf = buf[:-8]
            debug(chunks(bits, 8), buf)

    return bits + buf


def concat(head, tail, buf):
    debug(buf)
    bits = head
    for code in chunks(tail, 8):
        if type(code) == bytes:
            code = str(code, encoding="ascii")
        buf = code + buf
        if len(buf) > 8:
            bits += buf[-8:]
            buf = buf[:-8]
    debug(chunks(bits, 8), buf)

    return bits + buf


def truncate(data, from_byte, from_bit, size):
    data_chunks = chunks(data, 8)
    data_chunks_truncated = []
    x = None
    y_size = size
    has_trailing_bits = False
    i_from_byte = 0
    at = from_bit
    for y in data_chunks:
        if i_from_byte < from_byte:
            data_chunks_truncated.append(y)
            i_from_byte += 1
            continue
        if not x:
            x = y
            continue
        x = (x[:at] + x[at + size :] + y[:y_size]).rjust(8, "0")
        data_chunks_truncated.append(x)

        has_trailing_bits = len(y[y_size:]) > 0
        x = (y[y_size:]).rjust(8, "0")

        at = 8 - size
    if has_trailing_bits:
        data_chunks_truncated.append(x)

    return data_chunks_truncated


def extract(data, need_bits, next_byte_i, buf):
    bits = ""
    got_bits = 0
    while True:
        take_bits = min(need_bits - got_bits, len(buf))
        got_bits += take_bits
        next_bits = buf[-take_bits:]
        buf = buf[:-take_bits]
        debug(f"next_bits={next_bits}, bits={bits}")
        bits = next_bits + bits

        if got_bits >= need_bits:
            break

        buf = data[next_byte_i]
        next_byte_i += 1
        debug(f"parse: buf={buf}")

    debug(f"bits={bits}, next_byte_i={next_byte_i}, buf={buf}")
    return bits, next_byte_i, buf


def patch(data, pattern, byte_offset, bit_offset):
    target_offset = 8 * byte_offset + bit_offset
    for i in range(len(pattern)):
        data[target_offset + i] = pattern[i]

    return data


def bits_to_bytes(new_bits):
    mod_bits = len(new_bits) % 8
    if mod_bits > 0:
        last_octet = new_bits[-mod_bits:]
        last_octet = last_octet.rjust(8, "0")
        new_bits = new_bits[:-mod_bits] + last_octet
        debug(chunks(new_bits, 8))
        assert len(new_bits) % 8 == 0

    return b"".join([bytes([int(x, 2)]) for x in chunks(new_bits, 8)])


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        data = f.read()
        bits = "".join(bin(x)[2:].rjust(8, "0") for x in data)
    from_byte = int(sys.argv[2], 0)
    from_bit = int(sys.argv[3], 0)
    size = int(sys.argv[4], 0)

    new_bits = truncate(bits, from_byte, from_bit, size)

    new_bytes = b"".join([bytes([int(x, 2)]) for x in new_bits])
    with open("bitsturi.out", "wb") as f:
        f.write(new_bytes)
