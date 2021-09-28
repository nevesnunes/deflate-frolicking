#!/usr/bin/env python3

'''
Endues a DEFLATE stream with the grace of your offered message.

To preserve the same decompression output, the message is applied to a
duplicate of the first dynamic DEFLATE block in the provided stream, which
will not produce any output when decompressed. This duplicate is then
concatenated to the rest of the stream.
'''

import sys
import struct
import subprocess
import re
import os

from bitsturi import *
from huffman_solver import *

if __name__ == "__main__":
    compressed_file = sys.argv[1]
    with open(compressed_file, "rb") as f:
        data = f.read()
        base_bits = "".join(bin(x)[2:].rjust(8, "0") for x in data)
        base_chunks = chunks(base_bits, 8)

    next_byte_i = 0
    buf = ''
    bfinal, next_byte_i, buf = extract(base_chunks, 1, next_byte_i, buf)
    vbfinal = int(bfinal, 2)
    print(f"BFINAL {bfinal} = {vbfinal}")
    btype, next_byte_i, buf = extract(base_chunks, 2, next_byte_i, buf)
    vbtype = int(btype, 2)
    if vbtype != 2:
        raise RuntimeError("Expected BTYPE=0b10, got 0b{btype}.")
    print(f" BTYPE {btype} = {vbtype}")
    hlit, next_byte_i, buf = extract(base_chunks, 5, next_byte_i, buf)
    vhlit = int(hlit, 2)
    print(f"  HLIT {hlit} = {vhlit} (k + 257 = {vhlit + 257})")
    hdist, next_byte_i, buf = extract(base_chunks, 5, next_byte_i, buf)
    vhdist = int(hdist, 2)
    print(f" HDIST {hdist} = {vhdist} (k + 1 = {vhdist + 1})")
    hclen, next_byte_i, buf = extract(base_chunks, 4, next_byte_i, buf)
    vhclen = int(hclen, 2)
    print(f" HCLEN {hclen} = {vhclen} (k + 4 = {vhclen + 4})")

    message = sys.argv[2]

    output_file = f"{compressed_file}.add_message.out"
    output2_file = f"{compressed_file}.add_litlen_codes.out"
    output3_file = f"{compressed_file}.add_all_codes.out"
    output4_file = f"{compressed_file}.add_sym_256.out"
    output5_file = f"{compressed_file}.embellished"

    disasm = subprocess.run(
        ["infgen", "-d", compressed_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    inject_start_search = re.search(b'([0-9a-f]+) \d+: ! decoded len ', disasm.stdout)
    inject_start = int(inject_start_search.group(1), 16)
    print("Initial message start:", hex(inject_start))
    inject_end_search = re.search(b'([0-9a-f]+) \d+: ! literal ', disasm.stdout)
    inject_end = int(inject_end_search.group(1), 16)
    print("Initial message end:", hex(inject_end))

    is_valid = False
    for i in range(inject_start + 1, inject_end - 1 - len(message)):
        print(f" Trying message start = {i}...")
        candidate_vhlit = vhlit
        candidate_vhdist = 0  # We don't use distance codes

        data_patched = data[0:i] + message.encode("ascii") + data[i + len(message):]
        data_bits_patched = "".join(bin(x)[2:].rjust(8, "0") for x in data_patched)
        data_bits_patched = ''.join(patch(list(data_bits_patched), bin(candidate_vhlit)[2:].zfill(5), 0, 0))
        data_bits_patched = ''.join(patch(list(data_bits_patched), bin(candidate_vhdist)[2:].zfill(5), 1, 3))
        new_bytes = bits_to_bytes(data_bits_patched)
        with open(output_file, "wb") as f:
            f.write(new_bytes)

        disasm = subprocess.run(
            ["infgen", "-d", output_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        # TODO:
        # - Identify and remove last repetitions, avoiding oversubscribing
        # - Parse known length codes, so that others are added as exclusions to our solver
        too_many_lengths = re.search(b'repeat more lengths than available', disasm.stdout)
        over_subscribed = re.search(b'oversubscribed', disasm.stdout)
        missing_end_of_block = re.search(b'missing end-of-block', disasm.stdout)
        is_valid = not (too_many_lengths or over_subscribed)
        while not is_valid:
            if candidate_vhlit > 1:
                candidate_vhlit -= 1
                new_bits = ''.join(patch(list(data_bits_patched), bin(candidate_vhlit)[2:].zfill(5), 0, 0))
            else:
                break

            new_bytes = bits_to_bytes(new_bits)
            with open(output_file, "wb") as f:
                f.write(new_bytes)

            disasm = subprocess.run(
                ["infgen", "-d", output_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            too_many_lengths = re.search(b'repeat more lengths than available', disasm.stdout)
            over_subscribed = re.search(b'oversubscribed', disasm.stdout)
            missing_end_of_block = re.search(b'missing end-of-block', disasm.stdout)
            is_valid = not (too_many_lengths or over_subscribed)

        if not too_many_lengths and not over_subscribed and not missing_end_of_block:
            print("Got stream with valid codes!")
            is_valid = True
            break

    if not is_valid:
        raise RuntimeError("Could not fit message, try a smaller/different one...")

    code_bits = {}
    dist_1_bits = None
    sym_256_data = None

    missing_codes = re.search(b'([0-9a-f]+) (\d+): .* literal/length code is incomplete', disasm.stdout)
    if missing_codes:
        print("Finding remaining litlen codes...")

        next_byte_i = int(missing_codes.group(1), 16)
        next_bit_i = int(missing_codes.group(2), 10)

        # FIXME: When huffman tables are implemented, we don't need to parse these codes
        code_bits = {}
        dist_1_bits = None
        sym_256_data = None
        for match in re.finditer(b'! decoded len (\d+) bits (\d+) sym_i (\d+) .* (\d+)', disasm.stdout):
            code_bits[int(match.group(4), 10)] = match.group(2)
            sym_i = int(match.group(3), 10)
            if sym_i == candidate_vhlit + 257:
                dist_1_bits = match.group(2)
            if sym_i == 256:
                sym_256_data = {
                    "bits": match.group(2),
                    "sym_len": int(match.group(4), 10)
                }
        print(code_bits)
        print(dist_1_bits)
        print(sym_256_data)

        exclusions = {}
        litlen_counts = {}
        for match in re.finditer(b'! construct litlen len (\d+) count (\d+)', disasm.stdout):
            k = int(match.group(1), 10)
            v = int(match.group(2), 10)
            if v != 0:
                if k == 0:
                    exclusions[k] = v
                else:
                    litlen_counts[k] = v

        # FIXME: When huffman tables are implemented, we don't these exclusions
        for i in range(MAXBITS):
            # if i not in litlen_counts:
            if i not in code_bits:
                exclusions[i] = 0

        if 0 not in exclusions:
            exclusions[0] = 0
        print(exclusions, litlen_counts)
        new_counts = solve(litlen_counts, exclusions, MAXHLIT)
        need_counts = {}
        for k, v in new_counts.items():
            if k == 0:
                continue
            if k in litlen_counts:
                if v - litlen_counts[k] > 0:
                    need_counts[k] = v - litlen_counts[k]
            elif v > 0:
                need_counts[k] = v
        print("Need to add codes:", need_counts)

        # Add codes
        print(next_byte_i, next_bit_i)

        free_len = 8 - next_bit_i + len(dist_1_bits)
        print(f"free_len: {free_len}")
        assert free_len <= 8  # FIXME: Need to decrement byte_i

        new_bits = new_bits[:((next_byte_i)*8)]
        print(new_bits)

        last_octet = new_bits[-8:][free_len:]
        new_bits = new_bits[:-8]
        next_bits = add(code_bits, need_counts, last_octet)
        new_bits = new_bits + next_bits
        print(f"last_octet: {last_octet}, next_bits: {next_bits}")

        added_counts = 0
        for k, v in need_counts.items():
            for i in range(v):
                added_counts += 1
        candidate_vhlit += added_counts
        new_bits = ''.join(patch(list(new_bits), bin(candidate_vhlit)[2:].zfill(5), 0, 0))
        new_bytes = bits_to_bytes(new_bits)
        with open(output2_file, "wb") as f:
            f.write(new_bytes)
        # include padded bits for next operations
        new_bits = "".join(bin(x)[2:].rjust(8, "0") for x in new_bytes)

    disasm = subprocess.run(
        ["infgen", "-d", output2_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    missing_codes = re.search(b'([0-9a-f]+) (\d+): .* literal/length code is incomplete', disasm.stdout)
    if missing_codes:
        raise RuntimeError("Expected solved litlen codes, but output is still incomplete!")
    missing_codes = re.search(b'([0-9a-f]+) (\d+): ! under-subscribed dist', disasm.stdout)
    if missing_codes:
        print("Finding remaining dist codes...")

        next_byte_i = int(missing_codes.group(1), 16)
        next_bit_i = int(missing_codes.group(2), 10)

        # FIXME: When huffman tables are implemented, we don't need to parse these codes
        code_bits = {}
        dist_1_bits = None
        sym_256_data = None
        for match in re.finditer(b'! decoded len (\d+) bits (\d+) sym_i (\d+) .* (\d+)', disasm.stdout):
            code_bits[int(match.group(4), 10)] = match.group(2)
            sym_i = int(match.group(3), 10)
            if sym_i == candidate_vhlit + 257:
                dist_1_bits = match.group(2)
            if sym_i == 256:
                sym_256_data = {
                    "bits": match.group(2),
                    "sym_len": int(match.group(4), 10)
                }
        print(code_bits)
        print(dist_1_bits)
        print(sym_256_data)

        exclusions = {}
        litlen_counts = {}
        for match in re.finditer(b'! construct dist len (\d+) count (\d+)', disasm.stdout):
            k = int(match.group(1), 10)
            v = int(match.group(2), 10)
            if v != 0:
                if k == 0:
                    exclusions[k] = v
                else:
                    litlen_counts[k] = v

        # FIXME: When huffman tables are implemented, we don't these exclusions
        for i in range(MAXBITS):
            if i not in code_bits:
                exclusions[i] = 0

        if 0 not in exclusions:
            exclusions[0] = 0
        print(exclusions, litlen_counts)
        new_counts = solve(litlen_counts, exclusions, MAXHDIST)
        need_counts = {}
        for k, v in new_counts.items():
            if k == 0:
                continue
            if k in litlen_counts:
                if v - litlen_counts[k] > 0:
                    need_counts[k] = v - litlen_counts[k]
            elif v > 0:
                need_counts[k] = v
        print("Need to add codes:", need_counts)

        # Add codes
        print(next_byte_i, next_bit_i)

        free_len = 8 - next_bit_i + len(dist_1_bits)
        print(f"free_len: {free_len}")
        assert free_len <= 8  # FIXME: Need to decrement byte_i

        new_bits = new_bits[:((next_byte_i)*8)]
        print(new_bits)

        last_octet = new_bits[-8:][free_len:]
        new_bits = new_bits[:-8]
        next_bits = add(code_bits, need_counts, last_octet)
        new_bits = new_bits + next_bits
        print(f"last_octet: {last_octet}, next_bits: {next_bits}")

        added_counts = 0
        for k, v in need_counts.items():
            for i in range(v):
                added_counts += 1
        candidate_vhdist += added_counts
        new_bits = ''.join(patch(list(new_bits), bin(candidate_vhdist)[2:].zfill(5), 1, 3))
        new_bytes = bits_to_bytes(new_bits)
        with open(output3_file, "wb") as f:
            f.write(new_bytes)
        # include padded bits for next operations
        new_bits = "".join(bin(x)[2:].rjust(8, "0") for x in new_bytes)

    disasm = subprocess.run(
        ["infgen", "-d", output3_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    missing_codes = re.search(b'([0-9a-f]+) (\d+): .* literal/length code is incomplete', disasm.stdout)
    if missing_codes:
        raise RuntimeError("Expected solved litlen codes, but output is still incomplete!")
    missing_codes = re.search(b'([0-9a-f]+) (\d+): ! under-subscribed dist', disasm.stdout)
    if missing_codes:
        raise RuntimeError("Expected solved dist codes, but output is still incomplete!")

    missing_data = re.search(b'([0-9a-f]+) (\d+): incomplete deflate data', disasm.stdout)
    if not missing_data:
        raise RuntimeError("Expected missing deflate data!")
    print("Adding end-of-block symbol...")

    next_byte_i = int(missing_data.group(1), 16)
    next_bit_i = int(missing_data.group(2), 10)
    print(next_byte_i, next_bit_i)

    free_len = 8 - next_bit_i
    print(f"free_len: {free_len}")
    assert free_len <= 8  # FIXME: Need to decrement byte_i

    # FIXME: When huffman tables are implemented, we don't need to brute symbol 256 bits
    new_bits_base = new_bits[:]
    is_stream_ready = False
    for candidate in range(2 << sym_256_data["sym_len"] - 1):
        new_bits = new_bits_base[:]
        last_octet = new_bits[-8:][free_len:]
        new_bits = new_bits[:-8]
        new_bits = concat(new_bits, bin(candidate)[2:].zfill(sym_256_data["sym_len"]), last_octet)

        new_bytes = bits_to_bytes(new_bits)
        with open(output4_file, "wb") as f:
            f.write(new_bytes)

        disasm = subprocess.run(
            ["infgen", "-d", output4_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        decoded_sym_256 = re.search(b'([0-9a-f]+) (\d+): decode, symbol=256', disasm.stdout)
        if decoded_sym_256:
            is_stream_ready = True

            # include padded bits for next operations
            new_bits = "".join(bin(x)[2:].rjust(8, "0") for x in new_bytes)

            break

    if not is_stream_ready:
        raise RuntimeError("Expected end-of-block symbol after codes!")

    print("Concatenating new stream to input stream...")

    # New stream will be followed by more streams, set BFINAL=0
    new_bits = ''.join(patch(list(new_bits), "0", 0, 7))

    next_byte_i = int(decoded_sym_256.group(1), 16)
    next_bit_i = int(decoded_sym_256.group(2), 10)
    print(next_byte_i, next_bit_i)

    free_len = 8 - next_bit_i
    print(f"free_len: {free_len}")
    assert free_len <= 8  # FIXME: Need to decrement byte_i

    last_octet = new_bits[-8:][free_len:]
    new_bits = new_bits[:-8]
    new_bits = concat(new_bits, base_bits, last_octet)
    new_bytes = bits_to_bytes(new_bits)
    with open(output5_file, "wb") as f:
        f.write(new_bytes)

    print("Done!")
