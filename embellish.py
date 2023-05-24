#!/usr/bin/env python3

"""
Endues a DEFLATE stream with the grace of your offered message.

To preserve the same decompression output, the message is applied to a
duplicate of the first dynamic DEFLATE block in the provided stream, which
will not produce any output when decompressed. This duplicate is then
concatenated to the rest of the stream.
"""

import colorama
import subprocess
import sys
import re

import bitsturi
from huffman_solver import MAXHDIST, MAXHLIT, MAXBITS, solve
from typing import Any, Tuple


HLIT_OFFSET = 0
HDIST_OFFSET = 8 * 1 + 3
BFINAL_OFFSET = 7


def hibold(text):
    return colorama.Style.BRIGHT + str(text) + colorama.Style.RESET_ALL


def hi1(text):
    return (
        colorama.Fore.RED + colorama.Style.BRIGHT + str(text) + colorama.Style.RESET_ALL
    )


def hi2(text):
    return (
        colorama.Fore.MAGENTA
        + colorama.Style.BRIGHT
        + str(text)
        + colorama.Style.RESET_ALL
    )


def inject_message(
    hlit: int, message: str, disasm: Any, out_filename: str
) -> Tuple[int, int, str, Any]:
    inject_start_search = re.search(b"([0-9a-f]+) \\d+: ! decoded len ", disasm.stdout)
    inject_start = int(inject_start_search.group(1), 16)
    inject_end_search = re.search(b"([0-9a-f]+) \\d+: ! literal ", disasm.stdout)
    inject_end = int(inject_end_search.group(1), 16)
    print(f"Injection range: {hi2(hex(inject_start))}..{hi2(hex(inject_end))}")

    is_valid = False
    for i in range(inject_start + 1, inject_end - 1 - len(message)):
        print(f"  Trying message start @ {hi2(i)}...")
        candidate_hlit = hlit
        candidate_hdist = 0  # We don't use distance codes

        data_patched = data[0:i] + message.encode("ascii") + data[i + len(message) :]
        data_bits_patched = "".join(bin(x)[2:].rjust(8, "0") for x in data_patched)
        data_bits_patched = "".join(
            bitsturi.patch(
                list(data_bits_patched), bin(candidate_hlit)[2:].zfill(5), HLIT_OFFSET
            )
        )
        data_bits_patched = "".join(
            bitsturi.patch(
                list(data_bits_patched), bin(candidate_hdist)[2:].zfill(5), HDIST_OFFSET
            )
        )
        new_bytes = bitsturi.bits_to_bytes(data_bits_patched)
        with open(out_filename, "wb") as f:
            f.write(new_bytes)

        disasm = subprocess.run(
            ["infgen", "-d", out_filename],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        # TODO:
        # - Identify and remove last repetitions, avoiding oversubscribing
        # - Parse known length codes, so that others are added as exclusions to our solver
        too_many_lengths = re.search(
            b"repeat more lengths than available", disasm.stdout
        )
        over_subscribed = re.search(b"oversubscribed", disasm.stdout)
        missing_end_of_block = re.search(b"missing end-of-block", disasm.stdout)
        is_valid = not (too_many_lengths or over_subscribed)
        while not is_valid:
            if candidate_hlit > 1:
                candidate_hlit -= 1
                new_bits = "".join(
                    bitsturi.patch(
                        list(data_bits_patched),
                        bin(candidate_hlit)[2:].zfill(5),
                        HLIT_OFFSET,
                    )
                )
            else:
                break

            new_bytes = bitsturi.bits_to_bytes(new_bits)
            with open(out_filename, "wb") as f:
                f.write(new_bytes)

            disasm = subprocess.run(
                ["infgen", "-d", out_filename],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            too_many_lengths = re.search(
                b"repeat more lengths than available", disasm.stdout
            )
            over_subscribed = re.search(b"oversubscribed", disasm.stdout)
            missing_end_of_block = re.search(b"missing end-of-block", disasm.stdout)
            is_valid = not (too_many_lengths or over_subscribed)

        if not too_many_lengths and not over_subscribed and not missing_end_of_block:
            print("Got stream with valid codes!")
            is_valid = True
            break

    if not is_valid:
        raise RuntimeError("Could not fit message, try a smaller/different one...")

    return candidate_hlit, candidate_hdist, new_bits, disasm


def patch_codes(
    candidate_hlit: int,
    candidate_vhcode: int,
    new_bits: str,
    regex_incomplete_err: bytes,
    code_type: str,
    max_count: int,
    offset: int,
    disasm: Any,
    out_filename: str,
) -> Tuple[int, str, Any, Any]:
    # FIXME: When huffman tables are implemented, we don't need to parse these codes
    code_bits = {}
    dist_1_bits = None
    sym_256_data = None
    for match in re.finditer(
        b"! decoded len (\\d+) bits (\\d+) sym_i (\\d+) .* (\\d+)", disasm.stdout
    ):
        code_bits[int(match.group(4), 10)] = match.group(2)
        sym_i = int(match.group(3), 10)
        if sym_i == candidate_hlit + 257:
            dist_1_bits = match.group(2)
        if sym_i == 256:
            sym_256_data = {
                "bits": match.group(2),
                "sym_len": int(match.group(4), 10),
            }
    print("  code_bits:", hibold(code_bits))
    print("  dist_1_bits:", hibold(dist_1_bits))
    print("  sym_256_data:", hibold(sym_256_data))

    missing_codes = re.search(regex_incomplete_err, disasm.stdout)
    if missing_codes:
        print(f"Finding remaining {code_type} codes...")

        next_byte_i = int(missing_codes.group(1), 16)
        next_bit_i = int(missing_codes.group(2), 10)

        exclusions = {}
        litlen_counts = {}
        for match in re.finditer(
            f"! construct {code_type} len (\\d+) count (\\d+)".encode(), disasm.stdout
        ):
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
        print("  exclusions:", hibold(exclusions))
        print("  litlen_counts:", hibold(litlen_counts))
        new_counts = solve(litlen_counts, exclusions, max_count)
        need_counts = {}
        for k, v in new_counts.items():
            if k == 0:
                continue
            if k in litlen_counts:
                if v - litlen_counts[k] > 0:
                    need_counts[k] = v - litlen_counts[k]
            elif v > 0:
                need_counts[k] = v
        print("Need to add codes:", hibold(need_counts))

        # Add codes
        print(f"  offset: {hi2(next_byte_i)} {hi1(next_bit_i)}")

        free_len = 8 - next_bit_i + len(dist_1_bits)
        print(f"  free_len: {hibold(free_len)}")
        assert free_len <= 8  # FIXME: Need to decrement byte_i

        new_bits = new_bits[: ((next_byte_i) * 8)]
        print(f"  bits: {hi1(new_bits)}")

        last_octet = new_bits[-8:][free_len:]
        new_bits = new_bits[:-8]
        next_bits = bitsturi.add(code_bits, need_counts, last_octet)
        new_bits = new_bits + next_bits
        print(f"  last_octet: {hi1(last_octet)}")
        print(f"  next_bits: {hi1(next_bits)}")

        added_counts = 0
        for k, v in need_counts.items():
            for i in range(v):
                added_counts += 1
        candidate_vhcode += added_counts
        new_bits = "".join(
            bitsturi.patch(
                list(new_bits),
                bin(candidate_vhcode)[2:].zfill(5),
                offset,
            )
        )
    else:
        print(f"We already have enough {code_type} codes!")

    new_bytes = bitsturi.bits_to_bytes(new_bits)
    with open(out_filename, "wb") as f:
        f.write(new_bytes)
    # include padded bits for next operations
    new_bits = "".join(bin(x)[2:].rjust(8, "0") for x in new_bytes)

    # always check that litlen codes are valid (we either patched them or something after them)
    disasm = subprocess.run(
        ["infgen", "-d", out_filename],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    missing_codes = re.search(
        b"([0-9a-f]+) (\\d+): .* literal/length code is incomplete", disasm.stdout
    )
    if missing_codes:
        raise RuntimeError(
            "Expected solved litlen codes, but output is still incomplete!"
        )
    if code_type == "dist":
        missing_codes = re.search(
            b"([0-9a-f]+) (\\d+): ! under-subscribed dist", disasm.stdout
        )
        if missing_codes:
            raise RuntimeError(
                "Expected solved dist codes, but output is still incomplete!"
            )

    return candidate_vhcode, new_bits, sym_256_data, disasm


def add_eob_symbol(
    new_bits: str, missing_data: Any, out_filename: str
) -> Tuple[str, Any]:
    print("Adding end-of-block symbol...")

    next_byte_i = int(missing_data.group(1), 16)
    next_bit_i = int(missing_data.group(2), 10)
    print(f"  offset: {hi2(next_byte_i)} {hi1(next_bit_i)}")

    free_len = 8 - next_bit_i
    print(f"  free_len: {hibold(free_len)}")
    assert free_len <= 8  # FIXME: Need to decrement byte_i

    # FIXME: When huffman tables are implemented, we don't need to brute symbol 256 bits
    new_bits_base = new_bits[:]
    is_stream_ready = False
    for candidate in range(2 << sym_256_data["sym_len"] - 1):
        new_bits = new_bits_base[:]
        last_octet = new_bits[-8:][free_len:]
        new_bits = new_bits[:-8]
        new_bits = bitsturi.concat(
            new_bits, bin(candidate)[2:].zfill(sym_256_data["sym_len"]), last_octet
        )

        new_bytes = bitsturi.bits_to_bytes(new_bits)
        with open(out_filename, "wb") as f:
            f.write(new_bytes)

        disasm = subprocess.run(
            ["infgen", "-d", out_filename],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        decoded_sym_256 = re.search(
            b"([0-9a-f]+) (\\d+): decode, symbol=256", disasm.stdout
        )
        if decoded_sym_256:
            is_stream_ready = True

            # include padded bits for next operations
            new_bits = "".join(bin(x)[2:].rjust(8, "0") for x in new_bytes)

            break

    if not is_stream_ready:
        raise RuntimeError("Expected end-of-block symbol after codes!")

    return new_bits, decoded_sym_256


def add_block_to_stream(new_bits: str, base_bits: str, decoded_sym_256: Any) -> str:
    print("Concatenating new stream to input stream...")

    # New stream will be followed by more streams, set BFINAL=0
    new_bits = "".join(bitsturi.patch(list(new_bits), "0", BFINAL_OFFSET))

    next_byte_i = int(decoded_sym_256.group(1), 16)
    next_bit_i = int(decoded_sym_256.group(2), 10)
    print(f"  offset: {hi2(next_byte_i)} {hi1(next_bit_i)}")

    free_len = 8 - next_bit_i
    print(f"  free_len: {hibold(free_len)}")
    assert free_len <= 8  # FIXME: Need to decrement byte_i

    last_octet = new_bits[-8:][free_len:]
    new_bits = new_bits[:-8]
    new_bits = bitsturi.concat(new_bits, base_bits, last_octet)

    return new_bits


def parse_block_header(base_bits: str) -> Tuple[int, int]:
    print("Parsing block header...")

    base_chunks = bitsturi.chunks(base_bits, 8)
    next_byte_i = 0
    buf = ""

    bfinal_bits, next_byte_i, buf = bitsturi.extract(base_chunks, 1, next_byte_i, buf)
    bfinal = int(bfinal_bits, 2)
    print(f"  BFINAL {hi1(bfinal_bits):<18} = {hibold(bfinal)}")

    btype, next_byte_i, buf = bitsturi.extract(base_chunks, 2, next_byte_i, buf)
    vbtype = int(btype, 2)
    if vbtype != 2:
        raise RuntimeError(
            "Not a dynamic huffman table (expected BTYPE=0b10, got 0b{btype})."
        )
    print(f"  BTYPE  {hi1(btype):<18} = {hibold(vbtype)}")

    hlit_bits, next_byte_i, buf = bitsturi.extract(base_chunks, 5, next_byte_i, buf)
    hlit = int(hlit_bits, 2)
    print(f"  HLIT   {hi1(hlit_bits):<18} = {hibold(hlit)} (k + 257 = {hlit + 257})")

    hdist_bits, next_byte_i, buf = bitsturi.extract(base_chunks, 5, next_byte_i, buf)
    hdist = int(hdist_bits, 2)
    print(f"  HDIST  {hi1(hdist_bits):<18} = {hibold(hdist)} (k + 1 = {hdist + 1})")

    hclen_bits, next_byte_i, buf = bitsturi.extract(base_chunks, 4, next_byte_i, buf)
    hclen = int(hclen_bits, 2)
    print(f"  HCLEN  {hi1(hclen_bits):<18} = {hibold(hclen)} (k + 4 = {hclen + 4})")

    return hlit, hdist


if __name__ == "__main__":
    colorama.init()

    compressed_file = sys.argv[1]
    if not compressed_file:
        raise RuntimeError("No filename passed?")

    with open(compressed_file, "rb") as f:
        data = f.read()
        base_bits = "".join(bin(x)[2:].rjust(8, "0") for x in data)

    hlit, hdist = parse_block_header(base_bits)

    message = sys.argv[2]
    if not message:
        raise RuntimeError("No message passed?")

    disasm = subprocess.run(
        ["infgen", "-d", compressed_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    output_file = f"{compressed_file}.add_message.out"
    output2_file = f"{compressed_file}.add_litlen_codes.out"
    output3_file = f"{compressed_file}.add_all_codes.out"
    output4_file = f"{compressed_file}.add_sym_256.out"
    output5_file = f"{compressed_file}.embellished"

    candidate_hlit, candidate_hdist, new_bits, disasm = inject_message(
        hlit, message, disasm, output_file
    )

    candidate_hlit, new_bits, sym_256_data, disasm = patch_codes(
        candidate_hlit,
        candidate_hlit,
        new_bits,
        b"([0-9a-f]+) (\\d+): .* literal/length code is incomplete",
        "litlen",
        MAXHLIT,
        HLIT_OFFSET,
        disasm,
        output2_file,
    )

    candidate_hdist, new_bits, sym_256_data, disasm = patch_codes(
        candidate_hlit,
        candidate_hdist,
        new_bits,
        b"([0-9a-f]+) (\\d+): ! under-subscribed dist",
        "dist",
        MAXHDIST,
        HDIST_OFFSET,
        disasm,
        output3_file,
    )

    disasm = subprocess.run(
        ["infgen", "-d", output3_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    missing_data = re.search(
        b"([0-9a-f]+) (\\d+): incomplete deflate data", disasm.stdout
    )
    if not missing_data:
        raise RuntimeError("Expected missing deflate data!")

    new_bits, decoded_sym_256 = add_eob_symbol(new_bits, missing_data, output4_file)

    new_bits = add_block_to_stream(new_bits, base_bits, decoded_sym_256)

    new_bytes = bitsturi.bits_to_bytes(new_bits)
    with open(output5_file, "wb") as f:
        f.write(new_bytes)

    print("Done!")
