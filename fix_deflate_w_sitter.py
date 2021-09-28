#!/usr/bin/env python3

'''
Attempts to correct DEFLATE stream corruption consisting
of isolated 1 or 2 bytes.

Algorithm:
- Bruteforce 2 bytes at a time, checking if the decompression
  result length is larger than the previous.

Example error throwed by `zlib` for this corruption:
> Error -3 while decompressing data: invalid distance too far back
'''

from collections import deque
import ipdb
import json_sitter
import os
import re
import subprocess
import sys
import tempfile
import zlib

CHUNKSIZE = 2

# −8 to −15: Uses the absolute value of wbits as the window size logarithm.
#            The input must be a raw stream with no header or trailer.
# Reference: https://docs.python.org/3/library/zlib.html#decompress-wbits
WSIZE_LOG = -15

MAX_DISPLAY_LEN = 120

EDITOR = os.environ.get("EDITOR", "vim")

PARSER, LANG = json_sitter.init()


def snip(text, tail_i):
    if len(text) > 2 * MAX_DISPLAY_LEN:
        tail_display_len = max(tail_i, MAX_DISPLAY_LEN)
        if tail_i < MAX_DISPLAY_LEN:
            return f"{text}"
        else:
            return f"{text[:MAX_DISPLAY_LEN]} [...] {text[-tail_display_len:]} [+ {(len(text) - MAX_DISPLAY_LEN - tail_display_len)} byte(s)]"
    else:
        return f"{text}"


def fix(data, i, last_fix_i, best_len=0, best_count_valid_tokens=0):
    queue = []
    o = b""
    best_k = data[i]
    best_k2 = data[i + 1]
    best_has_errors = True
    initial_i = i
    seen_sitter_data = {}
    for wi in range(-CHUNKSIZE, CHUNKSIZE - 1):
        if last_fix_i > -1 and i + wi <= last_fix_i:
            # Index already has best value
            continue

        prev_c = data[i + wi]
        for k in range(0xFF):
            data[i + wi] = k

            prev_c2 = data[i + wi + 1]
            for k2 in range(0xFF):
                data[i + wi + 1] = k2

                o, i_, has_errors_ = decompress(data)

                tree = PARSER.parse(o)
                count_valid_tokens, error_node = json_sitter.bfs(tree, o)
                error_byte_i = error_node.start_byte if error_node else float("inf")

                # FIXME: skip entries with same output, prefer 1 byte vs. 2 bytes changes
                # if count_valid_tokens >= best_count_valid_tokens and error_byte_i >= best_len:
                # if error_byte_i >= best_len:
                best_k = k
                best_k2 = k2
                best_has_errors = has_errors
                best_count_valid_tokens = count_valid_tokens
                # FIXME: How to account for valid matches with less len than best_len?
                best_len = error_byte_i

                changed_bytes = 0
                changed_bytes += 1 if prev_c != k else 0
                changed_bytes += 1 if prev_c2 != k2 else 0
                patch_data = [
                    o[:],
                    i + wi,
                    best_k,
                    best_k2,
                    best_has_errors,
                    best_count_valid_tokens,
                    best_len,
                ]
                if o not in seen_sitter_data:
                    seen_sitter_data[o] = [changed_bytes, patch_data]
                if seen_sitter_data[o][0] > changed_bytes:
                    seen_sitter_data[o] = [changed_bytes, patch_data]

            data[i + wi + 1] = prev_c2
        data[i + wi] = prev_c

    for v in seen_sitter_data.values():
        queue.append(v[1])

    assert len(queue) > 0
    queue = sorted(queue, key=lambda x: x[6])[::-1]

    return queue


def decompress(data, end_i=float("inf")):
    has_errors = False
    decompress_obj = zlib.decompressobj(WSIZE_LOG)
    o = b""
    i = 0
    try:
        for i in range(0, len(data) // CHUNKSIZE + 1, 1):
            if i > end_i:
                has_errors = True
                break

            buffer = data[CHUNKSIZE * i : CHUNKSIZE * (i + 1)]
            o += decompress_obj.decompress(buffer)
    except BaseException:
        has_errors = True
    return o, i, has_errors


def dump(i, k, k2, data, o, debug=False):
    prefix = "@"
    if debug:
        prefix += "d_"
    signature = f"{prefix}{hex(i_)}_{hex(k)}_{hex(k2)}"
    with open(f"{signature}.fix", "wb") as f:
        f.write(data)
    with open(f"{signature}.out", "wb") as f:
        f.write(o)
    if debug:
        with open(f"{signature}.sitter", "w") as f:
            tree = PARSER.parse(o)
            count_valid_tokens, error_node = json_sitter.bfs(tree, o)
            error_byte_i = error_node.start_byte if error_node else 0
            f.write(hex(error_byte_i))


# TODO: hexdiff against longest len output
initial_message = b"""# Commands:
# p, pick <line> = use line for patch
# d, drop <line> = ignore line
# w, write <line> = write state for debugging
# x, expand <line> = show full line contents
#
# Lines starting with '#' will be ignored.
# This file will be restored if no line is picked.
"""


def parse_commands(message, queue, data):
    with tempfile.NamedTemporaryFile(suffix=".tmp") as tf:
        tf.write(pick_message)
        tf.flush()
        subprocess.call(EDITOR.split() + [tf.name])

        with open(tf.name, "r") as f:
            message = f.read()

    expands = re.findall("^x ([0-9]*)", message, re.MULTILINE)
    for x in expands:
        q_i = int(x)
        o, i_, k, k2, has_errors, count_valid_tokens_, len_ = queue[q_i]
        signature = f"@{hex(i_)}_{hex(k)}_{hex(k2)}"
        expanded = bytes(signature, encoding="latin-1") + b"\n" + o
        with tempfile.NamedTemporaryFile(suffix=".tmp") as tf:
            tf.write(expanded)
            tf.flush()
            subprocess.call(EDITOR.split() + [tf.name])

    debugs = re.findall("^w ([0-9]*)", message, re.MULTILINE)
    for d in debugs:
        q_i = int(d)
        o, i_, k, k2, has_errors, count_valid_tokens_, len_ = queue[q_i]
        data2 = data[:]
        data2[i_] = k
        data2[i_ + 1] = k2
        dump(i_, k, k2, data2, o, debug=True)

    picks = re.findall("^p ([0-9]*)", message, re.MULTILINE)
    if len(picks) > 0:
        return int(picks[0])

    return None


if __name__ == "__main__":
    data = bytearray(open(sys.argv[1], "rb").read())
    end_i = float("inf")
    if len(sys.argv) > 2:
        end_i = int(sys.argv[2], 0)

    last_fix_i = -1
    last_count_valid_tokens = 0
    o, i, has_errors = decompress(data, end_i)
    tail_i = len(o)
    with ipdb.launch_ipdb_on_exception():
        while has_errors:
            pick_message = initial_message[:]
            fix_i = CHUNKSIZE * i
            queue = fix(
                data[: CHUNKSIZE * (i + 0x40)],
                fix_i,
                last_fix_i,
                len(o),
                last_count_valid_tokens,
            )
            for q_i in range(len(queue)):
                o, i_, k, k2, has_errors, count_valid_tokens_, len_ = queue[q_i]
                k_str = hex(k)
                if data[i_] == k:
                    k_str = re.sub(".", ".", k_str)
                k2_str = hex(k2)
                if data[i_ + 1] == k2:
                    k2_str = re.sub(".", ".", k2_str)
                o_info = f"@{hex(i_)}_{k_str}_{k2_str}"
                pick_message += bytes(
                    f"\nd {q_i} ({o_info}, cvt={count_valid_tokens_}, len={len_}) {snip(o, tail_i)}",
                    encoding="latin-1",
                )

            assert len(queue) > 0

            q_i_pick = -1
            while q_i_pick not in range(len(queue)):
                q_i_pick = parse_commands(pick_message, queue, data)

            o, i_, k, k2, has_errors, count_valid_tokens_, len_ = queue[q_i_pick]
            data[i_] = k
            data[i_ + 1] = k2
            last_fix_i = i_
            last_count_valid_tokens = count_valid_tokens_
            o, i, has_errors = decompress(data)
            tail_i = len(o)

            dump(i_, k, k2, data, o)

            if not has_errors:
                break

    sys.stdout.buffer.write(o)
