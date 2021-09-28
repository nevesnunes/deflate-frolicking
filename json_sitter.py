#!/usr/bin/env python3

import ipdb
import os
import re
from collections import deque
from tree_sitter import Language, Parser

LOG_DEBUG = bool(str.upper(os.environ.get("LOG") or "") == "DEBUG")
LOG_INFO = bool(str.upper(os.environ.get("LOG") or "") == "INFO")


try:
    import colorama

    colorama.init()

    def hi_primary(text):
        return (
            colorama.Fore.MAGENTA
            + colorama.Style.BRIGHT
            + str(text)
            + colorama.Style.RESET_ALL
        )

    def hi_secondary(text):
        return (
            colorama.Fore.RED
            + colorama.Style.BRIGHT
            + str(text)
            + colorama.Style.RESET_ALL
        )


except ImportError:

    def hi_primary(text):
        return str(text)

    def hi_secondary(text):
        return str(text)


def log_debug(*args):
    if LOG_DEBUG:
        print(hi_secondary(args))


def log_info(*args):
    if LOG_INFO:
        print(hi_primary(args))


def id(node):
    return (node.type, node.start_point, node.end_point)


def pick(node):
    pick_reason = None
    if node.type == "ERROR":
        pick_reason = "error_type"
    if node.has_error:
        pick_reason = "has_error"
    if node.is_missing:
        pick_reason = "is_missing"
    if node.parent and node.parent.type == "ERROR":
        if node.type == '"':
            # '"' should be part of a pair.
            pick_reason = "dangling_token"
    if pick_reason:
        log_info(f"{pick_reason} {node}")
    return pick_reason


def bfs(tree, text):
    root = tree.root_node
    parents = {id(root): None}
    queue = deque([root])
    picked_node = root if pick(root) else None
    count_valid_tokens = 0 if pick(root) else 1
    while queue:
        node = queue.popleft()
        log_debug(1, node, node.sexp())
        log_debug(1, f"cvt={count_valid_tokens}")
        for neighbor in node.children:
            if id(neighbor) not in parents:
                parents[id(neighbor)] = node
                queue.append(neighbor)
                if pick(neighbor):
                    picked_node = neighbor
                    queue = deque([neighbor])
                    break
                else:
                    count_valid_tokens += 1

    if not picked_node:
        return count_valid_tokens, picked_node

    # If a node was picked, but it's not a leaf node, then check for gaps in parsed tokens. First gap matches first error. If no gaps found, pick first child.
    if len(picked_node.children) > 0:
        last_seen_byte = picked_node.children[0].start_byte
        for pick_child in picked_node.children:
            log_debug(2, pick_child)
            if pick(pick_child):
                log_debug(2, "pick")
                return count_valid_tokens, pick_child

            last_seen_dist = pick_child.start_byte - (last_seen_byte + 1)

            text_in_gap = text[last_seen_byte + 1 : pick_child.start_byte]
            log_debug(
                3,
                text_in_gap,
                last_seen_byte + 1,
                pick_child.start_byte,
                last_seen_dist,
            )
            if len(text_in_gap) > 0:
                count_whitespace = len(re.findall(b"\s+", text_in_gap))
                last_seen_dist -= count_whitespace

            if last_seen_dist > 0:
                log_debug(2, "last_seen_dist > 0")
                return count_valid_tokens, pick_child

            last_seen_byte = pick_child.end_byte
        # No child found with errors, but multiple cases can happen here: first token being valid with the rest being errors, or all being valid (error is a missing token at the end), or all being errors... let's compromise and pick the last child.
        # return picked_node.children[-1]
        return (
            count_valid_tokens,
            picked_node.children[1]
            if len(picked_node.children) > 1
            else picked_node.children[-1],
        )

    return count_valid_tokens, picked_node


def init():
    Language.build_library(
        "build/tree-sitter-languages.so",
        ["vendor/tree-sitter-json"],
    )

    lang = Language("build/tree-sitter-languages.so", "json")
    parser = Parser()
    parser.set_language(lang)
    return parser, lang


if __name__ == "__main__":
    LOG_INFO = True
    parser, lang = init()
    samples = [
        [b'{"a":[1]}', 0],
        [b'\n,{"a":[1]}', 1],
        [b'{"a":[1]', 8],
        [b'{"a":[1],,,,,"d":2","f":3', 9],
        [b'{"a":[1]},{"d":2","f":3}', 9],
        [b'{"a":[1,2,\x10\x11],"b":{"c":{"d":2}}}', 10],
        [b'{"a":[1,2,3,4,,5,,6,7,8]}', 14],
        [b'{"a":{"b":{"c":[{"d":}]}}}', 21],
        [b'{"a":[1],"b":{"c":{"d":2"}},"f":3}', 24],
        [b'{"a":"0","b":1,"c":{"id', 20],
        [b'{"a":"0","b":1,"c":{"id:3,"d":4,"e":5', 27],
        [b'{\n\t"a": "0",\n\t"b": 1,\n\t"c": { "id', 30],
    ]
    with ipdb.launch_ipdb_on_exception():
        for sample in samples:
            print(sample)
            tree = parser.parse(sample[0])
            print(tree.root_node.sexp())
            count_valid_tokens, error_node = bfs(tree, sample[0])
            error_byte_i = error_node.start_byte if error_node else 0
            print(count_valid_tokens, error_byte_i)
            assert error_byte_i == sample[1]
            print("---")

    # query = lang.query("""
    # (ERROR) @e
    # """)
    # captures = query.captures(tree.root_node)
    # print(captures)
