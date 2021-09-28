#!/usr/bin/env python3

from z3 import *

MAXBITS = 16
MAXHDIST = 29
MAXHLIT = 285


def solve(code_counts, exclusions, max_codes):
    z3.set_param(proof=True)
    s = Optimize()

    # Known input
    f_len = MAXBITS
    f = [Int("{:04d}".format(i)) for i in range(f_len)]
    for k, v in exclusions.items():
        s.add(f[k] == v)
    s.add(f[0] >= 0)
    s.add(f[1] >= 0)

    # Huffman table validation
    left = 2 - f[1]
    for i in range(2, f_len, 1):
        s.add(And(f[i] >= 0, f[i] < (1 << i)))
        left = (left * 2) - f[i]
    s.add(left == 0)

    # Avoid solutions requiring more codes than the maximum allowed
    s.add(Sum(f) <= max_codes)

    # We prefer solutions with the minimum number of additional lengths necessary,
    # so that we can use larger payloads
    s.minimize(Sum(f))

    # Used code lengths so far
    for k, v in code_counts.items():
        s.add(f[k] >= v)

    if s.check() == sat:
        print("Found solution:")
        model = s.model()
        vs = [(v, model[v]) for v in model]
        vs = sorted(vs, key=lambda a: str(a))
        new_code_counts = {}
        for k, v in vs:
            print(k, v)
            ik = int(str(k), 10)
            new_code_counts[ik] = int(str(v), 10)
        return new_code_counts
    else:
        print(s.unsat_core())
        print(s.__repr__())
        raise RuntimeError("No solution.")


if __name__ == "__main__":
    lit_counts = {
        3: 2,
        4: 3,
        5: 8,
        7: 13,
        8: 33,
        9: 19,
        10: 13,
    }
    solve(lit_counts, {}, MAXHLIT)

    dist_counts = {10: 1}
    solve(dist_counts, {}, MAXHDIST)
