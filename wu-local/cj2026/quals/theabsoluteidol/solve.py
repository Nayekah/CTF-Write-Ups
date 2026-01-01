#!/usr/bin/env python3
import ast
import itertools
import math
import sys
from math import comb

def parse_output_txt(path: str) -> dict:
    data = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            try:
                data[k] = ast.literal_eval(v)
            except Exception:
                data[k] = v
    need = ["N", "sum_cs", "ls", "cts", "flag"]
    for k in need:
        if k not in data:
            raise ValueError(f"Missing '{k}' in {path}")
    return data

def inv_mod(a, n):
    a %= n
    g = math.gcd(a, n)
    if g != 1:
        raise ValueError(f"no inverse for {a} mod N, gcd={g}")
    return pow(a, -1, n)

def int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    L = (n.bit_length() + 7) // 8
    return n.to_bytes(L, "big")

def poly_trim(p):
    while p and p[-1] == 0:
        p.pop()
    return p

def poly_deg(p):
    poly_trim(p)
    return len(p) - 1

def poly_add(a, b, mod):
    n = max(len(a), len(b))
    r = [0] * n
    for i in range(n):
        r[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % mod
    return poly_trim(r)

def poly_sub(a, b, mod):
    n = max(len(a), len(b))
    r = [0] * n
    for i in range(n):
        r[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % mod
    return poly_trim(r)

def poly_mul(a, b, mod):
    if not a or not b:
        return []
    r = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj == 0:
                continue
            r[i + j] = (r[i + j] + ai * bj) % mod
    return poly_trim(r)

def poly_scale(a, k, mod):
    if not a or k % mod == 0:
        return []
    return [(c * k) % mod for c in a]

def poly_divmod(a, b, mod):
    a = a[:]
    poly_trim(a)
    b = b[:]
    poly_trim(b)
    if not b:
        raise ZeroDivisionError
    da, db = len(a) - 1, len(b) - 1
    if da < db:
        return [], a
    lc = b[-1] % mod
    invlc = inv_mod(lc, mod)
    q = [0] * (da - db + 1)
    while a and len(a) - 1 >= db:
        da = len(a) - 1
        coeff = a[-1] * invlc % mod
        pos = da - db
        q[pos] = coeff
        for j in range(db + 1):
            a[pos + j] = (a[pos + j] - coeff * b[j]) % mod
        poly_trim(a)
    return poly_trim(q), poly_trim(a)

def poly_gcd(a, b, mod):
    a = a[:]
    b = b[:]
    poly_trim(a)
    poly_trim(b)
    if not a:
        return b
    if not b:
        return a
    while b:
        _, r = poly_divmod(a, b, mod)
        a, b = b, r
    lc = a[-1] % mod
    return poly_scale(a, inv_mod(lc, mod), mod)

def poly_y_pow_e_minus_c(e, cval, mod):
    p = [0] * (e + 1)
    p[0] = (-cval) % mod
    p[e] = 1
    return poly_trim(p)

def poly_w_minus_y_pow_e_minus_c(e, w, cval, mod):
    p = [0] * (e + 1)
    for j in range(e + 1):
        coef = comb(e, j) * pow(w, e - j, mod) % mod
        if j & 1:
            coef = (-coef) % mod
        p[j] = coef
    p[0] = (p[0] - cval) % mod
    return poly_trim(p)

def interpolate_consecutive(ys, mod):
    diffs = [y % mod for y in ys]
    coefs = []
    while diffs:
        coefs.append(diffs[0])
        diffs = [(diffs[i + 1] - diffs[i]) % mod for i in range(len(diffs) - 1)]

    res = [0]
    basis = [1]

    for k, ck in enumerate(coefs):
        if ck:
            res = poly_add(res, poly_scale(basis, ck, mod), mod)
        if k == len(coefs) - 1:
            break
        basis = poly_mul(basis, [(-k) % mod, 1], mod)
        basis = poly_scale(basis, inv_mod(k + 1, mod), mod)
    return poly_trim(res)

PERMS_5 = []
for perm in itertools.permutations(range(5)):
    inv_parity = 0
    for i in range(5):
        for j in range(i + 1, 5):
            if perm[i] > perm[j]:
                inv_parity ^= 1
    PERMS_5.append((perm, -1 if inv_parity else 1))

def ext_mul5(a, b, c, mod):
    a0, a1, a2, a3, a4 = a
    b0, b1, b2, b3, b4 = b
    t0 = a0 * b0
    t1 = a0 * b1 + a1 * b0
    t2 = a0 * b2 + a1 * b1 + a2 * b0
    t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0
    t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0
    t5 = a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1
    t6 = a2 * b4 + a3 * b3 + a4 * b2
    t7 = a3 * b4 + a4 * b3
    t8 = a4 * b4
    r0 = (t0 + t5 * c) % mod
    r1 = (t1 + t6 * c) % mod
    r2 = (t2 + t7 * c) % mod
    r3 = (t3 + t8 * c) % mod
    r4 = (t4) % mod
    return [r0, r1, r2, r3, r4]


def ext_eval_F_at_t_shift(F, t, c, mod, plus=False):
    b = [t % mod, 1 if plus else (mod - 1), 0, 0, 0]
    acc = [0, 0, 0, 0, 0]
    for coef in reversed(F):
        acc = ext_mul5(acc, b, c, mod)
        if coef:
            acc[0] = (acc[0] + coef) % mod
    return acc

def ext_norm5(a, c, mod):
    M = [[0] * 5 for _ in range(5)]
    for i in range(5):
        M[i][0] = a[i] % mod
    col = a[:]
    for j in range(1, 5):
        col = [(col[4] * c) % mod, col[0], col[1], col[2], col[3]]
        for i in range(5):
            M[i][j] = col[i]

    total = 0
    for perm, sign in PERMS_5:
        prod = 1
        for i in range(5):
            prod = (prod * M[i][perm[i]]) % mod
        total = (total + prod) if sign == 1 else (total - prod)
    return total % mod


def resultant_shift_e5(F, c_val, mod, plus=False):
    d = poly_deg(F)
    D = d * 5
    c = c_val % mod
    ys = []
    for t in range(D + 1):
        elem = ext_eval_F_at_t_shift(F, t, c, mod, plus=plus)
        ys.append(ext_norm5(elem, c, mod))
    return interpolate_consecutive(ys, mod)

def solve_two_e5(c1, c2, w, mod):
    f = poly_y_pow_e_minus_c(5, c1, mod)
    g = poly_w_minus_y_pow_e_minus_c(5, w, c2, mod)
    G = poly_gcd(f, g, mod)
    if poly_deg(G) != 1:
        raise ValueError("gcd not linear for k=2 (unexpected)")
    a0, a1 = G[0], G[1]
    x1 = (-a0) * inv_mod(a1, mod) % mod
    x2 = (w - x1) % mod
    return [x1, x2]

def solve_linear_sum_e5(cipher_list, w, mod):
    k = len(cipher_list)
    if k == 2:
        return solve_two_e5(cipher_list[0], cipher_list[1], w, mod)

    h = k // 2

    R = poly_y_pow_e_minus_c(5, cipher_list[0], mod)
    for i in range(1, h):
        R = resultant_shift_e5(R, cipher_list[i], mod, plus=False)

    S = poly_w_minus_y_pow_e_minus_c(5, w, cipher_list[-1], mod)
    for idx in range(k - 2, h - 1, -1):
        S = resultant_shift_e5(S, cipher_list[idx], mod, plus=True)

    G = poly_gcd(R, S, mod)
    if poly_deg(G) != 1:
        raise ValueError("middle gcd not linear (unexpected)")
    yh = (-G[0]) * inv_mod(G[1], mod) % mod

    left = solve_linear_sum_e5(cipher_list[:h], yh, mod)
    right = solve_linear_sum_e5(cipher_list[h:], (w - yh) % mod, mod)
    return left + right

def main():
    if len(sys.argv) < 2:
        path = "output.txt"
    else:
        path = sys.argv[1]

    out = parse_output_txt(path)
    N = int(out["N"])
    sum_cs = int(out["sum_cs"])
    ls = list(out["ls"])
    cts = list(out["cts"])
    flag_out = int(out["flag"])

    e = 5
    w = sum_cs % N
    a = [li % N for li in ls]

    enc_m = [(pow(ai, e, N) * ci) % N for ai, ci in zip(a, cts)]
    ms = solve_linear_sum_e5(enc_m, w, N)
    cs_rec = [(mi * inv_mod(ai, N)) % N for mi, ai in zip(ms, a)]

    flag0 = flag_out
    for c in cs_rec:
        flag0 ^= c

    fb = int_to_bytes(flag0)
    print(fb)

if __name__ == "__main__":
    main()