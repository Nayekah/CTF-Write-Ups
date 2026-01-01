#!/usr/bin/env python3
from pwn import *
from math import gcd
from collections import Counter
import random
from Crypto.Util.number import inverse, long_to_bytes

def recv_ct(r):
    line = r.recvline().decode(errors="ignore").strip()
    while "ct" not in line:
        line = r.recvline().decode(errors="ignore").strip()
    return int(line.split()[-1], 16)

def recv_pt(r):
    line = r.recvline().decode(errors="ignore").strip()
    while "pt" not in line:
        line = r.recvline().decode(errors="ignore").strip()
    return int(line.split()[-1], 16)

def menu_encrypt(r, m_int):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", format(m_int, "x").encode())
    return recv_ct(r)

def menu_bingo(r):
    r.sendlineafter(b"> ", b"2")
    return recv_ct(r)

def menu_decrypt(r, ct_int):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"> ", format(ct_int, "x").encode())
    return recv_pt(r)

def idx_of(ct, n):
    t = pow(ct % n, (n - 1) // 2, n)
    return 0 if t == 1 else 1

def crt_combine(fp, fq, p, q):
    inv_p = inverse(p, q)
    t = ((fq - fp) % q) * inv_p % q
    return fp + p * t

def sample_base_C(r):
    m = random.getrandbits(700)
    C = menu_encrypt(r, m)
    for _ in range(3):
        C *= menu_encrypt(r, 1)
    return C

def recover_n(r, trials=28, K=14, dd_bitmin=900):
    counter = Counter()

    for _ in range(trials):
        C = sample_base_C(r)

        y = []
        ck = 1
        y.append(menu_decrypt(r, 1))
        for _ in range(1, K + 1):
            ck *= C
            y.append(menu_decrypt(r, ck))

        for i in range(K - 1):
            dd = y[i+2] - 2*y[i+1] + y[i]
            dd = abs(dd)
            if dd != 0 and dd.bit_length() >= dd_bitmin:
                counter[dd] += 1

        if counter:
            dd_val, dd_cnt = counter.most_common(1)[0]
            if dd_cnt >= 6 and 980 <= dd_val.bit_length() <= 1050 and dd_val % 2 == 1:
                return dd_val

    if not counter:
        raise RuntimeError("No large second-diffs.")

    cand, _ = counter.most_common(1)[0]
    for s in [3, 5, 7, 11, 13, 17, 19]:
        while cand % s == 0 and (cand // s).bit_length() >= 980:
            cand //= s

    if cand % 2 == 0:
        while cand % 2 == 0 and (cand // 2).bit_length() >= 980:
            cand //= 2

    if not (980 <= cand.bit_length() <= 1050) or cand % 2 == 0:
        raise RuntimeError(f"Best candidate n looks wrong (bitlen={cand.bit_length()}).")

    return cand

def factor_n(r, n, tries=350):
    n2 = n * n
    p = q = None
    Ap = Aq = None

    for _ in range(tries):
        c = menu_encrypt(r, 1) % n2
        c2 = (c * c) % n2

        if idx_of(c, n) != idx_of(c2, n):
            continue

        y1 = menu_decrypt(r, c)
        y2 = menu_decrypt(r, c2)
        s = (y2 - y1) % n
        g = gcd(s, n)
        if g == 1 or g == n:
            continue
        if not (450 <= g.bit_length() <= 540):
            continue

        if p is None:
            p, Ap = g, s
        elif q is None and g != p:
            q, Aq = g, s

        if p is not None and q is not None:
            if p > q:
                p, q = q, p
                Ap, Aq = Aq, Ap
            return p, q, Ap, Aq

    raise RuntimeError("Failed to factor n.")

def recover(r, n, p, q, Ap, Aq, tries=450):
    n2 = n * n
    invAp_q = inverse(Ap % q, q)
    invAq_p = inverse(Aq % p, p)

    fp = None
    fq = None

    for _ in range(tries):
        if fp is not None and fq is not None:
            break

        cf = menu_bingo(r) % n2
        cf2 = (cf * cf) % n2

        if idx_of(cf, n) != idx_of(cf2, n):
            continue

        y1 = menu_decrypt(r, cf)
        y2 = menu_decrypt(r, cf2)
        v = (y2 - y1) % n
        g = gcd(v, n)

        if g == p and fq is None:
            fq = (v % q) * invAp_q % q
        elif g == q and fp is None:
            fp = (v % p) * invAq_p % p

    if fp is None or fq is None:
        raise RuntimeError("Failed to recover both residues fp,fq..")

    flag_int = crt_combine(fp, fq, p, q)
    return long_to_bytes(flag_int)

def main():
    # r = process(["python3", "chall.py"])
    r = remote("127.0.0.1", 9056)

    n = recover_n(r, trials=28, K=14, dd_bitmin=900)
    print(f"[+] n recovered bits={n.bit_length()}")

    p, q, Ap, Aq = factor_n(r, n, tries=350)
    print(f"[+] p bits={p.bit_length()}  q bits={q.bit_length()}")

    flag = recover(r, n, p, q, Ap, Aq, tries=450)
    print("[+] flag:", flag)

    r.close()

if __name__ == "__main__":
    main()

# need to be automated for attack, hehe