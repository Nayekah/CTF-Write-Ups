#!/usr/bin/env python3
from pwn import remote
from math import gcd

HOST = "127.0.0.1"
PORT = 9055

R = 12
BITS = 1024
GOAT = 910
M_BITS = 5680

def egcd(a, b):
    while b:
        a, b = b, a % b
    return a

def invmod(a, m):
    return pow(a, -1, m)

def gcd_list(xs):
    g = 0
    for x in xs:
        g = gcd(g, x)
    return g

def cf_terms(num, den):
    while den:
        a = num // den
        yield a
        num, den = den, num - a * den

def wiener_phi3_find_d(e, N, U1, z, d_bits_max=BITS + 64):
    N3 = N * N * N
    target = z % N
    base = U1 % N

    terms = list(cf_terms(e, N3))
    p_m2, p_m1 = 0, 1
    q_m2, q_m1 = 1, 0

    def try_kd(k, d):
        if k == 0 or d <= 0:
            return None
        if d.bit_length() > d_bits_max:
            return None
        if (e * d - 1) % k != 0:
            return None
        if pow(base, d, N) == target:
            return d
        return None

    for i, a in enumerate(terms):
        p = a * p_m1 + p_m2
        q = a * q_m1 + q_m2

        d_found = try_kd(p, q)
        if d_found is not None:
            return d_found

        if i >= 1 and a > 1:
            tmax = min(a - 1, 32)
            for t in range(1, tmax + 1):
                pp = t * p_m1 + p_m2
                qq = t * q_m1 + q_m2
                d_found = try_kd(pp, qq)
                if d_found is not None:
                    return d_found

        p_m2, p_m1 = p_m1, p
        q_m2, q_m1 = q_m1, q

        if q.bit_length() > d_bits_max:
            break

    return None

def rational_reconstruct(x, m, A, B):
    x %= m
    if x == 0:
        return (0, 1)

    r0, r1 = m, x
    s0, s1 = 1, 0
    t0, t1 = 0, 1

    while r1 > A:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
        t0, t1 = t1, t0 - q * t1

    a = r1
    b = t1
    if b == 0:
        return None

    if b < 0:
        a = -a
        b = -b

    if abs(a) > A or b > B:
        return None

    if (a - x * b) % m != 0:
        return None

    g = gcd(abs(a), b)
    a //= g
    b //= g

    a %= m
    if a > m // 2:
        a = a - m
    if a < 0:
        a = -a
        b = -b

    return (a, b)

def recover_s(N, e, d, M1, a, b, U1, U2):
    N2 = N * N

    m2 = M1 * a + b

    A = pow(U1, d, N2)
    B = pow(U2, e, N2)

    if gcd(A, N2) != 1:
        raise RuntimeError("A not invertible mod N^2.")

    C = (B * invmod(A, N2)) % N2

    t = (C - 1) % N2
    if t % N != 0:
        raise RuntimeError("(C-1) not divisible by N.")
    lin = (t // N) % N

    delta = (m2 - M1) % N
    coeff = (e % N) * (d % N) % N
    coeff = (coeff * delta) % N

    g = gcd(coeff, N)
    if g != 1:
        if lin % g != 0:
            raise RuntimeError("gcd(coeff,N)!=1")
        coeff //= g
        lin //= g
        N_red = N // g
        s_inv = (lin % N_red) * invmod(coeff % N_red, N_red) % N_red
        s = invmod(s_inv, N_red)
        raise RuntimeError("Hit rare non-invertible case;")
    else:
        s_inv = (lin * invmod(coeff, N)) % N
        s = invmod(s_inv, N)
        return s

def recv_until(io, token: bytes):
    data = b""
    while token not in data:
        chunk = io.recv(1)
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data

def recvline_str(io):
    return io.recvline().decode().strip()

def parse_int_line(line, prefix):
    if not line.startswith(prefix):
        raise ValueError(f"expected {prefix!r}, got {line!r}")
    return int(line.split("=", 1)[1].strip())

def main():
    io = remote(HOST, PORT)

    rounds = []

    for i in range(1, R + 1):
        while True:
            line = recvline_str(io)
            if line.startswith("=== Round"):
                break

        N = parse_int_line(recvline_str(io), "N")
        ab = parse_int_line(recvline_str(io), "a/b")
        c  = parse_int_line(recvline_str(io), "c")
        f  = parse_int_line(recvline_str(io), "f")
        z  = parse_int_line(recvline_str(io), "z")
        U1 = parse_int_line(recvline_str(io), "U1")
        U2 = parse_int_line(recvline_str(io), "U2")

        rounds.append({
            "N": N, "ab": ab, "c": c, "f": f, "z": z, "U1": U1, "U2": U2
        })

    diffs = [rd["f"] - rd["c"] for rd in rounds]
    M1 = gcd_list(diffs)
    if M1 <= 1 or M1.bit_length() > M_BITS + 64:
        raise RuntimeError(f"Bad M1 recovered: bitlen={M1.bit_length()}, M1={M1}")

    ss = []
    for idx, rd in enumerate(rounds, 1):
        N, ab, c, f, z, U1, U2 = rd["N"], rd["ab"], rd["c"], rd["f"], rd["z"], rd["U1"], rd["U2"]

        diff = f - c
        if diff % M1 != 0:
            raise RuntimeError("M1 does not divide (f-c).")
        e = diff // M1

        d = wiener_phi3_find_d(e, N, U1, z)
        if d is None:
            raise RuntimeError(f"Failed to recover d at round {idx}.")

        A = 1 << (GOAT + 4)
        B = 1 << (GOAT + 4)
        rec = rational_reconstruct(ab, N, A, B)
        if rec is None:
            A = 1 << (GOAT + 16)
            B = 1 << (GOAT + 16)
            rec = rational_reconstruct(ab, N, A, B)
        if rec is None:
            raise RuntimeError(f"Failed rational reconstruction at round {idx}.")
        a, b = rec

        s = recover_s(N, e, d, M1, a, b, U1, U2)
        ss.append(s)

    for i, s in enumerate(ss, 1):
        recv_until(io, b">> ")
        io.sendline(str(s).encode())

    print(io.recvall(timeout=5).decode(errors="ignore"))

if __name__ == "__main__":
    main()