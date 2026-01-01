#!/usr/bin/env python3
from sage.all import matrix, ZZ
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from mpmath import mp
import json

def lift_x(x):
    return mp.sqrt((x**2 - 1) / (2*x**2 - 1))

def double(pt):
    x, y = pt
    xf = (2*x*y) / (1 + 2*(x**2)*(y**2))
    yf = (y**2 - x**2) / (1 - 2*(x**2)*(y**2))
    return (xf, yf)

def add(pt1, pt2):
    x1, y1 = pt1
    x2, y2 = pt2
    xf = (x1*y2 + x2*y1) / (1 + 2*x1*x2*y1*y2)
    yf = (y1*y2 - x1*x2) / (1 - 2*x1*x2*y1*y2)
    return (xf, yf)

def scalar_multiply(pt, m: int):
    if m == 1:
        return pt
    half = scalar_multiply(pt, m // 2)
    ans = double(half)
    if m % 2 == 1:
        ans = add(ans, pt)
    return ans

def u_of_t(t):
    if t == 0:
        return mp.mpf("0")
    sgn = 1
    if t < 0:
        sgn = -1
        t = -t
    f = lambda T: 1 / mp.sqrt(1 + 4*(T**4))
    if t < 1:
        val = mp.quad(f, [0, t])
    else:
        val = mp.quad(f, [0, 1]) + mp.quad(f, [1, t])
    return sgn * val

def frac(x):
    return x - mp.floor(x)

def try_recover_N(alpha, beta, m_digits=120):
    m = ZZ(10) ** ZZ(m_digits)
    a = ZZ(int(mp.floor(alpha * mp.mpf(m))))
    b = ZZ(int(mp.floor(beta  * mp.mpf(m))))

    M = matrix(ZZ, 3, 3, [
        m, 0, 0,
        a, 1, 0,
        b, 0, 1
    ])

    W = ZZ(2) ** ZZ(128)
    for i in range(3):
        M[i, 2] *= W

    L = M.LLL()

    for i in range(L.nrows()):
        L[i, 2] //= W

    cands = []
    for row in L.rows():
        if row[2] == -1 or row[2] == 1:
            r = row
            if r[2] == 1:
                r = -r
            N = int(r[1])
            if N >= 0:
                cands.append(N)
    return cands

def decrypt_with_N(N, iv_hex, ct_hex):
    N &= (1 << 128) - 1
    key = int(N).to_bytes(16, "big")
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    return unpad(pt, 16)

def main():
    mp.dps = 800

    with open("output.txt", "r") as f:
        data = json.load(f)

    gx = mp.mpf(data["gx"]); gy = mp.mpf(data["gy"])
    px = mp.mpf(data["px"]); py = mp.mpf(data["py"])
    G = (gx, gy)
    P = (px, py)

    tG = gx * gy
    tP = px * py

    uG = u_of_t(tG)
    uP = u_of_t(tP)

    I = (mp.gamma(mp.mpf(1)/4) ** 2) / (4 * mp.sqrt(mp.pi))
    J = I / mp.sqrt(2)

    periods = [2*J, 4*J, 8*J, 16*J]

    iv_hex = data["iv"]
    ct_hex = data["ciphertext"]

    for Tper in periods:
        alpha = frac(uG / Tper)
        beta  = frac(uP / Tper)

        for sign in ["+", "-"]:
            beta_use = beta if sign == "+" else frac(-beta)

            for m_digits in [100, 120, 140]:
                cands = try_recover_N(alpha, beta_use, m_digits=m_digits)
                for N in cands:
                    try:
                        pt = decrypt_with_N(N, iv_hex, ct_hex)
                    except Exception:
                        continue
                    if b"{" in pt:
                        print("[+] period =", Tper)
                        print("[+] sign   =", sign, "m_digits =", m_digits)
                        print("[+] N      =", hex(N & ((1<<128)-1)))
                        print(pt)
                        return

if __name__ == "__main__":
    main()