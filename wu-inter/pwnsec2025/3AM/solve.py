#!/usr/bin/env sage -python
from sage.all import Matrix, ZZ, QQ, GF, PolynomialRing
from pwn import *
import sys
from itertools import combinations
import hmac, hashlib
from hashlib import shake_128

# === secp256k1 order ===
N  = int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

D_HOLES = [(0,16), (28,24), (96,32), (164,16)]
K_HOLES = [(36,24), (140,24)]

K_CHUNK1_POS = 36
K_CHUNK2_POS = 140
K_CHUNK_WIDTH = 24
K_BOUND = 1 << K_CHUNK_WIDTH   # u_i, v_i in [0, 2^24)

P_FIELD = 1144001070343154634288961
ACOEF   = 272144002963733033258483
BCOEF   = 454511900449591275020144

A_SET = (2,3,5)
N_ROWS = 900
BOUNDB = (1 << 16) - 1

HOST = "e9b99625c7e4bc54.chal.ctf.ae"
PORT = 443

def bits_clear_windows(x, windows):
    x = int(x)
    for pos, width in windows:
        mask = ((1 << width) - 1) << pos
        x &= ~mask
    return x

def mod_center(x, n):
    x = int(x) % int(n)
    if x > n//2:
        x -= n
    return x

def inv_mod(a, m):
    return pow(int(a), -1, int(m))

def HKDF(key, info, outlen=32):
    prk = hmac.new(b"\x00"*32, key, hashlib.sha256).digest()
    out = b""
    t = b""
    c = 1
    while len(out) < outlen:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        out += t
        c += 1
    return out[:outlen]

def mobius_apply(lam, mu, nu, x, p_field):
    d = (nu * x + 1) % p_field
    if d == 0:
        return None
    return ((lam * x + mu) * inv_mod(d, p_field)) % p_field

def mobius_inv(lam, mu, nu, y, p_field):
    denom = (y * nu - lam) % p_field
    if denom == 0:
        return None
    return ((mu - y) * inv_mod(denom, p_field)) % p_field

def read_header(io):
    line = io.recvline().strip().decode()
    assert line.startswith("Qx=0x")
    Qx = int(line.split("=",1)[1], 16)

    line = io.recvline().strip().decode()
    assert line.startswith("Qy=0x")
    Qy = int(line.split("=",1)[1], 16)

    line = io.recvline().strip().decode()
    assert line.startswith("d_masked=0x")
    d_masked = int(line.split("=",1)[1], 16)

    log.success(f"Qx = 0x{Qx:064x}")
    log.success(f"Qy = 0x{Qy:064x}")
    log.success(f"d_masked = 0x{d_masked:064x}")
    return Qx, Qy, d_masked

def menu_to_prompt(io):
    io.recvuntil(b"> ")

def ask_signature(io, msg=b"testmsg"):
    io.sendline(b"2")
    io.recvuntil(b"message: ")
    io.sendline(msg)

    ticket_line = io.recvline().strip().decode()
    assert ticket_line.startswith("ticket#")
    z_line = io.recvline().strip().decode()
    r_line = io.recvline().strip().decode()
    s_line = io.recvline().strip().decode()
    km_line = io.recvline().strip().decode()

    z = int(z_line.split("=",1)[1])
    r = int(r_line.split("=",1)[1])
    s = int(s_line.split("=",1)[1])
    k_masked = int(km_line.split("=",1)[1], 16)

    io.recvuntil(b"> ")

    return {
        "z": z,
        "r": r,
        "s": s,
        "k_masked": k_masked,
    }

def collect_signatures(io, num=12):
    sigs = []
    for i in range(num):
        msg = b"msg_%02d" % i
        sig = ask_signature(io, msg)
        log.info(f"[sig {i}] z={sig['z']}, r={sig['r']}, s={sig['s']}, "
                 f"k_masked=0x{sig['k_masked']:064x}")
        sigs.append(sig)
    return sigs

def get_dataset(io):
    io.sendline(b"1")
    rows = []
    for _ in range(N_ROWS):
        line = io.recvline().strip().decode()

        parts = line.split()
        if len(parts) != 3:
            log.error(f"Unexpected dataset line: {line}")
            raise ValueError("dataset parse error")
        idx = int(parts[0])
        a   = int(parts[1])
        y   = int(parts[2])
        rows.append((idx, a, y))
    io.recvuntil(b"> ")
    return rows

def get_ct(io):
    io.sendline(b"3")
    line = io.recvline().strip().decode()
    assert line.startswith("ct=0x")
    ct_hex = line.split("=",1)[1][2:]
    ct = bytes.fromhex(ct_hex)
    io.recvuntil(b"> ")
    return ct, ct_hex

def build_pair_lattice(sig1, sig2):
    """
    Given two signatures (z,r,s,k_masked) build a 5x5 lattice for
    unknown (u1, v1, u2, v2) using middle-bits-style equation:

      k1 + t k2 + u ≡ 0 (mod N)

    with k_i = k_masked_i + 2^36 u_i + 2^140 v_i.
    """
    z1, r1, s1, k1m = sig1["z"], sig1["r"], sig1["s"], sig1["k_masked"]
    z2, r2, s2, k2m = sig2["z"], sig2["r"], sig2["s"], sig2["k_masked"]

    inv_s1 = inv_mod(s1, N)
    inv_r2 = inv_mod(r2, N)

    # From De Micheli–Heninger (h_i=z_i):
    # t = -s1^{-1} s2 r1 r2^{-1}  (mod N)
    # u = s1^{-1} r1 h2 r2^{-1} - s1^{-1} h1
    t = (-inv_s1 * s2 * r1 * inv_r2) % N
    u = (inv_s1 * r1 * z2 * inv_r2 - inv_s1 * z1) % N

    # k1 + t k2 + u' ≡ 0 with
    # k_i = k_masked_i + 2^36 u_i + 2^140 v_i
    u_prime = (k1m + t * k2m + u) % N
    u_prime = mod_center(u_prime, N)

    c1 = 1 << K_CHUNK1_POS       # 2^36
    c2 = 1 << K_CHUNK2_POS       # 2^140
    c3 = (t * c1) % N            # t*2^36
    c4 = (t * c2) % N            # t*2^140

    Kb = K_BOUND
    B = Matrix(ZZ, 5, 5)
    B[0,0] = Kb * c1
    B[0,1] = Kb * c2
    B[0,2] = Kb * c3
    B[0,3] = Kb * c4
    B[0,4] = u_prime

    B[1,1] = N * Kb
    B[2,2] = N * Kb
    B[3,3] = N * Kb
    B[4,4] = N

    return B

def solve_pair_for_chunks(sig1, sig2):
    """
    Run LLL on pair-lattice; interpret short rows as integer linear
    equations in (u1,v1,u2,v2); solve 4 of them to get chunks.
    """
    B = build_pair_lattice(sig1, sig2)
    log.info("[*] Running LLL on 5x5 pair-lattice ...")
    A = B.LLL()

    Kb = K_BOUND
    eqs = []

    for r in A.rows():
        r = [int(x) for x in r]
        if all(r[i] == 0 for i in range(4)):
            continue
        if any(r[i] % Kb != 0 for i in range(4)):
            continue
        coeffs = [r[i] // Kb for i in range(4)]
        const  = int(r[4])
        eqs.append((coeffs, const))
        if len(eqs) >= 8:
            break

    if len(eqs) < 4:
        log.warning("[!] Not enough usable short equations from LLL")
        return None

    for idxs in combinations(range(len(eqs)), 4):
        A_mat = Matrix(QQ, 4, 4)
        b_vec = []

        for row_idx, eq_idx in enumerate(idxs):
            coeffs, const = eqs[eq_idx]
            for j in range(4):
                A_mat[row_idx, j] = QQ(coeffs[j])
            b_vec.append(QQ(-const))

        b_vec = Matrix(QQ, 4, 1, b_vec)

        try:
            sol = A_mat.solve_right(b_vec).column(0)
        except Exception:
            continue

        if not all(x.is_integer() for x in sol):
            continue
        u1, v1, u2, v2 = [int(x) for x in sol]

        u1_mod = u1 % Kb
        v1_mod = v1 % Kb
        u2_mod = u2 % Kb
        v2_mod = v2 % Kb

        return (u1_mod, v1_mod, u2_mod, v2_mod)

    log.warning("[!] No integral/bounded solution from pair equations")
    return None

def reconstruct_k(k_masked, u, v):
    return int(k_masked) \
           + (1 << K_CHUNK1_POS) * int(u) \
           + (1 << K_CHUNK2_POS) * int(v)

def try_recover_d_from_pair(sig1, sig2, d_masked):
    chunks = solve_pair_for_chunks(sig1, sig2)
    if chunks is None:
        return None
    u1, v1, u2, v2 = chunks
    log.info(f"[pair] chunks: u1={u1}, v1={v1}, u2={u2}, v2={v2}")

    k1 = reconstruct_k(sig1["k_masked"], u1, v1)
    z1, r1, s1 = sig1["z"], sig1["r"], sig1["s"]

    inv_r1 = inv_mod(r1, N)
    # s1 k1 ≡ z1 + r1 d  =>  d = (s1 k1 - z1) r1^{-1} (mod N)
    d = (s1 * k1 - z1) * inv_r1 % N
    d = int(d)

    if bits_clear_windows(d, D_HOLES) != d_masked:
        log.warning("[pair] d doesn't match d_masked, discard")
        return None

    return d

def verify_d_all_sigs(d, sigs):
    d = int(d)
    for i, sig in enumerate(sigs):
        z, r, s = sig["z"], sig["r"], sig["s"]
        inv_s = inv_mod(s, N)
        k_eff = inv_s * (z + r*d) % N
        if bits_clear_windows(k_eff, K_HOLES) != sig["k_masked"]:
            log.warning(f"[verify] signature {i} inconsistent for this d")
            return False
    return True

def derive_MK_from_d(d):
    h = hashlib.sha256(d.to_bytes(32, "big")).digest()
    MK = HKDF(h, b"mk", 32)
    return MK

def reconstruct_t_values(MK, dataset_rows):
    """
    For each row (i,a,y):
      - recompute lam,mu,nu from HKDF(MK, b"M|seed", 96)
      - recompute beta from HKDF(MK, b"b|seed", 16)
      - y0 = y - beta
      - t = Mobius^{-1}(lam,mu,nu, y0)
    Return dict: {a: [t_i,...]} for a in {2,3,5}
    """
    p = P_FIELD
    t_by_a = {2: [], 3: [], 5: []}

    for idx, a, y in dataset_rows:
        seed = idx.to_bytes(4, "big")

        # M-part: lam,mu,nu
        raw = HKDF(MK, b"M|" + seed, 96)
        lam = int.from_bytes(raw[:32], "big") % p
        if lam == 0:
            lam = 1
        mu  = int.from_bytes(raw[32:64], "big") % p
        nu  = int.from_bytes(raw[64:], "big") % p
        if nu == 0:
            nu = 1

        # b-part: beta
        braw = HKDF(MK, b"b|" + seed, 16)
        beta = int.from_bytes(braw, "big") % (2*BOUNDB + 1)
        beta -= BOUNDB

        y0 = (y - beta) % p
        t = mobius_inv(lam, mu, nu, y0, p)
        if t is None:
            log.warning(f"[mobius_inv] got None at idx={idx}, a={a}")
            continue

        if a not in t_by_a:
            continue
        t_by_a[a].append(t)

    return t_by_a

def majority_value(vals):
    """
    For each a, t-values should be all equal (no residual noise).
    We'll just check frequencies and pick the most common value.
    """
    if not vals:
        return None
    counts = {}
    for v in vals:
        counts[v] = counts.get(v, 0) + 1
    v_best, c_best = max(counts.items(), key=lambda kv: kv[1])
    if c_best < len(vals):
        log.warning(f"[majority] collisions: best={c_best}, total={len(vals)}")
    return v_best

def x2_formula(x, a, b, p):
    """
    x(2P) = (x^4 - 2ax^2 - 8bx + a^2) / (4x^3 + 4ax + 4b)
    """
    x %= p
    a %= p
    b %= p
    num = (x**4 - 2*a*x**2 - 8*b*x + a*a) % p
    den = (4*x**3 + 4*a*x + 4*b) % p
    return (num * inv_mod(den, p)) % p

def x3_formula(x, a, b, p):
    """
    x(3P) = phi3(x)/(psi3(x)^2), with:
    phi3(x) = x^9
              - 12a x^7
              - 96b x^6
              + 30a^2 x^5
              - 24ab x^4
              + (36a^3 + 48b^2) x^3
              + 48a^2 b x^2
              + (9a^4 + 96ab^2) x
              + (8a^3 b + 64 b^3)
    den3(x) = 9x^8
              + 36a x^6
              + 72b x^5
              + 30a^2 x^4
              + 144ab x^3
              + (-12a^3 + 144b^2) x^2
              - 24a^2 b x
              + a^4
    """
    x %= p
    a %= p
    b %= p

    # phi3 coefficients for x^9 ... x^0
    c_phi = [
        1,
        0,
        -12*a,
        -96*b,
        30*a*a,
        -24*a*b,
        36*a*a*a + 48*b*b,
        48*a*a*b,
        9*a**4 + 96*a*b*b,
        8*a**3*b + 64*b**3,
    ]
    # den3 coefficients for x^8 ... x^0
    c_den = [
        9,
        0,
        36*a,
        72*b,
        30*a*a,
        144*a*b,
        -12*a**3 + 144*b*b,
        -24*a*a*b,
        a**4,
    ]

    num = 0
    for c in c_phi:
        num = (num * x + c) % p
    den = 0
    for c in c_den:
        den = (den * x + c) % p

    return (num * inv_mod(den, p)) % p

def solve_for_Kp0_r(T2, T3):
    """
    Solve for X = x(Kp) and r in F_p using:
      x(2P) = x2(X), x(3P) = x3(X)
      T2 = x(2P) + r
      T3 = x(3P) + r
    Eliminate r:
      x2(X) - x3(X) = T2 - T3
    Build polynomial in X over GF(p) and find roots.
    """
    p = P_FIELD
    a = ACOEF % p
    b = BCOEF % p

    K = GF(p)
    R = PolynomialRing(K, ['X'])
    X = R.gen()

    aK = K(a)
    bK = K(b)

    # num2 = x^4 - 2 a x^2 - 8 b x + a^2
    num2 = X**4 - 2*aK*X**2 - 8*bK*X + aK**2
    # den2 = 4x^3 + 4 a x + 4 b
    den2 = 4*X**3 + 4*aK*X + 4*bK

    # phi3 and den3 polynomials with coeffs reduced mod p
    num3 = (X**9
            - 12*aK*X**7
            - 96*bK*X**6
            + 30*aK**2*X**5
            - 24*aK*bK*X**4
            + (36*aK**3 + 48*bK**2)*X**3
            + 48*aK**2*bK*X**2
            + (9*aK**4 + 96*aK*bK**2)*X
            + (8*aK**3*bK + 64*bK**3))

    den3 = (9*X**8
            + 36*aK*X**6
            + 72*bK*X**5
            + 30*aK**2*X**4
            + 144*aK*bK*X**3
            + (-12*aK**3 + 144*bK**2)*X**2
            - 24*aK**2*bK*X
            + aK**4)

    c = K((T2 - T3) % p)

    poly = num2*den3 - num3*den2 - c*den2*den3
    roots = poly.roots()

    if not roots:
        log.error("[!] No root for X found in GF(p)")
        return None, None

    for root, mult in roots:
        X0 = int(root)
        x2 = x2_formula(X0, a, b, p)
        r = (T2 - x2) % p
        x3 = x3_formula(X0, a, b, p)
        if (T3 - r) % p == x3:
            return X0, r

    log.error("[!] No (X,r) pair passed consistency check")
    return None, None

def decrypt_flag(Kp0, r, ct):
    ks = shake_128(str((Kp0, r)).encode()).digest(len(ct))
    flag = bytes(c ^ k for c, k in zip(ct, ks))
    log.success(f"FLAG (raw bytes): {flag}")
    try:
        log.success(f"FLAG (utf-8): {flag.decode()}")
    except Exception:
        pass

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "remote"

    if mode == "remote":
        io = remote(host=HOST, port=PORT, ssl=True, sni=HOST)
    else:
        io = remote(host=HOST, port=PORT, ssl=True, sni=HOST)

    Qx, Qy, d_masked = read_header(io)
    menu_to_prompt(io)

    log.info("[*] Collecting signatures ...")
    sigs = collect_signatures(io, num=12)

    d_candidate = None
    for i, j in combinations(range(len(sigs)), 2):
        log.info(f"[*] Trying pair ({i},{j}) ...")
        d = try_recover_d_from_pair(sigs[i], sigs[j], d_masked)
        if d is None:
            continue
        log.success(f"[+] candidate d from pair ({i},{j}): 0x{d:064x}")
        if verify_d_all_sigs(d, sigs):
            log.success("[+] d passes all sig checks!")
            d_candidate = d
            break
        else:
            log.warning("[!] d failed verification, trying next pair...")

    if d_candidate is None:
        log.error("[!] Failed to recover d from available pairs")
        io.close()
        return

    log.success(f"Recovered d = 0x{d_candidate:064x}")

    MK = derive_MK_from_d(d_candidate)
    log.success(f"MK = {MK.hex()}")

    log.info("[*] Fetching dataset rows ...")
    dataset_rows = get_dataset(io)
    log.success(f"Got {len(dataset_rows)} rows")

    log.info("[*] Fetching ciphertext ...")
    ct, ct_hex = get_ct(io)
    log.success(f"ct_hex = {ct_hex}")

    log.info("[*] Reconstructing t_i values (mobius^{-1} + beta) ...")
    t_by_a = reconstruct_t_values(MK, dataset_rows)

    T2 = majority_value(t_by_a[2])
    T3 = majority_value(t_by_a[3])
    T5 = majority_value(t_by_a[5])

    log.success(f"T2 = {T2}")
    log.success(f"T3 = {T3}")
    log.success(f"T5 = {T5}")

    Kp0, r = solve_for_Kp0_r(T2, T3)
    if Kp0 is None:
        log.error("[!] Failed to recover (Kp0, r)")
        io.close()
        return

    log.success(f"Kp0 = {Kp0}")
    log.success(f"r   = {r}")

    decrypt_flag(Kp0, r, ct)

    io.close()

if __name__ == "__main__":
    main()
