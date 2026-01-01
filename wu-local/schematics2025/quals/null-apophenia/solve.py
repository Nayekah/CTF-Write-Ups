import ecdsa
import os, sys, re, random, hashlib
from binascii import hexlify
from sage.all import QQ, matrix
from pwn import remote

HOST, PORT = "103.185.52.103", 3003

n = ecdsa.curves.NIST384p.order

def shortest_vectors(B):
    B = B.LLL()
    for row in B.rows():
        if not row.is_zero():
            yield row

def attack(a, b, m, X):
    assert len(a) == len(b)
    n1 = len(a); n2 = len(a[0])
    B = matrix(QQ, n1 + n2 + 1, n1 + n2 + 1)
    for i in range(n1):
        for j in range(n2):
            B[n1 + j, i] = a[i][j]
        B[i, i] = m
        B[n1 + n2, i] = b[i] - X // 2
    for j in range(n2):
        B[n1 + j, n1 + j] = X / QQ(m)
    B[n1 + n2, n1 + n2] = X
    for v in shortest_vectors(B):
        xs = [int(v[i] + X // 2) for i in range(n1)]
        ys = [(int(v[n1 + j] * m) // X) % m for j in range(n2)]
        if all(y != 0 for y in ys) and v[n1 + n2] == X:
            yield xs, ys

class PartialIntegerLSB:
    def __init__(self, k_bitlen, lsb_value, lsb_bits):
        self.bit_length = int(k_bitlen)
        self._lsb_value = int(lsb_value)
        self._lsb_bits  = int(lsb_bits)
    def get_known_lsb(self):  return (self._lsb_value, self._lsb_bits)
    def get_unknown_msb(self): return max(self.bit_length - self._lsb_bits, 1)
    def sub(self, values):
        assert len(values) == 1
        u = int(values[0])
        return (self._lsb_value + (u << self._lsb_bits)) % n

def dsa_known_lsb(n, h_list, r_list, s_list, k_parts):
    assert len(h_list) == len(r_list) == len(s_list) == len(k_parts)
    a, b, X = [], [], 0
    for hi, ri, si, ki in zip(h_list, r_list, s_list, k_parts):
        lsb, t = ki.get_known_lsb()
        inv_shift = pow(2**t, -1, n)
        a.append([(inv_shift * pow(si, -1, n) * ri) % n])
        b.append((inv_shift * pow(si, -1, n) * hi - inv_shift * lsb) % n)
        X = max(X, 2**ki.get_unknown_msb())
    for k_unknowns, x_list in attack(a, b, n, X):
        nonces = [ki.sub([ku]) for ki, ku in zip(k_parts, k_unknowns)]
        yield x_list[0] % n, [K % n for K in nonces]

def ehash(r: int, m: bytes) -> int:
    return int(hashlib.sha256(str(r).encode() + m).hexdigest(), 16) % n

PAIR = re.compile(rb"\((\d+),\s*(\d+)\)")
VALID_PAT = re.compile(rb"\bvalid\b", re.I)

def wait_prompt(io): io.recvuntil(b">> ")

def do_sign(io, m: bytes):
    io.sendline(b"2")
    io.recvuntil(b"message in hex: ")
    io.sendline(hexlify(m))
    line = io.recvline().strip()
    m_ = PAIR.search(line)
    if not m_:
        line2 = io.recvline(timeout=0.5) or b""
        m_ = PAIR.search(line2)
        if not m_:
            return None
    return int(m_.group(1)), int(m_.group(2))

def do_verify(io, m: bytes, r: int, s: int):
    io.sendline(b"3")
    io.recvuntil(b"message in hex: ")
    io.sendline(hexlify(m))
    io.recvuntil(b"input r: ")
    io.sendline(str(r).encode())
    io.recvuntil(b"input s: ")
    io.sendline(str(s).encode())
    line = io.recvline(timeout=1.2) or b""
    return line

def do_flag(io, r: int, s: int):
    io.sendline(b"4")
    io.recvuntil(b"input r: ")
    io.sendline(str(r).encode())
    io.recvuntil(b"input s: ")
    io.sendline(str(s).encode())
    out = b""
    for _ in range(6):
        try: out += io.recvline(timeout=0.8)
        except Exception: break
    return out

def main():
    TARGET = '空に溶かせば　きらめく七色のRAINBOW, 見つめて　Believe in me, my mind'.encode('utf-8')
    Q = 1 << 14

    LSB_BITS = 14
    K_BITLEN = (n - 1).bit_length()

    SIGS = 38

    io = remote(HOST, PORT)
    wait_prompt(io)

    samples = []
    for _ in range(SIGS):
        m = os.urandom(24 + random.randint(0, 24))
        sig = do_sign(io, m)
        if sig is None:
            try: wait_prompt(io)
            except Exception: pass
            continue
        r, s = sig
        h = ehash(r, m)
        samples.append((h, r, s, m))
        wait_prompt(io)

    if len(samples) < 24:
        print("[!] Not enough samples.")
        io.close(); return

    H_all = [t[0] for t in samples]
    R_all = [t[1] for t in samples]
    S_all = [t[2] for t in samples]

    found_x = None
    found_k_all = None

    for _ in range(32):
        size = random.randint(min(24, len(samples)), min(32, len(samples)))
        idxs = sorted(random.sample(range(len(samples)), size))
        H = [H_all[i] for i in idxs]
        R = [R_all[i] for i in idxs]
        S = [S_all[i] for i in idxs]
        parts = [PartialIntegerLSB(K_BITLEN, 0, LSB_BITS) for _ in idxs]

        for x_cand, _Ks in dsa_known_lsb(n, H, R, S, parts):
            k_all = []
            ok = True
            invs_cache = {}
            for (h, r, s, _m) in samples:
                if s not in invs_cache:
                    invs_cache[s] = pow(s, -1, n)
                k_i = (invs_cache[s] * ((h + (x_cand * r) % n) % n)) % n
                k_all.append(k_i)
                if (k_i % Q) != 0:
                    ok = False
                    break
            if ok:
                found_x = x_cand % n
                found_k_all = k_all
                break
        if found_x is not None:
            break

    if found_x is None:
        print("[!] Could not find an x that makes all k_i multiples of 2^14.")
        io.close(); return

    r_i = R_all[0]
    k_i = found_k_all[0] or (n - 1)
    e_star = ehash(r_i, TARGET)
    s_star = (pow(k_i, -1, n) * ((e_star + (found_x * r_i) % n) % n)) % n

    line = do_verify(io, TARGET, r_i, s_star)
    sys.stdout.write(line.decode(errors="ignore"))
    wait_prompt(io)
    if VALID_PAT.search(line or b""):
        out = do_flag(io, r_i, s_star)
        sys.stdout.write(out.decode(errors="ignore"))
        io.close(); return

    tries = 2
    for j in range(1, min(1 + tries, len(samples))):
        r_i = R_all[j]
        k_i = found_k_all[j] or (n - 1)
        e_star = ehash(r_i, TARGET)
        s_star = (pow(k_i, -1, n) * ((e_star + (found_x * r_i) % n) % n)) % n
        line = do_verify(io, TARGET, r_i, s_star)
        sys.stdout.write(line.decode(errors="ignore"))
        if VALID_PAT.search(line or b""):
            out = do_flag(io, r_i, s_star)
            sys.stdout.write(out.decode(errors="ignore"))
            io.close(); return
        try: wait_prompt(io)
        except Exception: break

    print("[!] Verify failed even with mod-checked k's.")
    io.close()

if __name__ == "__main__":
    main()