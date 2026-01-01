from pwn import remote
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import inverse
import base64
import re
import sys

HOST = "103.185.52.103"
PORT = 3001

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def b64_to_int(s: str) -> int:
    return int.from_bytes(base64.b64decode(s), "big")

def int_nth_root(x: int, n: int) -> int:
    lo, hi = 0, 1
    while hi ** n <= x:
        hi <<= 1
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** n <= x:
            lo = mid + 1
        else:
            hi = mid
    return lo - 1

def pow_signed(base: int, exp: int, mod: int) -> int:
    if exp >= 0:
        return pow(base, exp, mod)
    inv = inverse(base % mod, mod)
    return pow(inv, -exp, mod)

def parse_sections(blob: str):
    pem_en = re.search(r"=== publickey_en\.pem ===\s+(-+BEGIN PUBLIC KEY-+[\s\S]*?-+END PUBLIC KEY-+)", blob).group(1)
    pem_si = re.search(r"=== publickey_si\.pem ===\s+(-+BEGIN PUBLIC KEY-+[\s\S]*?-+END PUBLIC KEY-+)", blob).group(1)
    c1_b64  = re.search(r"=== key_for_en\.enc ===\s+([A-Za-z0-9+/=]+)", blob).group(1)
    c2_b64  = re.search(r"=== key_for_si\.enc ===\s+([A-Za-z0-9+/=]+)", blob).group(1)
    flag_b64 = re.search(r"=== flag\.enc ===\s+([A-Za-z0-9+/=]+)", blob).group(1)
    return pem_en, pem_si, c1_b64, c2_b64, flag_b64

def get_blob_from_remote():
    io = remote(HOST, PORT)
    data = io.recvall(timeout=5)
    io.close()
    return data.decode(errors="ignore")

def solve_from_blob(blob: str):
    pem_en, pem_si, c1_b64, c2_b64, flag_b64 = parse_sections(blob)

    key_en = RSA.import_key(pem_en)
    key_si = RSA.import_key(pem_si)

    n = key_en.n
    assert key_en.n == key_si.n, "Moduli differ unexpectedly"

    e1 = key_en.e
    e2 = key_si.e

    d_common = __import__("math").gcd(e1, e2)
    e1p, e2p = e1 // d_common, e2 // d_common

    g, a, b = egcd(e1p, e2p)
    assert g == 1, "e1' and e2' are not coprime"

    c1 = b64_to_int(c1_b64)
    c2 = b64_to_int(c2_b64)

    m_pow_d = (pow_signed(c1, a, n) * pow_signed(c2, b, n)) % n

    m_int = int_nth_root(m_pow_d, d_common)
    assert (m_int ** d_common) == m_pow_d, "Failed to get exact d-th root"

    aes_key = m_int.to_bytes(16, "big")

    iv_ct = base64.b64decode(flag_b64)
    iv, ct = iv_ct[:16], iv_ct[16:]

    flag = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
    return flag.decode(errors="ignore")

def main():
    if sys.stdin.isatty():
        blob = get_blob_from_remote()
    else:
        blob = sys.stdin.read()

    try:
        flag = solve_from_blob(blob)
        print(flag)
    except Exception as e:
        print("[x] Failed:", e)

if __name__ == "__main__":
    main()
