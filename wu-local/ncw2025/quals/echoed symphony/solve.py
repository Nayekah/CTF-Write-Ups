#!/usr/bin/env python3
import base64
import hashlib
import re
from collections import defaultdict

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

N  = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

def H(m: bytes) -> int:
    return int.from_bytes(hashlib.sha256(m + b"67").digest(), "big") % N

def inv(a: int) -> int:
    return pow(a % N, -1, N)

def msg_for_i(i: int) -> bytes:
    return f"log-{i:04d}: event stream entry #{i}".encode()

rec_re = re.compile(r"^Record\s+([0-9a-fA-F]+)\s+\[([0-9a-fA-F]+),\s*([0-9a-fA-F]+),\s*([0-9a-fA-F]+)\]\s*$")
enc_re = re.compile(r"^encrypted_flag\s*=\s*([0-9a-fA-F]+)\s*$")

def main():
    with open("output.txt", "r", encoding="utf-8", errors="ignore") as f:
        lines = [ln.strip() for ln in f if ln.strip() and ln.strip() != "."]

    records = []
    enc_hex = None

    for ln in lines:
        m = rec_re.match(ln)
        if m:
            tag_hex, sha_hex, r_hex, s_hex = m.groups()
            tag_ascii = bytes.fromhex(tag_hex).decode()
            i = int(base64.b64decode(tag_ascii))
            sha_given = int(sha_hex, 16)

            msg = msg_for_i(i)
            sha_check = int(hashlib.sha256(msg).hexdigest(), 16)
            if sha_check != sha_given:
                raise ValueError(f"msg format mismatch at i={i}")

            r = int(r_hex, 16) % N
            s = int(s_hex, 16) % N
            z = H(msg)
            records.append((i, r, s, z))
            continue

        m = enc_re.match(ln)
        if m:
            enc_hex = m.group(1).lower()

    if enc_hex is None:
        raise ValueError("encrypted_flag not found")

    by_r = defaultdict(list)
    for i, r, s, z in records:
        by_r[r].append((i, s, z))

    dup = [(r, lst) for r, lst in by_r.items() if len(lst) >= 2]
    if not dup:
        raise ValueError("no duplicated r found")

    r, lst = dup[0]
    (i1, s1, z1), (i2, s2, z2) = lst[0], lst[1]

    k = ((z1 - z2) * inv(s1 - s2)) % N
    d = ((s1 * k - z1) * inv(r)) % N

    key = hashlib.sha256(d.to_bytes(32, "big")).digest()
    ct = bytes.fromhex(enc_hex)
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    try:
        pt = unpad(pt, 16)
    except ValueError:
        pass

    print("dup indices:", i1, i2)
    print("d =", hex(d))
    print("flag =", pt.decode(errors="replace"))

if __name__ == "__main__":
    main()