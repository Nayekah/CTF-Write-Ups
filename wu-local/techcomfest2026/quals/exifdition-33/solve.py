#!/usr/bin/env python3
import itertools
import multiprocessing as mp
import re
import socket
from typing import Optional, Tuple, List

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.strxor import strxor

HOST = "techcomfest.1pc.tf"
PORT = 8303

SEED = b"GOLDSHIP"
HEX_RE = re.compile(rb"^[0-9a-fA-F]+$")

SECOND_KEY = "ExifToolVersion"

class Remote:
    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

    def recv_until(self, token: bytes) -> bytes:
        while token not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        idx = self.buf.index(token) + len(token)
        out, self.buf = self.buf[:idx], self.buf[idx:]
        return out

    def recv_line(self) -> bytes:
        while b"\n" not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        idx = self.buf.index(b"\n") + 1
        out, self.buf = self.buf[:idx], self.buf[idx:]
        return out

    def send_line(self, line: bytes):
        self.s.sendall(line + b"\n")


def get_ciphertexts() -> Tuple[bytes, bytes]:
    r = Remote(HOST, PORT)

    r.recv_until(b"?> ")
    r.send_line(b"2")
    r.recv_until(b"Command: ")
    r.send_line(b"-j")

    ct_img = None
    for _ in range(500):
        line = r.recv_line().strip()
        if line and HEX_RE.match(line):
            ct_img = bytes.fromhex(line.decode())
            break
    if ct_img is None:
        r.close()
        raise RuntimeError("Failed to read ciphertext for images.jpg")

    r.recv_until(b"?> ")
    r.send_line(b"1")

    ct_flag = None
    for _ in range(500):
        line = r.recv_line().strip()
        if line and HEX_RE.match(line):
            ct_flag = bytes.fromhex(line.decode())
            break
    if ct_flag is None:
        r.close()
        raise RuntimeError("Failed to read ciphertext for flag.png")

    r.close()
    return ct_img, ct_flag

def blocks2(ct: bytes) -> Tuple[bytes, bytes]:
    if len(ct) < 32 or (len(ct) % 16) != 0:
        raise ValueError(f"bad ct length: {len(ct)}")
    return ct[:16], ct[16:32]

def make_P1P2(fname: str) -> Tuple[bytes, bytes]:
    prefix = f"[{{'SourceFile': '{fname}', '{SECOND_KEY}': "
    b = prefix.encode("ascii")
    if len(b) < 32:
        b += b" " * (32 - len(b))
    return b[:16], b[16:32]

def gen_candidates() -> Tuple[List[bytes], set]:
    cands = []
    for p in itertools.permutations(SEED):
        b8 = bytes(p)
        cands.append(b8 + b8)
    return cands, set(cands)

def decrypt_double_cbc(ct: bytes, k1: bytes, iv1: bytes, k2: bytes, iv2: bytes) -> bytes:
    layer1 = AES.new(k2, AES.MODE_CBC, iv=iv2).decrypt(ct)
    pt_padded = AES.new(k1, AES.MODE_CBC, iv=iv1).decrypt(layer1)
    return unpad(pt_padded, 16)

def worker_k2_range(args):
    (start, end, cands, cand_set, C1i, C2i, C1f, C2f, P1i, P2i, P1f, P2f) = args

    aes1_list = [AES.new(k1, AES.MODE_ECB) for k1 in cands]

    for idx in range(start, end):
        k2 = cands[idx]
        aes2 = AES.new(k2, AES.MODE_ECB)

        I2i = strxor(aes2.decrypt(C2i), C1i)
        I2f = strxor(aes2.decrypt(C2f), C1f)

        D1i = aes2.decrypt(C1i)
        D1f = aes2.decrypt(C1f)

        for j, aes1 in enumerate(aes1_list):
            I1i = strxor(aes1.decrypt(I2i), P2i)

            iv2 = strxor(D1i, I1i)
            if iv2 not in cand_set:
                continue

            I1f = strxor(aes1.decrypt(I2f), P2f)
            if strxor(D1f, I1f) != iv2:
                continue

            iv1 = strxor(P1i, aes1.decrypt(I1i))
            if iv1 not in cand_set:
                continue
            if strxor(P1f, aes1.decrypt(I1f)) != iv1:
                continue

            k1 = cands[j]
            return (k1, iv1, k2, iv2)

    return None


def recover_keys(ct_img: bytes, ct_flag: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    cands, cand_set = gen_candidates()
    C1i, C2i = blocks2(ct_img)
    C1f, C2f = blocks2(ct_flag)

    P1i, P2i = make_P1P2("images.jpg")
    P1f, P2f = make_P1P2("flag.png")

    n = len(cands)
    cpu = max(1, mp.cpu_count() - 1)
    chunk = (n + cpu - 1) // cpu

    tasks = []
    for i in range(cpu):
        start = i * chunk
        end = min(n, (i + 1) * chunk)
        if start < end:
            tasks.append((start, end, cands, cand_set, C1i, C2i, C1f, C2f, P1i, P2i, P1f, P2f))

    with mp.Pool(processes=cpu) as pool:
        for res in pool.imap_unordered(worker_k2_range, tasks, chunksize=1):
            if res is not None:
                pool.terminate()
                pool.join()
                return res

    raise RuntimeError("Key recovery failed (unexpected if prefix is correct).")

def main():
    ct_img, ct_flag = get_ciphertexts()
    print(f"[+] got ct_img={len(ct_img)} bytes, ct_flag={len(ct_flag)} bytes")

    k1, iv1, k2, iv2 = recover_keys(ct_img, ct_flag)
    print(f"[+] k1={k1.hex()}  iv1={iv1.hex()}")
    print(f"[+] k2={k2.hex()}  iv2={iv2.hex()}")

    pt = decrypt_double_cbc(ct_flag, k1, iv1, k2, iv2)
    s = pt.decode("utf-8", errors="replace")
    print("[+] decrypted (head):")
    print(s[:500])

    m = re.search(r"[A-Za-z0-9_]+?\{[^}]+\}", s)
    if m:
        print("[+] FLAG:", m.group(0))

if __name__ == "__main__":
    main()