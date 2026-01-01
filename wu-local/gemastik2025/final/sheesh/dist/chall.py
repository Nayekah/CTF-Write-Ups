#!/usr/bin/env python3

import os, sys, signal, binascii, random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes

random.seed(os.urandom(16))
K0 = os.urandom(16)
K1 = os.urandom(16)
S0 = os.urandom(16)
S1 = os.urandom(16)
M0 = os.urandom(16)
M1 = os.urandom(16)

with open("./flag.txt","rb") as f:
    flag = f.read()

def hex_input(q):
    s = input(q).strip()
    try:    return binascii.unhexlify(s)
    except: print("err"); return None

def enc1(b16: bytes) -> bytes:
    x = AES.new(K1, AES.MODE_ECB).encrypt(b16)
    return bytes(a ^ b for a, b in zip(x, b16))

def enc2(iv: bytes, m: bytes) -> bytes:
    return AES.new(K0, AES.MODE_CBC, iv=iv).encrypt(pad(m, 16))

def enc3(m: bytes) -> bytes:
    return AES.new(K1, AES.MODE_CBC, iv=b"\x00"*16).encrypt(pad(m, 16))[-16:]

def T(iv: bytes, ct: bytes):
    n = len(ct)
    if n < 96 or (n & 15): 
        return None
    v = memoryview(ct)
    W = [bytes(v[i:i+16]) for i in range(0, n, 16)]
    m = len(W)

    r = ((iv[0] & 7) + 2) % m
    if r:
        W = W[r:] + W[:r]

    j = 1 + (W[0][0] & 1)
    if len(W) <= j:
        return None
    del W[j]
    if len(W) < 2:
        return None

    a0 = long_to_bytes(bytes_to_long(W[0]) ^ bytes_to_long(M0))
    a1 = long_to_bytes(bytes_to_long(W[1]) ^ bytes_to_long(M1))
    return b"".join((S0, a0, S1, a1, *W[2:]))

def C(iv: bytes, ct: bytes) -> bool:
    z = T(iv, ct)
    if z is None:
        ok = False
    else:
        try:
            x = AES.new(K0, AES.MODE_CBC, iv=iv).decrypt(z)
            unpad(x, 16)
            ok = True
        except:
            ok = False
    if random.random() < 0.08:
        ok = not ok
    return ok

iv = os.urandom(16)
MK = enc3(iv + iv)                   
H0 = (flag + b"\x00"*16)[:16]
H1 = bytes(a ^ b for a, b in zip(H0, MK))
pt = H1 + flag[16:]
ct = enc2(iv, pt)

print("iv:", iv.hex())
print("ct:", ct.hex())
print()

while True:
    try:
        blob = hex_input("blob: ")
        if blob is None:
            print("err\n"); continue
        L = len(blob)
        if L == 16:
            y = enc1(blob)
            print("blk:", y.hex()); print()
        elif L >= 32 and (L % 16) == 0:
            iv, ct = blob[:16], blob[16:]
            print("ok\n" if C(iv, ct) else "no\n")
        else:
            print("err\n")
    except EOFError:
        break