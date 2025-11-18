from sage.all import *
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

flag = open("flag.txt", "rb").read().strip()

p = getPrime(1024)
q = getPrime(1024)
N = (p**2) * q
phi = (p) * (p - 1) * (q - 1)

while True:
    x = randint(2, 255)
    z = randint(2, 255)
    if gcd(phi, x) != 1:
        continue
    y0 = (-z * inverse_mod(phi, x)) % x
    e = (phi * y0 + z) // x 
    if not (1 < e < phi):
        continue
    if gcd(e, phi) != 1:
        continue
    y = (e * x - z) // phi
    if (y % p) != 0 and (y % q) != 0:
        break

R = Zmod(N)
awokaowkao = os.urandom(256)
M = matrix(R, 16, 16, awokaowkao)
C = pow(M, e)

def get_iv(b, k):
    return bytes(b[i*k + (k - 1 - i)] for i in range(k))

key = awokaowkao[:16] + awokaowkao[16:32]
iv = get_iv(awokaowkao, 16)

m = int.from_bytes(flag, "big")
c_rsa = pow(m, e, N)
rsa_bytes = c_rsa.to_bytes((N.bit_length() + 7) // 8, "big")

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
ct = cipher.encrypt(pad(rsa_bytes, 16))

with open("output.txt", "w") as f:
    f.write(f"C = {C.list()}\n")
    f.write(f"ct = {ct!r}\n")
    f.write(f"N = {int(N)}\n")
    f.write(f"e = {int(e)}\n")