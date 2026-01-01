#!/usr/bin/env python3
import math

N = 92226959634395542727305870286691824099
e = 65537
c = 81028662439340068660785564873246389821

a = math.isqrt(N + 1)
assert a * a == N + 1

p = a - 1
q = a + 1
print(f"p = {p}")
print(f"q = {q}")

phi = (p - 1) * (q - 1)

def egcd(a, b):
    if b == 0:
        return 1, 0, a
    x1, y1, g = egcd(b, a % b)
    return y1, x1 - (a // b) * y1, g

x, y, g = egcd(e, phi)
assert g == 1
d = x % phi

m0 = pow(c, d, N)
print(f"m0 (mod N) = {m0}")

prefix = b"NCW{"
total_len = 23

P = int.from_bytes(prefix, "big")
B = 256 ** (total_len - len(prefix))

low = P * B
high = (P + 1) * B

L = (low - m0 + N - 1) // N
U = (high - m0) // N

print(f"Searching k in range [{L}, {U}] (size = {U-L+1})")

flag_bytes = None
for k in range(L, U + 1):
    M = m0 + k * N
    b = M.to_bytes(total_len, "big")
    if not b.startswith(prefix):
        continue
    if all(32 <= x <= 126 for x in b):
        flag_bytes = b
        print(f"Found candidate k = {k}")
        print(f"Flag = {b}")
        break