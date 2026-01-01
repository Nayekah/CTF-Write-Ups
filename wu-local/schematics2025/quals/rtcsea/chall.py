from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

KEY = os.urandom(16)

def encrypt(plaintext):
    cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128))
    return cipher.encrypt(plaintext)

with open("plaintext.txt", "rb") as f:
    known_plaintext = f.read().strip()

with open("flag.txt", "rb") as f:
    flag = f.read().strip()

flag_parts = [flag[i:i+4] for i in range(0, len(flag), 4)]

cipher_parts = [encrypt(part) for part in flag_parts]

cipher_test = encrypt(known_plaintext)

noise = [encrypt(os.urandom(len(flag_parts[0]))) for _ in range(3)]

import random
all_ct = cipher_parts + [cipher_test] + noise

with open("output.txt", "w") as out:
    for ct in all_ct:
        out.write(ct.hex() + "\n")
