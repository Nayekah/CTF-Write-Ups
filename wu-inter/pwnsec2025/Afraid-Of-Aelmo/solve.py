from sage.all import Integer, crt
from pwn import remote
import re
import os
import sys

path = os.path.dirname(os.path.realpath(__file__))
if sys.path[1] != path:
    sys.path.insert(1, path)

# https://github.com/jvdsn/crypto-attacks
from attacks.hnp.lattice_attack import attack as hnp_attack

HOST = "2451d6d066ce339f.chal.ctf.ae"
PORT = 443

B = 1 << 200  # r = randbelow(1 << 200)


def hnp_for_one_q():
    io = remote(host=HOST, port=PORT, ssl=True, sni=HOST)

    data = io.recvuntil(b"hint:").decode()
    hint_line = io.recvline().decode().strip()

    p = int(re.search(r"\np = (\d+)", data).group(1))
    q = Integer(int(re.search(r"\nq = (\d+)", data).group(1)))
    g = int(re.search(r"\ng = (\d+)", data).group(1))
    y = int(re.search(r"\ny = (\d+)", data).group(1))
    bitlen = int(re.search(r"(\d+)", hint_line).group(1))

    print(f"[*] hint bit_length = {bitlen}")
    print(f"[*] q bits = {q.nbits()}")

    es = []
    zs = []

    for _ in range(6):
        io.recvuntil(b"Select an option > ")
        io.sendline(b"1")
        io.recvline()
        proofline = io.recvline().decode().strip()
        m = re.search(r"\{.*\}", proofline)
        if not m:
            break
        d = eval(m.group(0))
        es.append(Integer(d["e"]))
        zs.append(Integer(d["z"]))

    io.close()
    print(f"[*] collected {len(es)} samples for this q")

    if len(es) < 2:
        print("[!] too few samples, skipping this q")
        return None

    # HNP mapping:
    #   z_i ≡ r_i + w*e_i (mod q)
    #   => e_i*w - z_i ≡ -r_i (mod q), |r_i| < B
    a = [[int(e % q)] for e in es]        # a_i
    b = [int((-z) % q) for z in zs]       # b_i
    m_mod = int(q)
    X = B

    w_mod_q = None
    print("[*] running HNP lattice_attack for this q...")
    for xs, ys in hnp_attack(a, b, m_mod, X):
        cand = Integer(ys[0])

        ok = True
        for e, z in zip(es, zs):
            x = (e * cand - z) % q   # ≡ -r_i mod q
            if x > q//2:             # balance [-q/2, q/2]
                x -= q
            if abs(x) >= B:
                ok = False
                break

        if ok:
            w_mod_q = cand
            break

    if w_mod_q is None:
        print("[!] HNP failed for this q, skip and try another connection")
        return None

    print(f"[+] HNP success: w mod q = {w_mod_q}")
    return q, w_mod_q, bitlen



def main():
    qs = []
    ws = []
    bitlen_hint = None

    TARGET_GOOD = 30

    while len(qs) < TARGET_GOOD:
        res = hnp_for_one_q()
        if res is None:
            continue

        q, wq, bitlen = res

        if bitlen_hint is None:
            bitlen_hint = bitlen

        if q in qs:
            print("[!] duplicate q, skip")
            continue

        qs.append(q)
        ws.append(wq)

        prod_q_bits = (qs[0].parent().prod(qs)).nbits()
        print(f"[+] collected {len(qs)} good congruences; log2(prod_q) ≈ {prod_q_bits}")

    print("[*] Running CRT over all q_i...")
    prod_q = qs[0].parent().prod(qs)
    w_crt = crt(ws, qs)
    print("[*] w_crt bit_length =", w_crt.nbits(), " (hint =", bitlen_hint, ")")

    M = prod_q
    w = w_crt
    if w.nbits() > bitlen_hint:
        w = w_crt - M
        print("[*] adjusted w by -prod_q; new bit_length =", w.nbits())

    if w.nbits() > bitlen_hint:
        print("[!] Something is wrong: w still larger than hint bit_length")
    else:
        print("[+] w bit_length looks consistent with hint")

    nbytes = (bitlen_hint + 7) // 8
    flag_bytes = int(w).to_bytes(nbytes, "big")

    print("[+] FLAG bytes (raw, first 200) =", flag_bytes[:200], b"...")
    try:
        s = flag_bytes.decode()
        print("[+] Full plaintext length:", len(s))

        idx = s.find("flag{")
        if idx == -1:
            print("[!] Not found")
            print(s[:500])
        else:
            end = s.find("}", idx)
            if end == -1:
                print("[!] flag{ found but no closing }")
                print(s[idx:idx+200])
            else:
                flag = s[idx:end+1]
                print("[+] FLAG =", flag)
    except UnicodeDecodeError:
        print("[!] Unicode error when decoding FLAG bytes")
        print(flag_bytes.hex()[:400], "...")

if __name__ == "__main__":
    main()
