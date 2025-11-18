from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import re, ast
from subprocess import check_output
from re import findall

def parse_output(path="output.txt"):
    data = open(path, "r").read()

    C_match = re.search(r"C\s*=\s*(\[[^\]]*\])", data, re.S)
    if not C_match:
        raise ValueError("Cannot find C = [...] in output file")
    C_list = ast.literal_eval(C_match.group(1))

    ct_match = re.search(r"ct\s*=\s*(b([\'\"]).*?\2)", data, re.S)
    if not ct_match:
        raise ValueError("Cannot find ct = b'...' in output file")
    ct = ast.literal_eval(ct_match.group(1))

    N_match = re.search(r"N\s*=\s*(\d+)", data)
    e_match = re.search(r"e\s*=\s*(\d+)", data)
    if not (N_match and e_match):
        raise ValueError("Cannot find N or e in output file")

    N = Integer(N_match.group(1))
    e = Integer(e_match.group(1))

    return C_list, ct, N, e

def factor_from_ex_relation(N, e, xmax=512, zmax=512):
    N = Integer(N)
    e = Integer(e)

    print(f"[*] Brute forcing x,z in [2..{xmax}], [2..{zmax}] ...")
    for x in range(2, xmax+1):
        for z in range(2, zmax+1):
            k = e*x - z
            g = gcd(k, N)
            if 1 < g < N:
                print(f"[+] Nontrivial gcd found: gcd(e*{x} - {z}, N) = g (bits={g.nbits()})")
                p = g
                q = N // (p*p)
                return p, q, x, z

    raise ValueError("Failed to factor N via (e*x - z, N) gcd trick")

def gaussian_elimination_mod_composite(A):
    R = A.base_ring()
    n = R.cardinality()
    M = Matrix(R, A)

    nrows, ncols = M.nrows(), M.ncols()
    pivot_row = 0
    for j in range(ncols):
        if pivot_row >= nrows:
            break

        pivot_candidate_row = -1
        for i in range(pivot_row, nrows):
            if M[i, j] != 0:
                pivot_candidate_row = i
                break
        if pivot_candidate_row == -1:
            continue

        M.swap_rows(pivot_row, pivot_candidate_row)
        pivot_val = M[pivot_row, j]

        g, inv, _ = xgcd(Integer(pivot_val), n)
        M.rescale_row(pivot_row, R(inv))

        for i in range(nrows):
            if i != pivot_row:
                M.add_multiple_of_row(i, pivot_row, -M[i, j])

        pivot_row += 1

    return M

def flatter(M):
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    nums = list(map(int, findall(b"-?\\d+", ret)))
    return matrix(ZZ, M.nrows(), M.ncols(), nums)

def recover_basis(C_list, N, k=16):
    print("[*] Reconstructing M...")
    R = Zmod(N)
    C = Matrix(R, k, k, C_list)

    nvar = k * k  # 256

    L = Matrix(R, nvar, nvar)
    for i in range(k):
        for j in range(k):
            row = i * k + j
            for t in range(k):
                col1 = i * k + t       # X[i,t]
                col2 = j + k * t       # X[t,j]
                L[row, col1] += C[t, j]
                L[row, col2] -= C[i, t]

    L = gaussian_elimination_mod_composite(L)

    L = L[:(nvar - k), :].T
    L = Matrix(R, L)

    M1 = L[:k, :]      # 16 x (k^2 - k)
    M2 = L[k:, :]      # (k^2 - 2k) x (k^2 - k)

    T = M1 * M2.inverse()  # 16 x (k^2 - 2k)

    # Angkat ke ZZ
    T_int = Matrix(ZZ, [[int(x) for x in row] for row in T.rows()])
    krows = T_int.nrows()    # 16
    mcols = T_int.ncols()    # something ~240

    top_left     = identity_matrix(ZZ, krows)
    top_right    = T_int
    bottom_left  = zero_matrix(ZZ, mcols, krows)
    bottom_right = N * identity_matrix(ZZ, mcols)

    M_lattice = block_matrix(ZZ, [
        [top_left,    top_right],
        [bottom_left, bottom_right],
    ])

    M_red = flatter(M_lattice)

    v = vector(ZZ, M_red[0])
    w = vector(ZZ, M_red[1])

    return v, w

def get_iv(b, k):
    return bytes(b[i*k + (k - 1 - i)] for i in range(k))

def main():
    C_list, ct, N, e = parse_output("output.txt")
    print("[*] Parsed N, e, ct, C_list from output.txt")
    print(f"    N bits = {N.nbits()}, e bits = {e.nbits()}")

    p, q, x, z = factor_from_ex_relation(N, e)
    print(f"    (x, z) = ({x}, {z})")
    print(f"[+] p bits = {p.nbits()}, q bits = {q.nbits()}")

    phi = p * (p - 1) * (q - 1)
    d = inverse_mod(e, phi)
    print(f"[+] phi bits = {phi.nbits()}")
    print(f"[+] d bits   = {d.nbits()}")

    v, w = recover_basis(C_list, N, k=16)

    print("[*] Searching alpha for valid AES padding ...")
    awoka = None

    for alpha in range(-2048, 2049):
        cand_vec = alpha * v + w
        cand = [abs(int(x)) for x in cand_vec]

        if len(cand) != 16*16:
            continue
        if not all(0 <= b < 256 for b in cand):
            continue

        awoka_candidate = bytes(cand)

        key_bytes = awoka_candidate[:16] + awoka_candidate[16:32]
        iv_bytes  = get_iv(awoka_candidate, 16)

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
        rsa_padded = cipher.decrypt(ct)

        try:
            rsa_bytes = unpad(rsa_padded, 16)
        except ValueError:
            continue

        print(f"[+] Found alpha = {alpha} with correct AES padding")
        awoka = awoka_candidate
        break

    if awoka is None:
        raise ValueError("Failed to find valid awoka via AES padding check")

    print(f"[*] awoka length = {len(awoka)} bytes")

    c_rsa = Integer(int.from_bytes(rsa_bytes, "big"))

    m = pow(c_rsa, d, N)
    flag = long_to_bytes(int(m)).lstrip(b"\x00")

    print("[+] FLAG:", flag)

if __name__ == "__main__":
    main()
