from sage.all import *
import json, hashlib
from sage.modules.free_module_integer import IntegerLattice


# Directly taken from rbtree's LLL repository
# From https://oddcoder.com/LOL-34c3/, https://hackmd.io/@hakatashi/B1OM7HFVI
def Babai_CVP(mat, target):
    M = IntegerLattice(mat, lll_reduce=True).reduced_basis
    G = M.gram_schmidt()[0]
    diff = target
    for i in reversed(range(G.nrows())):
        diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
    return target - diff


def solve_cvp(mat, lb, ub, weight=None):
    num_var  = mat.nrows()
    num_ineq = mat.ncols()

    max_element = 0 
    for i in range(num_var):
        for j in range(num_ineq):
            max_element = max(max_element, abs(mat[i, j]))

    if weight is None:
        weight = num_ineq * max_element

    if len(lb) != num_ineq:
        print("Fail: len(lb) != num_ineq")
        return

    if len(ub) != num_ineq:
        print("Fail: len(ub) != num_ineq")
        return

    for i in range(num_ineq):
        if lb[i] > ub[i]:
            print("Fail: lb[i] > ub[i] at index", i)
            return

    max_diff = max([ub[i] - lb[i] for i in range(num_ineq)])
    applied_weights = []

    for i in range(num_ineq):
        ineq_weight = weight if lb[i] == ub[i] else max_diff // (ub[i] - lb[i])
        if ineq_weight == 0:
            ineq_weight = 1
        applied_weights.append(ineq_weight)
        for j in range(num_var):
            mat[j, i] *= ineq_weight
        lb[i] *= ineq_weight
        ub[i] *= ineq_weight

    target = vector([(lb[i] + ub[i]) // 2 for i in range(num_ineq)])
    result = Babai_CVP(mat, target)

    for i in range(num_ineq):
        if not (lb[i] <= result[i] <= ub[i]):
            print("Warning: inequality does not hold after solving at index", i)
            break
    
    return result, applied_weights

with open("output.txt","r") as f:
    data = json.load(f)

q  = data["q"]
A  = Matrix(ZZ, data["A"])
b_list = data["b"]
Bs = Matrix(ZZ, data["Bs"])
enc_flag = bytes.fromhex(data["enc_flag_hex"])

n = A.nrows()   # 40
m = A.ncols()   # 60
k = 12
F = GF(q)

A_F = Matrix(F, A)

X = Bs[k:, 0:k]
X_F = Matrix(F, X)

A_top_F = A_F[0:k, :]
A_bot_F = A_F[k:, :]
C_F = X_F * A_top_F + A_bot_F
C = Matrix(ZZ, C_F)

b_vec = vector(ZZ, b_list)

secret_len = n - k    # 28
num_e = m
num_t = m

num_vars  = num_z + num_e + num_t
num_eq    = m
num_ineq  = num_eq + num_z + num_e + num_t   # 60 + 28 + 60 + 60 = 208

M = matrix(ZZ, num_vars, num_ineq)
lb = [0]*num_ineq
ub = [0]*num_ineq

def idx_z(t): return t
def idx_e(j): return num_z + j
def idx_t(j): return num_z + num_e + j

for j in range(m):
    col = j
    for t in range(num_z):
        M[idx_z(t), col] = int(C[t, j])
    M[idx_e(j), col] = 1
    M[idx_t(j), col] = -q

    lb[col] = int(b_vec[j])
    ub[col] = int(b_vec[j])

for t in range(num_z):
    col = num_eq + t
    M[idx_z(t), col] = 1
    lb[col] = -1
    ub[col] = 1

base_e = num_eq + num_z
for j in range(m):
    col = base_e + j
    M[idx_e(j), col] = 1
    lb[col] = -1
    ub[col] = 1

T = 50
base_t = base_e + num_e    # 60 + 28 + 60 = 148
for j in range(m):
    col = base_t + j
    M[idx_t(j), col] = 1
    lb[col] = -T
    ub[col] = T

print("[*] Matrix size: vars =", num_vars, ", ineqs =", num_ineq)
print("[*] Solving CVP... this may take a bit")

res, applied_weights = solve_cvp(M, lb, ub)
print("[*] CVP done")

z2 = []
for t in range(num_z):
    col = num_eq + t
    val = ZZ(res[col]) // applied_weights[col]
    z2.append(int(val))

e_vals = []
for j in range(m):
    col = base_e + j
    val = ZZ(res[col]) // applied_weights[col]
    e_vals.append(int(val))

t_vals = []
for j in range(m):
    col = base_t + j
    val = ZZ(res[col]) // applied_weights[col]
    t_vals.append(int(val))

print("[*] z2 (first 10 entries):", z2[:10])

ok = True
for t in range(num_z):
    if not (-1 <= z2[t] <= 1):
        print("z2 out of bound at", t, ":", z2[t])
        ok = False

for j in range(m):
    if not (-1 <= e_vals[j] <= 1):
        print("e out of bound at", j, ":", e_vals[j])
        ok = False
    if not (-T <= t_vals[j] <= T):
        print("t out of bound at", j, ":", t_vals[j])
        ok = False

if ok:
    print("[*] All bounds satisfied")

for j in range(m):
    lhs = sum(z2[t]*C[t,j] for t in range(num_z)) + e_vals[j] - q*t_vals[j]
    if lhs != b_vec[j]:
        print("Equation mismatch at col", j, ": lhs=", lhs, "rhs=", b_vec[j])
        ok = False
        break

if not ok:
    print("[!] Something went wrong in solving.")
else:
    print("[*] All equations satisfied, secret z2 recovered.")

Fq = GF(q)

z2_F = vector(Fq, [ZZ(v) % q for v in z2])

s2_F = z2_F

X_F = Matrix(Fq, X)
s1_F = z2_F * X_F

s_F  = vector(Fq, list(s1_F) + list(s2_F))

s_ints = [int(x) for x in s_F]
print("[*] s (first 10 entries):", s_ints[:10])

key_bytes = hashlib.sha256(
    b"".join(int(v).to_bytes(2, "little", signed=False) for v in s_ints)
).digest()

flag = bytes(c ^ key_bytes[i % len(key_bytes)] for i, c in enumerate(enc_flag))
print("[+] Flag:", flag)