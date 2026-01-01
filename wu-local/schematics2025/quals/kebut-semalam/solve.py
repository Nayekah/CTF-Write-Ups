from pwn import remote
from z3 import BitVec, BitVecVal, ZeroExt, Solver, And, LShR, sat
from binascii import crc32 as py_crc32

HOST, PORT = "103.185.52.103", 3004
MAX_AHEAD = 4096

U, D = 11, 0xFFFFFFFF
S, B = 7,  0x9D2C5680
T, C = 15, 0xEFC60000
L = 18

def _undo_right(y, shift):
    x = 0
    for _ in range(5):
        x = y ^ (x >> shift)
    return x & 0xFFFFFFFF

def _undo_left_and(y, shift, mask):
    x = 0
    for _ in range(5):
        x = y ^ ((x << shift) & mask)
    return x & 0xFFFFFFFF

def untemper(y):
    y &= 0xFFFFFFFF
    y = _undo_right(y, L)
    y = _undo_left_and(y, T, C)
    y = _undo_left_and(y, S, B)
    y = _undo_right(y, U)
    return y

class MTClone:
    def __init__(self):
        self.state = [0]*624
        self.index = 624
    def absorb(self, outs):
        self.state = [untemper(o) for o in outs[:624]]
        self.index = 624
    def twist(self):
        N, M, A = 624, 397, 0x9908B0DF
        UPPER, LOWER = 0x80000000, 0x7FFFFFFF
        for i in range(N):
            x = (self.state[i] & UPPER) | (self.state[(i+1) % N] & LOWER)
            xA = (x >> 1) ^ (A if (x & 1) else 0)
            self.state[i] = self.state[(i+M) % N] ^ xA
        self.index = 0
    def rand32(self):
        if self.index >= 624:
            self.twist()
        y = self.state[self.index]; self.index += 1
        y ^= (y >> U) & D
        y ^= (y << S) & B
        y ^= (y << T) & C
        y ^= (y >> L)
        return y & 0xFFFFFFFF

CRC_POLY = 0xEDB88320

def z3_crc32(bytes_sym):
    reg = BitVecVal(0xFFFFFFFF, 32)
    for b in bytes_sym:
        reg = reg ^ ZeroExt(24, b)
        for _ in range(8):
            reg = LShR(reg, 1) ^ ((reg & BitVecVal(1,32)) * BitVecVal(CRC_POLY,32))
    return reg ^ BitVecVal(0xFFFFFFFF, 32)

def solve_team_for_crc_hex(target_hex):
    target = int(target_hex, 16)
    def char_ok(b):
        return And(b >= 0x20, b <= 0x7e, b != 0x2d)
    for n in range(1, 6):
        for dash_pos in range(n):
            s = Solver()
            bs = [BitVec(f"b{i}", 8) for i in range(n)]
            for i, b in enumerate(bs):
                s.add(b == 0x2d if i == dash_pos else char_ok(b))
            s.add(z3_crc32(bs) == BitVecVal(target, 32))
            if s.check() == sat:
                m = s.model()
                team = bytes(int(m[b].as_long()) for b in bs)
                if team.count(b'-') == 1 and hex(py_crc32(team) & 0xFFFFFFFF)[2:] == target_hex:
                    return team
    return None

def get_ticket(io, team_bytes):
    io.sendline(b"G")
    io.recvuntil(b"Your team name: ")
    io.sendline(team_bytes)
    io.recvuntil(b"Your encrypted ticket is: ")
    pkt_hex = io.recvline().decode().strip()
    io.recvuntil(b"Team OTP:")
    otp_line = io.recvline().decode().strip()
    otp_hex = otp_line.split()[-1]
    return pkt_hex, otp_hex

def send_insert(io, pkt_hex):
    io.sendline(b"I")
    io.recvuntil(b"Your encrypted ticket (hex): ")
    io.sendline(pkt_hex.encode())

def main():
    io = remote(HOST, PORT)

    outs = []
    for _ in range(624):
        _, otp_hex = get_ticket(io, b"a")
        outs.append(int(otp_hex, 16))
    mt = MTClone()
    mt.absorb(outs)

    r = []
    for _ in range(MAX_AHEAD+1):
        r.append(mt.rand32())
    r_hex = [format(x, 'x') for x in r]

    chosen = None
    for k in range(1, MAX_AHEAD):
        target_hex = r_hex[k]
        team = solve_team_for_crc_hex(target_hex)
        if team:
            chosen = (k, r_hex[k-1], target_hex, team)
            break
    if not chosen:
        print(f"[!] No ≤5-char team found for any r_(k+1) in next {MAX_AHEAD}. Increase MAX_AHEAD.")
        return

    k, rk_hex, rkp1_hex, team = chosen

    for _ in range(k-1):
        get_ticket(io, b"a")

    pkt_hex, printed = get_ticket(io, team)

    send_insert(io, pkt_hex)
    io.interactive()

if __name__ == "__main__":
    main()
