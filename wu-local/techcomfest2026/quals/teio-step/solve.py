#!/usr/bin/env python3
import socket
import time

HOST = "techcomfest.1pc.tf"
PORT = 8301

MASK32 = 0xFFFFFFFF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF
MATRIX_A   = 0x9908B0DF
N = 624
M = 397

def int32(x: int) -> int:
    return x & MASK32

def temper(y: int) -> int:
    y &= MASK32
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= (y >> 18)
    return y & MASK32

def undo_right(y: int, shift: int) -> int:
    x = y
    for _ in range(5):
        x = y ^ (x >> shift)
    return x & MASK32

def undo_left(y: int, shift: int, mask: int) -> int:
    x = y
    for _ in range(5):
        x = y ^ ((x << shift) & mask)
    return x & MASK32

def untemper(y: int) -> int:
    y &= MASK32
    y = undo_right(y, 18)
    y = undo_left(y, 15, 0xEFC60000)
    y = undo_left(y, 7,  0x9D2C5680)
    y = undo_right(y, 11)
    return y & MASK32

def twist(state):
    for i in range(N):
        y = (state[i] & UPPER_MASK) | (state[(i + 1) % N] & LOWER_MASK)
        state[i] = int32(state[(i + M) % N] ^ (y >> 1) ^ (MATRIX_A if (y & 1) else 0))
    return state

def calc(si: int, si1: int, sim: int) -> int:
    y = (si & UPPER_MASK) | (si1 & LOWER_MASK)
    return int32(sim ^ (y >> 1) ^ (MATRIX_A if (y & 1) else 0))

def s2n(bs: bytes) -> int:
    return int.from_bytes(bs, "big")

THRESH = s2n(b"bakushinbakushin") % 175433

class Remote:
    def __init__(self, host: str, port: int, timeout: float = 3.5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.s = None
        self.buf = b""

    def connect(self):
        self.s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.s.settimeout(self.timeout)

    def close(self):
        try:
            if self.s:
                self.s.close()
        finally:
            self.s = None
            self.buf = b""

    def _recv_some(self) -> bytes:
        chunk = self.s.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        return chunk

    def recvuntil(self, token: bytes) -> bytes:
        while token not in self.buf:
            self.buf += self._recv_some()
        i = self.buf.index(token) + len(token)
        out = self.buf[:i]
        self.buf = self.buf[i:]
        return out

    def recvline(self) -> bytes:
        while b"\n" not in self.buf:
            self.buf += self._recv_some()
        i = self.buf.index(b"\n") + 1
        out = self.buf[:i]
        self.buf = self.buf[i:]
        return out

    def sendline(self, data: bytes):
        self.s.sendall(data + b"\n")

def solve_once():
    r = Remote(HOST, PORT)
    r.connect()

    used = set()

    r.recvuntil(b">> ")

    nums = []
    send_num = 0

    for _ in range(623):
        if send_num in used:
            raise RuntimeError("local duplicate would occur")
        used.add(send_num)

        r.sendline(str(send_num).encode())

        line = r.recvline().strip()
        while True:
            try:
                out = int(line)
                break
            except ValueError:
                line = r.recvline().strip()

        nums.append(untemper(out))
        send_num = out

        r.recvuntil(b">> ")

    wack_last = calc(0, nums[0], nums[396])
    nums.append(wack_last)

    tw = nums.copy()
    twist(tw)

    idx1 = 622 - 397
    idx2 = 622 - 1
    idx3 = 622
    idx4 = (idx1 - 397) % 624

    lhs = 0
    for i in [idx1, idx2, idx3, idx4, 623]:
        lhs ^= tw[i]
    lhs &= MASK32

    def predict_sta_from_i(i_untempered: int) -> int:
        calc1 = calc(nums[idx1], nums[idx1 + 1], i_untempered)
        calc2 = calc(nums[idx2], i_untempered, tw[(idx2 + 397) % 624])
        calc3 = calc(i_untempered, nums[idx3 + 1], tw[(idx3 + 397) % 624])
        calc4 = calc(nums[idx4], nums[idx4 + 1], calc1)
        rhs = nums[-1] ^ calc1 ^ calc2 ^ calc3 ^ calc4
        return int32(lhs ^ rhs)

    ans = None
    best_i = 0
    best_val = 1 << 33

    for a in range(2):
        for b in range(2):
            mini = 0
            i0 = a | (b << 1) | mini
            minv = predict_sta_from_i(i0)
            chosen = i0

            for bit in range(2, 32):
                cand = a | (b << 1) | (1 << bit) | mini
                v = predict_sta_from_i(cand)
                if v < minv:
                    mini = cand
                    minv = v
                    chosen = cand
                if v == 0:
                    ans = cand
                    break

            if ans is None and minv < best_val:
                best_val = minv
                best_i = chosen

            if ans is not None:
                break
        if ans is not None:
            break

    if ans is None:
        ans = best_i

    final_send = temper(ans)

    if final_send in used:
        raise RuntimeError("final input would duplicate")
    used.add(final_send)

    r.sendline(str(final_send).encode())

    out = []
    try:
        while True:
            out.append(r.recvline())
    except Exception:
        pass

    r.close()
    return b"".join(out)

def main():
    print(f"[+] threshold: abs(sta) < {THRESH}")
    print(f"[+] target: {HOST}:{PORT}")

    attempt = 0
    while True:
        attempt += 1
        try:
            blob = solve_once()
            txt = blob.decode(errors="ignore")
            print(f"\n=== attempt {attempt} ===")
            print(txt)

            if "TCF{" in txt:
                print("[+] done.")
                break
        except KeyboardInterrupt:
            print("\n[!] stopped.")
            break
        except Exception as e:
            print(f"[!] attempt {attempt} failed early: {e}")
            time.sleep(0.05)

if __name__ == "__main__":
    main()