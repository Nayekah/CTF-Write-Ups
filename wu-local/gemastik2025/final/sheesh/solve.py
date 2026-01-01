#!/usr/bin/env python3
from pwn import process, context, remote
import os, binascii
from Crypto.Util.Padding import unpad

context.log_level = "info"
BS = 16

def bxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def chunk16(b: bytes):
    return [b[i:i+16] for i in range(0, len(b), 16)]

class FastIO:
    def __init__(self, tube):
        self.t = tube
        self.buf = b""
        self._sync_to_prompt()

    def _recv_more(self, n=65536):
        c = self.t.recv(n)
        if not c:
            raise EOFError("process closed")
        self.buf += c

    def _sync_to_prompt(self):
        needle = b"blob: "
        while needle not in self.buf:
            self._recv_more()
        i = self.buf.rfind(needle)
        self.buf = self.buf[i + len(needle):]

    def _read_segments(self, need: int):
        out = []
        sep = b"\n\n"
        buf = self.buf
        recv_more = self._recv_more
        while len(out) < need:
            j = buf.find(sep)
            if j == -1:
                self.buf = buf
                recv_more()
                buf = self.buf
                continue
            out.append(buf[:j])
            buf = buf[j+2:]
        self.buf = buf
        self._sync_to_prompt()
        return out

    def send_lines_and_get_okno(self, hex_lines: list[bytes]) -> list[bool]:
        self.t.send(b"\n".join(hex_lines) + b"\n")
        segs = self._read_segments(len(hex_lines))
        res = []
        for seg in segs:
            s = seg.strip()
            last = s.split()[-1] if s else b"no"
            if last == b"ok":
                res.append(True)
            elif last == b"no":
                res.append(False)
            else:
                raise RuntimeError(f"unexpected oracle segment: {seg!r}")
        return res

    def send_line_and_get_blk(self, hex_line: bytes) -> bytes:
        self.t.send(hex_line + b"\n")
        seg = self._read_segments(1)[0]
        s = seg.strip()
        parts = s.split()
        for k in range(len(parts)-1):
            if parts[k] == b"blk:":
                return bytes.fromhex(parts[k+1].decode())
        raise RuntimeError(f"unexpected enc1 segment: {seg!r}")


class Solver:
    def __init__(self):
        # self.p = process(["python3", "chall.py"])
        self.p = remote("127.0.0.1", 9057)
        self.iv0, self.ct0 = self._read_banner()

        oracle_iv = bytearray(os.urandom(16))
        oracle_iv[0] = (oracle_iv[0] & 0xF8) | 0x04
        self.oracle_iv = bytes(oracle_iv)

        self.io = FastIO(self.p)
        self.hexlify = binascii.hexlify

        self._choose_good_fixed_blocks()

    def _read_banner(self):
        def recv_nonempty():
            while True:
                line = self.p.recvline()
                if not line:
                    raise EOFError("process closed")
                s = line.strip()
                if s:
                    return s

        iv_line = recv_nonempty().decode()
        ct_line = recv_nonempty().decode()
        if not iv_line.startswith("iv:") or not ct_line.startswith("ct:"):
            raise RuntimeError("unexpected banner")
        iv = bytes.fromhex(iv_line.split("iv:")[1].strip())
        ct = bytes.fromhex(ct_line.split("ct:")[1].strip())
        return iv, ct

    def enc1(self, b16: bytes) -> bytes:
        return self.io.send_line_and_get_blk(self.hexlify(b16))

    def E_K1(self, b16: bytes) -> bytes:
        y = self.enc1(b16)
        return bxor(y, b16)

    def compute_MK(self, iv: bytes) -> bytes:
        P1 = iv
        P2 = iv
        P3 = bytes([0x10]) * 16
        C1 = self.E_K1(P1)
        C2 = self.E_K1(bxor(P2, C1))
        C3 = self.E_K1(bxor(P3, C2))
        return C3

    def _make_prefix(self):
        self.prefix = self.oracle_iv + self.b0 + self.b1 + self.b2 + self.b3

    def _hexline(self, prev: bytes, targetC: bytes) -> bytes:
        return self.hexlify(self.prefix + prev + targetC)

    def _choose_good_fixed_blocks(self):
        targetC = os.urandom(16)
        hx = self.hexlify

        while True:
            self.b0 = bytes([os.urandom(1)[0] & 0xFE]) + os.urandom(15)
            self.b1 = os.urandom(16)
            self.b2 = os.urandom(16)
            self.b3 = os.urandom(16)
            self._make_prefix()

            lines = []
            for g in range(256):
                prev = bytearray(os.urandom(16))
                prev[15] = g ^ 1
                lines.append(hx(self.prefix + bytes(prev) + targetC))
            oks = self.io.send_lines_and_get_okno(lines)
            cand = [g for g, ok in enumerate(oks) if ok]
            if not cand:
                continue

            cand = cand[:12]
            for g in cand:
                test = []
                for _ in range(25):
                    prev = bytearray(os.urandom(16))
                    prev[15] = g ^ 1
                    test.append(hx(self.prefix + bytes(prev) + targetC))
                okcnt = sum(self.io.send_lines_and_get_okno(test))
                if okcnt >= 18:
                    return

    def _sweep_candidates(self, targetC: bytes, base_suffix: bytes, pos: int, padv: int, sweeps: int = 2):
        counts = [0] * 256
        hx = self.hexlify
        pre = self.prefix

        for _ in range(sweeps):
            lines = []
            for g in range(256):
                prev = bytearray(os.urandom(16))
                prev[pos+1:] = base_suffix[pos+1:]
                prev[pos] = g ^ padv
                lines.append(hx(pre + bytes(prev) + targetC))
            oks = self.io.send_lines_and_get_okno(lines)
            for g, ok in enumerate(oks):
                counts[g] += 1 if ok else 0

        return counts

    def _confirm_batch(self, targetC: bytes, base_suffix: bytes, pos: int, padv: int, cand: list[int], trials: int):
        score = {g: 0 for g in cand}
        hx = self.hexlify
        pre = self.prefix

        for _ in range(trials):
            lines = []
            for g in cand:
                prev = bytearray(os.urandom(16))
                prev[pos+1:] = base_suffix[pos+1:]
                prev[pos] = g ^ padv
                lines.append(hx(pre + bytes(prev) + targetC))
            oks = self.io.send_lines_and_get_okno(lines)
            for g, ok in zip(cand, oks):
                score[g] += 1 if ok else 0

        return score

    def _anti_falsepad_check(self, targetC: bytes, base_suffix: bytes, pos: int, padv: int, g: int) -> bool:
        if padv <= 1 or pos == 15:
            return True

        hx = self.hexlify
        pre = self.prefix

        prev = bytearray(os.urandom(16))
        prev[pos+1:] = base_suffix[pos+1:]
        prev[pos] = g ^ padv
        prev[pos+1] ^= 1

        line = hx(pre + bytes(prev) + targetC)
        oks = sum(self.io.send_lines_and_get_okno([line] * 7))

        return oks <= 3

    def recover_intermediate(self, targetC: bytes) -> bytes:
        I = bytearray(16)

        for pos in range(15, -1, -1):
            padv = 16 - pos

            base = bytearray(16)
            for k in range(15, pos, -1):
                base[k] = I[k] ^ padv

            counts = self._sweep_candidates(targetC, bytes(base), pos, padv, sweeps=2)
            mx = max(counts)
            if mx <= 0:
                counts = self._sweep_candidates(targetC, bytes(base), pos, padv, sweeps=3)
                mx = max(counts)

            cand = [g for g in range(256) if counts[g] >= 1]
            if not cand:
                raise RuntimeError(f"no candidates at pos={pos}")

            cand.sort(key=lambda g: counts[g], reverse=True)
            cand = cand[:64]

            trials = 9
            score = self._confirm_batch(targetC, bytes(base), pos, padv, cand, trials=trials)

            def best_two(sc):
                items = sorted(sc.items(), key=lambda kv: kv[1], reverse=True)
                return items[0], (items[1] if len(items) > 1 else (None, -999))

            (bestg, bests), (secg, secs) = best_two(score)

            if bests < 6 or bests - secs < 3:
                top = sorted(cand, key=lambda g: score[g], reverse=True)[:16]
                extra = 6
                score2 = self._confirm_batch(targetC, bytes(base), pos, padv, top, trials=extra)
                for g in top:
                    score[g] += score2[g]
                (bestg, bests), (secg, secs) = best_two({g: score[g] for g in top})
                trials += extra

            if bests < (trials * 2) // 3:
                counts2 = self._sweep_candidates(targetC, bytes(base), pos, padv, sweeps=1)
                for i in range(256):
                    counts[i] += counts2[i]
                cand2 = [g for g in range(256) if counts[g] >= 2]
                if not cand2:
                    cand2 = [g for g in range(256) if counts[g] >= 1]
                cand2.sort(key=lambda g: counts[g], reverse=True)
                cand2 = cand2[:24]
                score = self._confirm_batch(targetC, bytes(base), pos, padv, cand2, trials=13)
                (bestg, bests), (secg, secs) = best_two(score)
                trials = 13

            if padv > 1:
                ordered = sorted(score.keys(), key=lambda g: score[g], reverse=True)[:6]
                chosen = None
                for g in ordered:
                    if self._anti_falsepad_check(targetC, bytes(base), pos, padv, g):
                        chosen = g
                        break
                if chosen is None:
                    raise RuntimeError(f"falsepad unresolved at pos={pos}")
                bestg = chosen

            I[pos] = bestg

        return bytes(I)

    def solve(self):
        iv = self.iv0
        ct = self.ct0
        C = chunk16(ct)

        P_blocks = []
        for i, Ci in enumerate(C):
            Ii = self.recover_intermediate(Ci)
            prevC = iv if i == 0 else C[i-1]
            Pi = bxor(Ii, prevC)
            P_blocks.append(Pi)

        pt_padded = b"".join(P_blocks)
        pt = unpad(pt_padded, 16)

        MK = self.compute_MK(iv)
        H1 = pt[:16]
        H0 = bxor(H1, MK)
        flag = H0 + pt[16:]
        print(flag.decode(errors="replace"))

if __name__ == "__main__":
    Solver().solve()