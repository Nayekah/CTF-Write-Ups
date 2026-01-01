from pathlib import Path

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def main(output_path="output.txt", known_plaintext_path="plaintext.txt"):
    lines = [ln.strip() for ln in Path(output_path).read_text().splitlines() if ln.strip()]
    lengths = [len(x) for x in lines]
    idx_long = max(range(len(lines)), key=lambda i: lengths[i])

    known_plaintext = Path(known_plaintext_path).read_bytes().strip()
    ct_known = bytes.fromhex(lines[idx_long])

    L = min(len(known_plaintext), len(ct_known))
    keystream = xor_bytes(known_plaintext[:L], ct_known[:L])

    short_lens = [len(x) for x in lines if len(x) < lengths[idx_long]]
    if not short_lens:
        raise RuntimeError("No short 4-byte cipher parts found before/after the known-plaintext line.")
    chunk_hex_len = min(short_lens)
    chunk_size = chunk_hex_len // 2
    ks_head = keystream[:chunk_size]
    if len(ks_head) != chunk_size:
        raise RuntimeError("Known plaintext not long enough to extract keystream head.")

    flag_chunks = []
    for i in range(idx_long):
        ct_part = bytes.fromhex(lines[i])
        if len(ct_part) != chunk_size:
            raise RuntimeError(f"Unexpected chunk length on line {i+1}: got {len(ct_part)} bytes.")
        pt_part = xor_bytes(ct_part, ks_head)
        flag_chunks.append(pt_part)

    flag = b"".join(flag_chunks)
    print("Flag:", flag.decode("utf-8"))

if __name__ == "__main__":
    main()