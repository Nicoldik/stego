#!/usr/bin/env python3
"""
crackme stego tool

Установка: pip install pillow numpy cryptography --break-system-packages
"""

import sys, os, struct, hashlib, secrets, argparse
from PIL import Image
import numpy as np

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("pip install cryptography --break-system-packages")
    sys.exit(1)

MAGIC = b"NCLD"
ORDER_SALT_LEN = 8

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return kdf.derive(password.encode())

def encrypt(plaintext: bytes, password: str):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return MAGIC + salt + nonce + ct

def decrypt(payload: bytes, password: str):
    if payload[:4] != MAGIC:
        raise ValueError("bad magic / wrong extraction or wrong password")
    salt = payload[4:20]
    nonce = payload[20:32]
    ct = payload[32:]
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ct, None)

def pixel_order(width, height, password, salt_for_order):
    n = width * height
    seed = int.from_bytes(hashlib.sha256(password.encode() + salt_for_order).digest()[:8], "big")
    rng = np.random.default_rng(seed)
    order = rng.permutation(n)
    return order

def embed(in_path, out_path, password, secret_text):
    img = Image.open(in_path).convert("RGB")
    arr = np.array(img)
    h, w, _ = arr.shape
    flat = arr.reshape(-1, 3)

    payload = encrypt(secret_text.encode(), password)
    length_prefix = struct.pack(">I", len(payload))
    bitstream_bytes = length_prefix + payload
    bits = np.unpackbits(np.frombuffer(bitstream_bytes, dtype=np.uint8))

    capacity = flat.shape[0]
    if len(bits) > capacity:
        raise ValueError(f"Картинка слишком маленькая: нужно {len(bits)} пикселей, есть {capacity}")

    order_salt = secrets.token_bytes(ORDER_SALT_LEN)
    order = pixel_order(w, h, password, order_salt)

    chosen = order[:len(bits)]
    flat[chosen, 2] = (flat[chosen, 2] & 0xFE) | bits

    out_arr = flat.reshape(h, w, 3)
    Image.fromarray(out_arr, "RGB").save(out_path, "PNG")

    with open(out_path + ".salt", "wb") as f:
        f.write(order_salt)

    print(f"[+] Спрятано {len(payload)} байт шифртекста в {out_path}")
    print(f"[+] Файл соли порядка сохранён: {out_path}.salt (нужен для extract)")

def extract(in_path, password, order_salt_path=None):
    img = Image.open(in_path).convert("RGB")
    arr = np.array(img)
    h, w, _ = arr.shape
    flat = arr.reshape(-1, 3)

    salt_path = order_salt_path or (in_path + ".salt")
    with open(salt_path, "rb") as f:
        order_salt = f.read(ORDER_SALT_LEN)

    order = pixel_order(w, h, password, order_salt)

    len_bits = flat[order[:32], 2] & 1
    length_bytes = np.packbits(len_bits).tobytes()
    payload_len = struct.unpack(">I", length_bytes)[0]

    total_bits = 32 + payload_len * 8
    if total_bits > len(order):
        raise ValueError("Некорректная длина / неверный пароль")

    all_bits = flat[order[:total_bits], 2] & 1
    all_bytes = np.packbits(all_bits).tobytes()
    payload = all_bytes[4:4 + payload_len]

    return decrypt(payload, password)

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("embed")
    e.add_argument("input")
    e.add_argument("output")
    e.add_argument("--password", required=True)
    e.add_argument("--secret", required=True, help="текст флага, который прячем")

    x = sub.add_parser("extract")
    x.add_argument("input")
    x.add_argument("--password", required=True)
    x.add_argument("--salt-file", default=None, help="путь к файлу соли порядка (по умолчанию <input>.salt)")

    args = ap.parse_args()
    if args.cmd == "embed":
        embed(args.input, args.output, args.password, args.secret)
    elif args.cmd == "extract":
        try:
            data = extract(args.input, args.password, args.salt_file)
            print("[+] Извлечённый секрет:", data.decode())
        except Exception as ex:
            print("[-] Ошибка:", ex)

if __name__ == "__main__":
    main()
