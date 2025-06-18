from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib

def process_key(key):
    """Menghasilkan kunci 8-byte dari hash MD5"""
    hashed = hashlib.md5(key.encode()).digest()
    return hashed[:8]

def encrypt(text, key):
    key = process_key(key)
    des = DES.new(key, DES.MODE_ECB)
    padded_text = pad(text.encode(), 8)  # PKCS5 padding (blok DES = 8 byte)
    encrypted = des.encrypt(padded_text)
    return encrypted.hex()

def decrypt(cipher_hex, key):
    key = process_key(key)
    des = DES.new(key, DES.MODE_ECB)
    decrypted_bytes = des.decrypt(bytes.fromhex(cipher_hex))
    unpadded = unpad(decrypted_bytes, 8)  # Hapus padding PKCS5
    return unpadded.decode()
