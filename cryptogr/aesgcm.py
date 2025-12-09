import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Cifra dati raw con AES-GCM e restituisce blob = nonce + ciphertext.
# Usato per backup CSV e backup master_key (export/import/backup recovery).


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


# Decifra blob = nonce + ciphertext AES-GCM.
# Rilascia eccezione in caso di tag invalido.


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    if not blob or len(blob) < 13:
        raise ValueError("Blob non valido")
    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)
