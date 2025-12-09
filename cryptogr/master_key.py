import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .kdf import derive_key


# Cifra una singola password del vault.
# Restituisce (ciphertext, nonce, salt).
# Nota: la funzione deriva una key per entry con derive_key(master_key, salt)
# così com'era nel progetto originale.


def encrypt(password: str, master_key) -> tuple:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(master_key, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, password.encode(), None)
    return ciphertext, nonce, salt


# Decifra una password del vault.
# Se la decifratura fallisce ritorna la stringa '[DECRYPT FAILED]' per mantenere la compatibilità.


def decrypt(ciphertext: bytes, nonce: bytes, salt: bytes, master_key) -> str:
    try:
        key = derive_key(master_key, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        return "[DECRYPT FAILED]"