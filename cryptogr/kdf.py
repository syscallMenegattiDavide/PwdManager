from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# PBKDF2-HMAC-SHA256 wrapper.
# Nota: iterations = 200000 è il valore usato nel progetto originale per recovery/export/import.


def kdf_pbkdf2(
    password: bytes, salt: bytes, length: int = 32, iterations: int = 200000
) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


# Deriva una chiave a 32 byte da una password (str o bytes) + salt.
# Questa è la funzione usata per derivare la 'master key' quando si imposta/effettua il login.


def derive_key(password, salt: bytes) -> bytes:
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    return kdf_pbkdf2(password_bytes, salt, length=32, iterations=390000)
