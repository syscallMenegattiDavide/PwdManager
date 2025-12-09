import secrets
from typing import Optional

DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"


# Genera una password sicura usando `secrets.choice`.
# - length: lunghezza (default 20)
# - charset: set di caratteri da usare (default DEFAULT_CHARSET)


def generate_password(length: int = 20, charset: Optional[str] = None) -> str:
    if charset is None:
        charset = DEFAULT_CHARSET
    return "".join(secrets.choice(charset) for _ in range(length))
