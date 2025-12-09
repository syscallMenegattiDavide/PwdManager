import sqlite3
from typing import Optional, Tuple
from db.database import DB_PATH


# Restituisce tuple (password_hash, salt) oppure None se non esiste una riga.


def get_master() -> Optional[Tuple[str, bytes]]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM master LIMIT 1")
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return row[0], row[1]


# Inserisce una nuova master row se non esiste, altrimenti aggiorna la prima riga (id=1).


def set_master(password_hash: str, salt: bytes) -> None:

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM master LIMIT 1")
    r = c.fetchone()
    if r:
        c.execute(
            "UPDATE master SET password_hash=?, salt=? WHERE id=?",
            (password_hash, salt, r[0]),
        )
    else:
        c.execute(
            "INSERT INTO master (password_hash, salt) VALUES (?, ?)",
            (password_hash, salt),
        )
    conn.commit()
    conn.close()
