import sqlite3
from typing import Optional, Tuple
from db.database import DB_PATH


# Restituisce (salt, key_hash, backup) oppure None se la tabella è vuota.
# salt/key_hash/backup possono essere None; caller deve gestirli.


def get_recovery() -> Optional[Tuple[bytes, bytes, bytes]]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT salt, key_hash, backup FROM recovery LIMIT 1")
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return row[0], row[1], row[2]


# Inserisce o aggiorna la riga della tabella recovery.
# key viene generalmente scritto come NULL per motivi di sicurezza.


def upsert_recovery(
    key: Optional[str], salt: bytes, key_hash: bytes, backup: bytes
) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM recovery LIMIT 1")
    r = c.fetchone()
    if r:
        c.execute(
            "UPDATE recovery SET key=?, salt=?, key_hash=?, backup=? WHERE id=?",
            (key, salt, key_hash, backup, r[0]),
        )
    else:
        c.execute(
            "INSERT INTO recovery (key, salt, key_hash, backup) VALUES (?, ?, ?, ?)",
            (key, salt, key_hash, backup),
        )
    conn.commit()
    conn.close()


# Imposta la colonna 'key' a NULL (utile per non lasciare la recovery key in chiaro).


def clear_recovery_key() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE recovery SET key=NULL")
    conn.commit()
    conn.close()