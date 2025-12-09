import sqlite3
from typing import List, Tuple, Optional
from db.database import DB_PATH


def list_vault() -> List[Tuple[int, str, str, bytes, bytes, bytes]]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, site, username, password, nonce, salt FROM vault")
    rows = c.fetchall()
    conn.close()
    return rows


def get_entry(entry_id: int) -> Optional[Tuple[int, str, str, bytes, bytes, bytes]]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT id, site, username, password, nonce, salt FROM vault WHERE id=?",
        (entry_id,),
    )
    row = c.fetchone()
    conn.close()
    return row


def insert_entry(
    site: str, username: str, password_blob: bytes, nonce: bytes, salt: bytes
) -> int:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO vault (site, username, password, nonce, salt) VALUES (?, ?, ?, ?, ?)",
        (site, username, password_blob, nonce, salt),
    )
    conn.commit()
    rowid = c.lastrowid
    conn.close()
    return rowid


def update_entry(
    entry_id: int, password_blob: bytes, nonce: bytes, salt: bytes
) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE vault SET password=?, nonce=?, salt=? WHERE id=?",
        (password_blob, nonce, salt, entry_id),
    )
    conn.commit()
    conn.close()


def delete_entry(entry_id: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM vault WHERE id=?", (entry_id,))
    conn.commit()
    conn.close()