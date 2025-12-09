import sqlite3

DB_PATH = "passwords.db"


# Crea il DB e applica le piccole migrazioni.


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Tabella master (hash + salt)
    c.execute(
        """CREATE TABLE IF NOT EXISTS master (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password_hash TEXT NOT NULL,
        salt BLOB
    )"""
    )

    # Tabella vault
    c.execute(
        """CREATE TABLE IF NOT EXISTS vault (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site TEXT,
        username TEXT,
        password BLOB,
        nonce BLOB,
        salt BLOB
    )"""
    )

    # Tabella recovery (versione vecchia aveva solo 'key')
    c.execute(
        """CREATE TABLE IF NOT EXISTS recovery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT
    )"""
    )
    conn.commit()

    # Migrazione colonne recovery
    c.execute("PRAGMA table_info(recovery)")
    rec_cols = [r[1] for r in c.fetchall()]

    if "salt" not in rec_cols:
        try:
            c.execute("ALTER TABLE recovery ADD COLUMN salt BLOB")
        except Exception:
            pass

    if "key_hash" not in rec_cols:
        try:
            c.execute("ALTER TABLE recovery ADD COLUMN key_hash BLOB")
        except Exception:
            pass

    if "backup" not in rec_cols:
        try:
            c.execute("ALTER TABLE recovery ADD COLUMN backup BLOB")
        except Exception:
            pass

    # Migrazione master salt (se mancava)
    c.execute("PRAGMA table_info(master)")
    cols = [r[1] for r in c.fetchall()]
    if "salt" not in cols:
        try:
            c.execute("ALTER TABLE master ADD COLUMN salt BLOB")
            conn.commit()
        except Exception:
            pass

    conn.commit()
    conn.close()
