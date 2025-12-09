import base64
import os
import sqlite3
import secrets

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    session,
)
from argon2 import PasswordHasher

from forms.login_forms import LoginForm
from cryptogr.kdf import kdf_pbkdf2, derive_key
from cryptogr.aesgcm import encrypt_bytes
from db.database import DB_PATH
from utils.decorators import login_required

login_bp = Blueprint("login", __name__)
ph = PasswordHasher()


@login_bp.route("/", methods=["GET", "POST"])
def login():
    form = LoginForm()

    # Controlla se esiste una master password
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM master LIMIT 1")
    result = c.fetchone()
    conn.close()

    # Se invio form
    if form.validate_on_submit():
        pw = form.password.data

        # Primo avvio
        if result is None:
            hash_pw = ph.hash(pw)
            master_salt = os.urandom(16)

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                "INSERT INTO master (password_hash, salt) VALUES (?, ?)",
                (hash_pw, master_salt),
            )

            # Genera recovery key
            recovery_key = secrets.token_urlsafe(32)
            recovery_salt = os.urandom(16)

            recovery_key_hash = kdf_pbkdf2(
                recovery_key.encode(),
                recovery_salt,
                length=32,
                iterations=200000,
            )

            # Deriva master key
            derived_key = derive_key(pw, master_salt)

            session.permanent = True
            session["master_key"] = base64.b64encode(derived_key).decode()
            session["mfa_ok"] = False

            # Cifra backup master key
            recovery_enc_key = kdf_pbkdf2(
                recovery_key.encode(),
                recovery_salt,
                length=32,
                iterations=200000,
            )

            backup_blob = encrypt_bytes(derived_key, recovery_enc_key)

            # Scrivi recovery table
            c.execute("SELECT id FROM recovery LIMIT 1")
            r = c.fetchone()

            if r:
                c.execute(
                    "UPDATE recovery SET key=?, salt=?, key_hash=?, backup=? WHERE id=?",
                    (
                        session["recovery_key"],
                        recovery_salt,
                        recovery_key_hash,
                        backup_blob,
                        r[0],
                    ),
                )
            else:
                c.execute(
                    "INSERT INTO recovery (key, salt, key_hash, backup) VALUES (?, ?, ?, ?)",
                    (None, recovery_salt, recovery_key_hash, backup_blob),
                )

            conn.commit()
            conn.close()

            session["recovery_key"] = recovery_key
            return redirect(url_for("recovery.first_setup_recovery"))

        # Login normale
        try:
            stored_hash, stored_salt = result[0], result[1]
            ph.verify(stored_hash, pw)
        except Exception:
            flash("Master password errata.", "danger")
            return redirect(url_for("login.login"))

        derived_key = derive_key(pw, stored_salt)
        session.permanent = True
        session["master_key"] = base64.b64encode(derived_key).decode()
        session["mfa_ok"] = False

        return redirect(url_for("dashboard.dashboard"))

    return render_template("login.html", form=form, pw=result is not None)


@login_bp.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logout effettuato.", "info")
    return redirect(url_for("login.login"))
