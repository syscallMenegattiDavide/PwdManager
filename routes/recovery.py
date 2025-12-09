import base64
import os
import sqlite3
import secrets

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    current_app,
)
from argon2 import PasswordHasher

from forms.recovery_form import RecoveryForm
from cryptogr.kdf import kdf_pbkdf2, derive_key
from cryptogr.aesgcm import encrypt_bytes, decrypt_bytes
from cryptogr.master_key import (
    encrypt as encrypt_with_master,
    decrypt as decrypt_with_master,
)
from db.database import DB_PATH
from utils.decorators import login_required
import hmac

recovery_bp = Blueprint("recovery", __name__)
ph = PasswordHasher()

# Flusso di recovery:
# 1) Verifica la recovery key (PBKDF2 + hmac.compare_digest)
# 2) Decifra il backup del master_key (AES-GCM)
# 3) Permette di impostare una nuova master password
# 4) Re-deriva la nuova master key e re-critta il vault
# 5) Genera una nuova recovery key, la cifra e la salva (hash + salt + backup)


@recovery_bp.route("/recovery", methods=["GET", "POST"])
@login_required
def recovery():
    form = RecoveryForm()
    if form.validate_on_submit():
        rkey = form.recovery_key.data.strip()
        new_pw = form.new_password.data

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT salt, key_hash, backup FROM recovery LIMIT 1")
        row = c.fetchone()

        if not row:
            flash("Chiave di recupero non valida.", "danger")
            conn.close()
            return redirect(url_for("recovery.recovery"))

        rec_salt, rec_hash, backup_blob = row

        if rec_salt is None or rec_hash is None or backup_blob is None:
            flash("Sistema di recovery non configurato correttamente.", "danger")
            conn.close()
            return redirect(url_for("recovery.recovery"))

        # Verifica la recovery key (PBKDF2)
        try:
            derived = kdf_pbkdf2(rkey.encode(), rec_salt, length=32, iterations=200000)
        except Exception as e:
            current_app.logger.error(f"Errore derivazione recovery key: {e}")
            flash("Errore durante la verifica della chiave di recupero.", "danger")
            conn.close()
            return redirect(url_for("recovery.recovery"))

        if not hmac.compare_digest(derived, rec_hash):
            flash("Chiave di recupero non valida.", "danger")
            conn.close()
            return redirect(url_for("recovery.recovery"))

        # Decifra backup del master_key
        try:
            rec_enc_key = kdf_pbkdf2(
                rkey.encode(), rec_salt, length=32, iterations=200000
            )
            master_key_bytes = decrypt_bytes(backup_blob, rec_enc_key)
        except Exception as e:
            current_app.logger.error(f"Errore decifratura backup master_key: {e}")
            flash("Impossibile decifrare il backup del master key.", "danger")
            conn.close()
            return redirect(url_for("recovery.recovery"))

        # Aggiorna master password + salt
        master_salt = os.urandom(16)
        hash_pw = ph.hash(new_pw)
        c.execute(
            "UPDATE master SET password_hash=?, salt=? WHERE id=1",
            (hash_pw, master_salt),
        )

        # Deriva nuova master key
        new_derived_key = derive_key(new_pw, master_salt)

        # Re-encrypt vault: leggi tutte le righe, decripta con master_key_bytes (vecchia derived key),
        # e ricripta con new_derived_key
        c.execute("SELECT id, password, nonce, salt FROM vault")
        vault_rows = c.fetchall()

        for vid, ciphertext, nonce, salt in vault_rows:
            try:
                plaintext = decrypt_with_master(
                    ciphertext, nonce, salt, master_key_bytes
                )
            except Exception:
                plaintext = "[DECRYPT FAILED]"

            if plaintext == "[DECRYPT FAILED]":
                current_app.logger.warning(
                    f"Could not decrypt vault id {vid} during recovery re-encrypt. Leaving unchanged."
                )
                continue

            new_ct, new_nonce, new_salt = encrypt_with_master(
                plaintext, new_derived_key
            )
            c.execute(
                "UPDATE vault SET password=?, nonce=?, salt=? WHERE id=?",
                (new_ct, new_nonce, new_salt, vid),
            )

        # Genera una NUOVA recovery key e relativo backup/hash/salt
        new_recovery = secrets.token_urlsafe(32)
        new_recovery_salt = os.urandom(16)
        new_recovery_hash = kdf_pbkdf2(
            new_recovery.encode(), new_recovery_salt, length=32, iterations=200000
        )
        new_backup_blob = encrypt_bytes(
            new_derived_key,
            kdf_pbkdf2(
                new_recovery.encode(), new_recovery_salt, length=32, iterations=200000
            ),
        )

        # Aggiorna tabella recovery (lasciamo 'key' a NULL per sicurezza)
        c.execute("SELECT id FROM recovery LIMIT 1")
        r = c.fetchone()
        if r:
            c.execute(
                "UPDATE recovery SET key=NULL, salt=?, key_hash=?, backup=? WHERE id=?",
                (new_recovery_salt, new_recovery_hash, new_backup_blob, r[0]),
            )
        else:
            c.execute(
                "INSERT INTO recovery (key, salt, key_hash, backup) VALUES (?, ?, ?, ?)",
                (None, new_recovery_salt, new_recovery_hash, new_backup_blob),
            )

        conn.commit()
        conn.close()

        # Salva in sessione per mostrarla (l'utente dovrà salvarla)
        session["recovery_key"] = new_recovery
        flash(
            "Master password reimpostata correttamente. Conserva la nuova recovery key mostrata.",
            "success",
        )
        return redirect(url_for("recovery.show_recovery"))

    return render_template("recovery.html", form=form)


# Mostra la recovery key in chiaro (presa dalla sessione)
# L'utente deve confermare di averla salvata.


@recovery_bp.route("/show_recovery", methods=["GET", "POST"])
def show_recovery():

    recovery_key = session.get("recovery_key")
    if not recovery_key:
        flash("Nessuna recovery key disponibile.", "warning")
        return redirect(url_for("login.login"))

    if request.method == "POST":
        if request.form.get("confirm_save"):
            session.pop("recovery_key", None)
            flash("Recovery key salvata correttamente!", "success")
            return redirect(url_for("login.login"))
        else:
            flash("Devi confermare di aver salvato la recovery key.", "danger")

    return render_template("show_recovery.html", recovery_key=recovery_key)


# Pagina obbligatoria al primo avvio: mostra la recovery key appena generata
# (presa da session), l'utente deve confermare prima di proseguire al setup MFA.


@recovery_bp.route("/first_setup_recovery", methods=["GET", "POST"])
def first_setup_recovery():

    recovery_key = session.get("recovery_key")

    if not recovery_key:
        flash("Nessuna recovery key disponibile.", "warning")
        return redirect(url_for("login.login"))

    if request.method == "POST":
        if request.form.get("confirm_save"):
            session.pop("recovery_key", None)
            flash("Recovery key salvata correttamente!", "success")
            return redirect(url_for("mfa.setup_mfa"))
        else:
            flash("Devi confermare di aver salvato la recovery key.", "danger")

    return render_template("first_setup_recovery.html", recovery_key=recovery_key)
