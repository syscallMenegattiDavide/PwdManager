import base64
import csv
import io
import sqlite3

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_file,
)
from io import BytesIO

from utils.decorators import login_required
from cryptogr.kdf import kdf_pbkdf2
from cryptogr.aesgcm import encrypt_bytes, decrypt_bytes
from cryptogr.master_key import (
    decrypt as decrypt_with_master,
    encrypt as encrypt_with_master,
)
from db.database import DB_PATH

export_import_bp = Blueprint("export_import", __name__)


@export_import_bp.route("/export", methods=["GET"])
@login_required
def export_page():
    return render_template("export.html")


# 1) Verifica la recovery key (PBKDF2)
# 2) Decripta tutte le password dal vault utilizzando master_key in sessione
# 3) Crea CSV in-memory e lo cifra con una chiave derivata dalla recovery key (AES-GCM)
# 4) Restituisce file binario (nonce + ciphertext)


@export_import_bp.route("/export", methods=["POST"])
@login_required
def export_passwords():
    user_key = request.form.get("recovery_key", "").strip()
    if not user_key:
        flash("Inserisci la recovery key.", "danger")
        return redirect(url_for("export_import.export_page"))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT salt, key_hash FROM recovery LIMIT 1")
    row = c.fetchone()
    if not row:
        conn.close()
        flash("Sistema di recovery non configurato.", "danger")
        return redirect(url_for("export_import.export_page"))

    rec_salt, rec_hash = row
    if rec_salt is None or rec_hash is None:
        conn.close()
        flash("Sistema di recovery non configurato correttamente.", "danger")
        return redirect(url_for("export_import.export_page"))

    # Verifica recovery key (PBKDF2)
    try:
        derived = kdf_pbkdf2(user_key.encode(), rec_salt, length=32, iterations=200000)
    except Exception:
        conn.close()
        flash("Errore durante la verifica della recovery key.", "danger")
        return redirect(url_for("export_import.export_page"))

    # Confronto (usiamo hmac.compare_digest per sicurezza)
    import hmac

    if not hmac.compare_digest(derived, rec_hash):
        conn.close()
        flash("Recovery key non valida!", "error")
        return redirect(url_for("export_import.export_page"))

    # Recupera tutto il vault
    c.execute("SELECT site, username, password, nonce, salt FROM vault")
    rows = c.fetchall()
    conn.close()

    master_key = base64.b64decode(session["master_key"])

    # Crea CSV in memoria
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["site", "username", "password"])
    for site, username, pw_blob, nonce, salt in rows:
        try:
            plaintext = decrypt_with_master(pw_blob, nonce, salt, master_key)
        except Exception:
            plaintext = "[DECRYPT FAILED]"
        writer.writerow([site, username, plaintext])

    csv_bytes = output.getvalue().encode("utf-8")

    # Cifra CSV con chiave derivata dalla recovery key
    rec_enc_key = kdf_pbkdf2(user_key.encode(), rec_salt, length=32, iterations=200000)
    encrypted_blob = encrypt_bytes(csv_bytes, rec_enc_key)  # nonce + ciphertext

    mem = BytesIO()
    mem.write(encrypted_blob)
    mem.seek(0)

    filename = "passwords_encrypted.bin"
    return send_file(
        mem,
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream",
    )


@export_import_bp.route("/import", methods=["GET"])
@login_required
def import_page():
    if "master_key" not in session or not session.get("mfa_ok"):
        return redirect(url_for("login.login"))
    return render_template("import.html")


# 1) Verifica recovery key (PBKDF2)
# 2) Decifra file binario (nonce+ciphertext) con la derived key
# 3) Legge CSV e importa ogni riga nel vault cifrandola con la master_key corrente


@export_import_bp.route("/import", methods=["POST"])
@login_required
def import_passwords():
    if "master_key" not in session or not session.get("mfa_ok"):
        flash("Sessione non valida. Effettua nuovamente il login.", "warning")
        return redirect(url_for("login.login"))

    user_key = request.form.get("recovery_key", "").strip()
    file = request.files.get("file")

    if not file:
        flash("Nessun file selezionato.", "danger")
        return redirect(url_for("export_import.import_page"))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT salt, key_hash FROM recovery LIMIT 1")
    row = c.fetchone()
    conn.close()

    if not row or not row[0]:
        flash("Sistema di recovery non configurato correttamente.", "danger")
        return redirect(url_for("export_import.import_page"))

    rec_salt, rec_hash = row

    try:
        derived = kdf_pbkdf2(user_key.encode(), rec_salt, length=32, iterations=200000)
    except Exception:
        flash("Errore durante la derivazione della chiave di recovery.", "danger")
        return redirect(url_for("export_import.import_page"))

    import hmac

    if not hmac.compare_digest(derived, rec_hash):
        flash("Recovery key non valida!", "danger")
        return redirect(url_for("export_import.import_page"))

    # Decifra il file
    try:
        encrypted_blob = file.read()  # nonce + ciphertext
        csv_bytes = decrypt_bytes(encrypted_blob, derived)
        content = csv_bytes.decode("utf-8")
        reader = csv.reader(io.StringIO(content))
        header = next(reader)
        if header != ["site", "username", "password"]:
            flash("Formato CSV non valido. Intestazioni errate.", "danger")
            return redirect(url_for("export_import.import_page"))
    except Exception:
        flash("Errore nella decifratura o nella lettura del file CSV.", "danger")
        return redirect(url_for("export_import.import_page"))

    master_key = base64.b64decode(session["master_key"])
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    imported = 0
    for row in reader:
        if len(row) != 3:
            continue
        site, username, pwd_plain = row
        ciphertext, nonce, salt = encrypt_with_master(pwd_plain, master_key)
        c.execute(
            "INSERT INTO vault (site, username, password, nonce, salt) VALUES (?, ?, ?, ?, ?)",
            (site, username, ciphertext, nonce, salt),
        )
        imported += 1

    conn.commit()
    conn.close()

    flash(f"Import completato: {imported} password aggiunte al vault.", "success")
    return redirect(url_for("dashboard.dashboard"))
