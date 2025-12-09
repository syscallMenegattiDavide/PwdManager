import base64
import sqlite3
from flask import Blueprint, redirect, render_template, flash, session, url_for

from forms.add_password_form import AddPasswordForm
from utils.decorators import login_required
from cryptogr.master_key import encrypt, decrypt
from db.database import DB_PATH

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    form = AddPasswordForm()
    master_key = base64.b64decode(session["master_key"])

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Aggiunta password
    if form.validate_on_submit():
        site = form.site.data
        username = form.username.data
        password = form.password.data

        ciphertext, nonce, salt = encrypt(password, master_key)

        c.execute(
            "INSERT INTO vault (site, username, password, nonce, salt) VALUES (?, ?, ?, ?, ?)",
            (site, username, ciphertext, nonce, salt),
        )

        conn.commit()
        flash("Password salvata!", "success")

    c.execute("SELECT id, site, username, password, nonce, salt FROM vault")
    rows = c.fetchall()
    conn.close()

    decrypted = []
    for row in rows:
        pid, site, username, pw, nonce, salt = row
        dec = decrypt(pw, nonce, salt, master_key)
        decrypted.append((pid, site, username, dec))

    return render_template("dashboard.html", add_form=form, passwords=decrypted)


@dashboard_bp.route("/add_password", methods=["POST"])
@login_required
def add_password():
    form = AddPasswordForm()
    if form.validate_on_submit():
        try:
            master_key = base64.b64decode(session["master_key"])
            site = form.site.data
            username = form.username.data
            password = form.password.data
            ciphertext, nonce, salt = encrypt(password, master_key)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                "INSERT INTO vault (site, username, password, nonce, salt) VALUES (?, ?, ?, ?, ?)",
                (site, username, ciphertext, nonce, salt),
            )
            conn.commit()
            conn.close()
            flash("Password aggiunta con successo!", "success")
        except Exception as e:
            dashboard_bp.logger.error(f"Errore durante l'aggiunta della password: {e}")
            flash("Errore durante l'aggiunta della password", "danger")
    else:
        flash("Errore nei dati inseriti.", "danger")

    return redirect(url_for("dashboard.dashboard"))


@dashboard_bp.route("/delete/<int:password_id>", methods=["POST"])
@login_required
def delete_password(password_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM vault WHERE id=?", (password_id,))
    conn.commit()
    conn.close()
    flash("Password eliminata!", "info")
    return redirect(url_for("dashboard.dashboard"))
