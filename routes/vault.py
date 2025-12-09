import base64
import sqlite3
import secrets

from flask import Blueprint, jsonify, redirect, url_for, flash, request, session
from utils.decorators import login_required
from cryptogr.master_key import decrypt
from db.database import DB_PATH

vault_bp = Blueprint("vault", __name__)


@vault_bp.route("/delete/<int:password_id>", methods=["POST"])
@login_required
def delete_password(password_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM vault WHERE id=?", (password_id,))
    conn.commit()
    conn.close()
    flash("Password eliminata!", "info")
    return redirect(url_for("dashboard.dashboard"))


@vault_bp.route("/reveal_password", methods=["POST"])
@login_required
def reveal_password():
    if "master_key" not in session:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json() or {}
    pid = data.get("id")

    try:
        pid = int(pid)
    except Exception:
        return jsonify({"error": "bad_request"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password, nonce, salt FROM vault WHERE id=?", (pid,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "not_found"}), 404

    ciphertext, nonce, salt = row
    master_key = base64.b64decode(session["master_key"])
    plaintext = decrypt(ciphertext, nonce, salt, master_key)

    if plaintext == "[DECRYPT FAILED]":
        return jsonify({"error": "decrypt_failed"}), 500

    return jsonify({"password": plaintext})


@vault_bp.route("/generate_password")
@login_required
def generate_password():
    chars = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    )
    pw = "".join(secrets.choice(chars) for _ in range(20))
    return pw
