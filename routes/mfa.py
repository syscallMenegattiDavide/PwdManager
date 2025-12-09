import base64
import io
import os
import qrcode
import pyotp

from flask import Blueprint, render_template, redirect, url_for, session, flash
from forms.mfa_form import MFAForm
from dotenv import load_dotenv

mfa_bp = Blueprint("mfa", __name__)

load_dotenv()

TOTP_SECRET = os.getenv("TOTP_SECRET")
if not TOTP_SECRET:
    TOTP_SECRET = pyotp.random_base32()
    with open(".env", "a") as f:
        f.write(f"\nTOTP_SECRET={TOTP_SECRET}")


@mfa_bp.route("/setup_mfa")
def setup_mfa():
    if "master_key" not in session:
        return redirect(url_for("login.login"))

    totp = pyotp.TOTP(TOTP_SECRET)
    uri = totp.provisioning_uri(name="Vault", issuer_name="SecureVault")

    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template("setup_mfa.html", qr_b64=qr_b64)


@mfa_bp.route("/mfa", methods=["GET", "POST"])
def mfa():
    if "master_key" not in session:
        return redirect(url_for("login.login"))

    form = MFAForm()
    totp = pyotp.TOTP(TOTP_SECRET)

    if form.validate_on_submit():
        token = form.token.data.strip()

        if totp.verify(token):
            session["mfa_ok"] = True
            flash("Autenticazione MFA riuscita!", "success")
            return redirect(url_for("dashboard.dashboard"))
        else:
            flash("Codice MFA non valido.", "danger")

    return render_template("mfa.html", form=form)
