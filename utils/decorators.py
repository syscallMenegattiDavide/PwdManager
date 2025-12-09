from functools import wraps
from flask import session, redirect, url_for, flash


# Verifica:
#   - che esista session['master_key']
#   - che session['mfa_ok'] sia True
# Se non ci sono, redirige al login o alla page MFA (come nell'originale).


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "master_key" not in session:
            flash("Sessione scaduta. Effettua nuovamente il login.", "warning")
            return redirect(url_for("login.login"))

        if not session.get("mfa_ok"):
            flash("Devi completare l'autenticazione MFA.", "warning")
            return redirect(url_for("mfa.mfa"))

        return f(*args, **kwargs)

    return decorated_function
