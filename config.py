import os
import secrets
from datetime import timedelta


def configure_app(app):
    # Secret key Flask
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)

    if not os.getenv("SECRET_KEY"):
        with open(".env", "a") as f:
            f.write(f"\nSECRET_KEY={app.config['SECRET_KEY']}")

    # Sessioni lato server
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_FILE_DIR"] = os.path.join(os.getcwd(), "flask_session")
    os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)

    app.config["SESSION_PERMANENT"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

    # Cookie sicuri
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
