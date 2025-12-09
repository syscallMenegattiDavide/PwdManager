from flask import Flask
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

from config import configure_app
from db.database import init_db

# Importa blueprint
from routes.login import login_bp
from routes.dashboard import dashboard_bp
from routes.vault import vault_bp
from routes.mfa import mfa_bp
from routes.recovery import recovery_bp
from routes.export_import import export_import_bp


def create_app():
    load_dotenv()

    app = Flask(__name__)
    configure_app(app)

    # Protezione CSRF
    csrf = CSRFProtect(app)

    # Sessioni lato server
    Session(app)

    # Inizializza DB
    init_db()

    # Registra blueprint
    app.register_blueprint(login_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(vault_bp)
    app.register_blueprint(mfa_bp)
    app.register_blueprint(recovery_bp)
    app.register_blueprint(export_import_bp)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(port=5000, debug=True)
