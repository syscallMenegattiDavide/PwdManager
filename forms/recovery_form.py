from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired


class RecoveryForm(FlaskForm):
    recovery_key = StringField("Chiave di Recupero", validators=[DataRequired()])
    new_password = PasswordField("Nuova Master Password", validators=[DataRequired()])
    submit = SubmitField("Reimposta Password")
