from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    password = PasswordField("Master Password", validators=[DataRequired()])
    submit = SubmitField("Accedi")
