from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired


class MFAForm(FlaskForm):
    token = StringField("Codice MFA", validators=[DataRequired()])
    submit = SubmitField("Verifica")
