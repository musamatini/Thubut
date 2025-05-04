from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectMultipleField, BooleanField, widgets
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, NumberRange, Optional
from models import User

# List of common languages - expand as needed
LANGUAGE_CHOICES = [
    ('ar', 'Arabic (العربية)'),
    ('en', 'English'),
    ('ur', 'Urdu (اردو)'),
    ('fr', 'French (Français)'),
    ('tr', 'Turkish (Türkçe)'),
    ('id', 'Indonesian (Bahasa Indonesia)'),
    ('ms', 'Malay (Bahasa Melayu)'),
    ('bn', 'Bengali (বাংলা)'),
    ('de', 'German (Deutsch)'),
    ('es', 'Spanish (Español)'),
    ('ru', 'Russian (Русский)'),
    ('zh', 'Chinese (中文)'),
]

class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class SignupForm(FlaskForm):
    fullname = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    age = IntegerField('Age', validators=[Optional(), NumberRange(min=10, max=120)])
    phone_number = StringField('Phone Number (Optional)', validators=[Optional(), Length(max=20)])
    languages = MultiCheckboxField('Fluent Languages', choices=LANGUAGE_CHOICES, validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please log in or use a different email.')

    def validate_phone_number(self, phone_number):
        if phone_number.data:
            user = User.query.filter_by(phone_number=phone_number.data).first()
            if user:
                raise ValidationError('That phone number is already registered.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')