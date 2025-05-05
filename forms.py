# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectMultipleField, BooleanField, widgets
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, NumberRange, Optional # Keep Optional for other fields
from models import User
import pycountry

# --- Generate Language Choices using pycountry ---
try:
    WORLD_LANGUAGES = sorted(
        [
            (lang.alpha_2, lang.name)
            for lang in pycountry.languages
            if hasattr(lang, 'alpha_2')
        ],
        key=lambda x: x[1]
    )
except LookupError:
    print("WARNING: pycountry lookup failed. Using a minimal fallback language list.")
    WORLD_LANGUAGES = [
        ('en', 'English'), ('es', 'Spanish'), ('fr', 'French'), ('de', 'German'),
        ('zh', 'Chinese'), ('ar', 'Arabic'), ('ur', 'Urdu'), ('ru', 'Russian'),
        ('hi', 'Hindi'), ('bn', 'Bengali'), ('pt', 'Portuguese'), ('ja', 'Japanese'),
    ]

# --- Define the MultiCheckboxField --- (No changes needed here)
class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


# --- Define the SignupForm ---
class SignupForm(FlaskForm):
    fullname = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    age = IntegerField('Age', validators=[Optional(), NumberRange(min=10, max=120)]) # Keep Optional here
    phone_number = StringField('Phone Number (Optional)', validators=[Optional(), Length(max=20)]) # Keep Optional here
    # MODIFIED: Make languages required again
    languages = MultiCheckboxField(
        'Fluent Languages', # <-- Removed "(Optional)" from label
        choices=WORLD_LANGUAGES,
        validators=[DataRequired(message="Please select at least one language.")] # <-- Changed back to DataRequired()
    )
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    # --- Validation methods remain the same ---
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError('That email is already registered. Please log in or use a different email.')

    def validate_phone_number(self, phone_number):
        if phone_number.data:
            user = User.query.filter_by(phone_number=phone_number.data).first()
            if user:
                raise ValidationError('That phone number is already registered.')


# --- LoginForm remains the same ---
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')