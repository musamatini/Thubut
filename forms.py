# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, BooleanField, widgets, DateField # Added DateField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError # Removed Optional, NumberRange
from models import User
import pycountry
import re # For password complexity
import phonenumbers # For phone number validation
from wtforms import SelectMultipleField

class SignupForm(FlaskForm):
    # ... other fields
    languages = SelectMultipleField( # Changed from MultiCheckboxField
        'Fluent Languages',
        choices=WORLD_LANGUAGES,
        validators=[DataRequired(message="Please select at least one language.")],
        # You might need to add id="languages" in the template for TomSelect to find it
        # Or WTForms will generate an ID like 'languages'
    )

# --- MultiCheckboxField (remains the same, but Tom Select will enhance it) ---
class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


# --- Custom Password Validator ---
def password_complexity(form, field):
    password = field.data
    errors = []
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): # Or use \W for any non-alphanumeric
        errors.append("Password must contain at least one special symbol (e.g., !@#$%).")
    if errors:
        raise ValidationError(errors)

# --- SignupForm ---
class SignupForm(FlaskForm):
    fullname = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    # Changed from age to birthday
    birthday = DateField('Birthday', validators=[DataRequired()], format='%Y-%m-%d')
    # Phone number field - will be enhanced with intl-tel-input
    # The validator will check the full number provided by intl-tel-input
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(max=20)])

    languages = MultiCheckboxField( # Or SelectMultipleField if Tom Select works better
        'Fluent Languages',
        choices=WORLD_LANGUAGES,
        validators=[DataRequired(message="Please select at least one language.")]
    )
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, message="Password must be at least 8 characters long."), password_complexity])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Passwords must match.")])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError('That email is already registered. Please log in or use a different email.')

    def validate_phone_number(self, phone_number_field):
        # This validation assumes phone_number_field.data will be in E.164 format or a format
        # parseable by phonenumbers. intl-tel-input can provide this.
        if phone_number_field.data:
            try:
                # The 'None' for region is important if the number includes the country code.
                # If you only get national number and have a separate country code field,
                # you'd pass the country code (e.g., "US") as the second argument.
                # For intl-tel-input, it usually gives the full E.164 number.
                parsed_number = phonenumbers.parse(phone_number_field.data, None)
                if not phonenumbers.is_valid_number(parsed_number):
                    raise ValidationError('Invalid phone number format for the selected country.')

                # Check for uniqueness using the E.164 format for consistency
                e164_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
                user = User.query.filter_by(phone_number=e164_number).first()
                if user:
                    raise ValidationError('That phone number is already registered.')
                # Store the E.164 format back if you want to normalize it before saving
                # phone_number_field.data = e164_number # This modifies form data, do in route if preferred

            except phonenumbers.phonenumberutil.NumberParseException as e:
                # Error message might be "Invalid country code" or "(0) Invalid number"
                # Customize this message for better UX.
                error_msg = str(e)
                if "Invalid country code" in error_msg:
                     raise ValidationError("Invalid country code in the phone number.")
                else:
                     raise ValidationError("Invalid phone number. Please include country code (e.g., +12223334444).")


# --- LoginForm (remains the same) ---
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

# --- Email Verification Code Form ---
class VerificationCodeForm(FlaskForm):
    code = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')

# --- Password Reset Request Form ---
class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

# --- Password Reset Form ---
class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8), password_complexity])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')