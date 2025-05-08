# forms.py
import eventlet
eventlet.monkey_patch()
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, BooleanField, widgets, DateField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from models import User
import pycountry
import re # For password complexity
import phonenumbers # For phone number validation

# --- Generate Language Choices using pycountry ---
# THIS SECTION WAS MISSING OR MISPLACED IN YOUR PROVIDED CODE
try:
    WORLD_LANGUAGES = sorted(
        [
            (lang.alpha_2, lang.name)
            for lang in pycountry.languages
            if hasattr(lang, 'alpha_2') # Ensure the language has a 2-letter code
        ],
        key=lambda x: x[1] # Sort the list alphabetically by language name
    )
except LookupError:
    # Fallback if pycountry database is missing or something goes wrong during lookup
    print("WARNING: pycountry lookup failed. Using a minimal fallback language list.")
    WORLD_LANGUAGES = [
        ('en', 'English'), ('es', 'Spanish'), ('fr', 'French'), ('de', 'German'),
        ('zh', 'Chinese'), ('ar', 'Arabic'), ('hi', 'Hindi'), ('pt', 'Portuguese'),
        # Add more common languages if needed for fallback
    ]

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
        raise ValidationError(errors) # This will pass a list of error messages

# --- MultiCheckboxField (Optional - Tom Select works better with standard SelectMultipleField) ---
# If you are using Tom Select, it's generally easier to use a standard SelectMultipleField
# and let Tom Select enhance that. If you still want custom checkbox rendering, this is okay.
class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()

# --- SignupForm ---
class SignupForm(FlaskForm):
    fullname = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    birthday = DateField('Birthday', validators=[DataRequired()], format='%Y-%m-%d')
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(max=30)]) # Increased max length for E.164 plus formatting

    # For Tom Select, a standard SelectMultipleField is usually best:
    languages = SelectMultipleField(
        'Fluent Languages',
        choices=WORLD_LANGUAGES, # Now WORLD_LANGUAGES is defined
        validators=[DataRequired(message="Please select at least one language.")]
    )
    # If you insist on MultiCheckboxField and TomSelect can't enhance it easily,
    # you might need different JS initialization or stick to just checkbox styling.
    # For the enhanced UI with search, SelectMultipleField + TomSelect is recommended.
    # languages = MultiCheckboxField(
    #     'Fluent Languages',
    #     choices=WORLD_LANGUAGES,
    #     validators=[DataRequired(message="Please select at least one language.")]
    # )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters long."),
            password_complexity
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(),
            EqualTo('password', message="Passwords must match.")
        ]
    )
    submit = SubmitField('Sign Up')

    def validate_username(self, username_field): # Use a different name for the argument
        user = User.query.filter_by(username=username_field.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email_field): # Use a different name for the argument
        user = User.query.filter_by(email=email_field.data.lower()).first()
        if user:
            raise ValidationError('That email is already registered. Please log in or use a different email.')

    def validate_phone_number(self, phone_number_field):
        if phone_number_field.data:
            try:
                # intl-tel-input usually provides the full number with country code (E.164 or similar)
                # so region 'None' is appropriate for parsing.
                parsed_number = phonenumbers.parse(phone_number_field.data, None)
                if not phonenumbers.is_valid_number(parsed_number):
                    raise ValidationError('Invalid phone number format for the selected country or globally.')

                e164_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
                
                # If current_user is available (e.g. editing profile) and is the same user, skip unique check for their own number
                # This check is more relevant during signup or when editing a *different* user's profile
                # For signup, current_user won't be authenticated yet.
                # For profile edit, you'd need to pass current_user to the form or check user.id
                
                existing_user = User.query.filter_by(phone_number=e164_number).first()
                if existing_user:
                    # If we are in an edit context, ensure it's not the current user's own number
                    # from flask_login import current_user
                    # if not (current_user.is_authenticated and current_user.id == existing_user.id):
                    raise ValidationError('That phone number is already registered.')
                
                # Optionally, you can normalize the form data here to store it consistently
                # phone_number_field.data = e164_number
                # However, it's often better to do this normalization in the route before saving to DB.

            except phonenumbers.phonenumberutil.NumberParseException as e:
                error_msg = str(e)
                app_log_msg = f"Phone number parsing error for '{phone_number_field.data}': {error_msg}"
                # Log app_log_msg to your Flask app logger if desired
                
                # Provide a user-friendly message
                if "Invalid country code" in error_msg:
                     raise ValidationError("Invalid country code in the phone number. Please ensure it's correct.")
                elif "too short" in error_msg.lower() or "too long" in error_msg.lower():
                     raise ValidationError("The phone number is too short or too long for the selected country.")
                else:
                     raise ValidationError("Invalid phone number. Please include the country code and check the number (e.g., +12223334444).")


# --- LoginForm ---
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

# --- Email/Phone Verification Code Form ---
class VerificationCodeForm(FlaskForm):
    code = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6, message="Code must be 6 digits.")])
    submit = SubmitField('Verify')

# --- Password Reset Request Form ---
class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

# --- Password Reset Form ---
class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        'New Password',
        validators=[
            DataRequired(),
            Length(min=8),
            password_complexity
        ]
    )
    confirm_password = PasswordField(
        'Confirm New Password',
        validators=[
            DataRequired(),
            EqualTo('password', message="New passwords must match.")
        ]
    )
    submit = SubmitField('Reset Password')