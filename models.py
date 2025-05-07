# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app
import json
import datetime
import random
import string

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    birthday = db.Column(db.Date, nullable=False)
    # Changed phone_number to nullable=True as it might be optional at signup
    # If it's mandatory, forms.py should enforce DataRequired() always.
    # The app.py signup logic handles 'None' if not provided.
    phone_number = db.Column(db.String(30), unique=True, nullable=True) # Increased length slightly
    languages = db.Column(db.Text, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    email_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    email_verification_code = db.Column(db.String(6), nullable=True)
    email_verification_code_expires_at = db.Column(db.DateTime, nullable=True)

    phone_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    phone_verification_code = db.Column(db.String(10), nullable=True) # Increased length for API codes
    phone_verification_code_expires_at = db.Column(db.DateTime, nullable=True)

    role = db.Column(db.String(20), default='Memorizer', nullable=False)

    password_reset_token_expires_at = db.Column(db.DateTime, nullable=True)
    # password_reset_token itself is not stored if using itsdangerous correctly; expiry is key.

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def _generate_numeric_code(self, length=6): # Renamed for clarity
        return "".join(random.choices(string.digits, k=length))

    def set_email_verification_code(self):
        self.email_verification_code = self._generate_numeric_code()
        self.email_verification_code_expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        return self.email_verification_code

    def verify_email_code(self, code):
        if self.email_verification_code == code and \
           self.email_verification_code_expires_at and \
           self.email_verification_code_expires_at > datetime.datetime.utcnow():
            self.email_confirmed = True # Mark as confirmed
            self.email_verification_code = None # Clear after use
            self.email_verification_code_expires_at = None
            return True
        return False

    def set_phone_verification_code_details(self, code_from_api, expiry_minutes=10):
        """
        Sets the phone verification code (typically received from an external API) and its expiry.
        This method is for when an external API *provides* you the code it sent.
        """
        self.phone_verification_code = str(code_from_api) # Ensure it's a string
        self.phone_verification_code_expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiry_minutes)
        # Note: This method doesn't return the code as it's an input.

    # This method might be less useful if the SMS API sends its own code that we don't pre-generate.
    # def generate_and_set_phone_code(self, code_length=6, expiry_minutes=10):
    #     generated_code = self._generate_numeric_code(length=code_length)
    #     self.phone_verification_code = generated_code
    #     self.phone_verification_code_expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiry_minutes)
    #     return generated_code

    def verify_phone_code(self, code):
        current_time = datetime.datetime.utcnow()
        app.logger.debug(f"Verifying phone code for user {self.id}. Submitted: '{code}', Stored: '{self.phone_verification_code}', Expires: {self.phone_verification_code_expires_at}, Current: {current_time}")
        if self.phone_verification_code == str(code) and \
           self.phone_verification_code_expires_at and \
           self.phone_verification_code_expires_at > current_time:
            # self.phone_confirmed = True # Actual confirmation flag set in the route
            self.phone_verification_code = None # Clear code after use
            self.phone_verification_code_expires_at = None
            app.logger.info(f"Phone code verification successful for user {self.id}.")
            return True
        app.logger.warning(f"Phone code verification FAILED for user {self.id}. Submitted: '{code}', Stored: '{self.phone_verification_code}', Expires: {self.phone_verification_code_expires_at}, Valid: {self.phone_verification_code_expires_at > current_time if self.phone_verification_code_expires_at else False}")
        return False


    def get_password_reset_token(self, expires_in_seconds=600): # 10 minutes
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        self.password_reset_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in_seconds)
        return s.dumps(self.email, salt='password-reset-salt')

    @staticmethod
    def verify_password_reset_token(token, max_age_seconds=600):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            email = s.loads(token, salt='password-reset-salt', max_age=max_age_seconds)
        except (SignatureExpired, BadSignature) as e:
            current_app.logger.warning(f"Password reset token verification failed: {e}")
            return None
        
        user = User.query.filter_by(email=email).first()
        if user and user.password_reset_token_expires_at and \
           user.password_reset_token_expires_at < datetime.datetime.utcnow():
            current_app.logger.warning(f"Password reset token for {email} has expired based on DB record.")
            return None # Token is also expired based on our stored expiry (double check)
        return user

    def set_languages(self, lang_list):
        if not lang_list:
            raise ValueError("Languages cannot be empty.")
        self.languages = json.dumps(lang_list)

    def get_languages(self):
        if self.languages:
            try:
                return json.loads(self.languages)
            except json.JSONDecodeError:
                return []
        return []

    def __repr__(self):
        return f'<User {self.username} ({self.id})>'

# Add a global app reference for logging in User model methods if needed outside request context
# This is a bit of a hack, prefer passing logger or using current_app if available
from flask import current_app as app