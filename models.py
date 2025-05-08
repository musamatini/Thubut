# models.py

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
# MODIFIED: Moved current_app import to the top and added alias as app for logger calls
from flask import current_app as app
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
    phone_verification_code = db.Column(db.String(10), nullable=True) # Increased length for API codes (might be longer than 6)
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
            self.email_confirmed = True
            app.logger.info(f"[User.verify_email_code] User {self.id}: email_confirmed set to True on instance.") # LOG
            self.email_verification_code = None
            self.email_verification_code_expires_at = None
            return True
        app.logger.warning(f"[User.verify_email_code] User {self.id}: Code '{code}' verification failed. Stored: '{self.email_verification_code}', Expires: {self.email_verification_code_expires_at}") # LOG
        return False

    

    def set_phone_verification_code_details(self, code_from_api, expiry_minutes=10):
        """
        Sets the phone verification code (typically received from an external API) and its expiry.
        This method is for when an external API *provides* you the code it sent.
        """
        # Ensure the code is a string to avoid type comparison issues later
        self.phone_verification_code = str(code_from_api) 
        self.phone_verification_code_expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiry_minutes)
        app.logger.debug(f"User {self.id}: Set phone verification code and expiry.")
        # Note: This method doesn't return the code as it's an input.

    # This method might be less useful if the SMS API sends its own code that we don't pre-generate.
    # def generate_and_set_phone_code(self, code_length=6, expiry_minutes=10):
    #     generated_code = self._generate_numeric_code(length=code_length)
    #     self.phone_verification_code = generated_code
    #     self.phone_verification_code_expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiry_minutes)
    #     return generated_code

    def verify_phone_code(self, code):
        current_time = datetime.datetime.utcnow()
        # Use == comparison for string codes
        is_code_match = (self.phone_verification_code is not None) and (str(self.phone_verification_code) == str(code))
        is_not_expired = (self.phone_verification_code_expires_at is not None) and (self.phone_verification_code_expires_at > current_time)

        app.logger.debug(f"Verifying phone code for user {self.id}. Submitted: '{code}', Stored: '{self.phone_verification_code}', Expires: {self.phone_verification_code_expires_at}, Current: {current_time}. Match: {is_code_match}, Not Expired: {is_not_expired}")

        if is_code_match and is_not_expired:
            # self.phone_confirmed = True # Actual confirmation flag set in the route
            self.phone_verification_code = None # Clear code after use
            self.phone_verification_code_expires_at = None
            app.logger.info(f"Phone code verification successful for user {self.id}.")
            return True
        
        # Clear code on failure to prevent brute-forcing the same old code
        if self.phone_verification_code:
             app.logger.warning(f"Phone code verification FAILED for user {self.id}. Clearing code.")
             self.phone_verification_code = None # Clear code on failed attempt
             self.phone_verification_code_expires_at = None # Clear expiry

        return False


    def get_password_reset_token(self, expires_in_seconds=600): # 10 minutes
        s = URLSafeTimedSerializer(app.config['SECRET_KEY']) # Use app.config
        self.password_reset_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in_seconds)
        return s.dumps(self.email, salt='password-reset-salt')

    @staticmethod
    def verify_password_reset_token(token, max_age_seconds=600):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY']) # Use app.config
        try:
            email = s.loads(token, salt='password-reset-salt', max_age=max_age_seconds)
        except (SignatureExpired, BadSignature) as e:
            app.logger.warning(f"Password reset token verification failed: {e}")
            return None
        
        user = User.query.filter_by(email=email).first()
        # Also check against the stored expiry time in the DB as an extra layer
        if user and user.password_reset_token_expires_at and \
           user.password_reset_token_expires_at < datetime.datetime.utcnow():
            app.logger.warning(f"Password reset token for {email} has expired based on DB record.")
            # Optionally, clear these fields if they exist but are expired
            # user.password_reset_token_expires_at = None
            # db.session.commit() # Requires a session context and potential commit
            return None # Token is expired

        # If the token was valid according to itsdangerous, but no user or expired in DB
        if not user:
             app.logger.warning(f"Password reset token valid for email {email} but no user found.")
             return None
        
        return user # Token is valid and user found


    def set_languages(self, lang_list):
        if not lang_list:
            # Or handle this validation in the form
            raise ValueError("Languages cannot be empty.") 
        self.languages = json.dumps(lang_list)

    def get_languages(self):
        if self.languages:
            try:
                return json.loads(self.languages)
            except (json.JSONDecodeError, TypeError): # Handle None or non-string
                app.logger.error(f"Error decoding languages JSON for user {self.id}: {self.languages}")
                return []
        return []

    def __repr__(self):
        return f'<User {self.username} ({self.id})>'

# The import was moved to the top and aliased as 'app'
# from flask import current_app as app # REMOVED from here