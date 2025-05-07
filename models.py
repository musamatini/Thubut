# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired # Added BadSignature, SignatureExpired
from flask import current_app
import json
import datetime # Added
import random # Added
import string # Added

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Renamed age to birthday and changed type
    birthday = db.Column(db.Date, nullable=False)
    # Made phone_number non-nullable, ensure it can store E.164 format
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    languages = db.Column(db.Text, nullable=False) # Made non-nullable
    password_hash = db.Column(db.String(256), nullable=False)

    email_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    # Fields for email verification code
    email_verification_code = db.Column(db.String(6), nullable=True)
    email_verification_code_expires_at = db.Column(db.DateTime, nullable=True)

    # Fields for phone number verification (optional for now, can be made mandatory later)
    phone_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    phone_verification_code = db.Column(db.String(6), nullable=True)
    phone_verification_code_expires_at = db.Column(db.DateTime, nullable=True)

    role = db.Column(db.String(20), default='Memorizer', nullable=False)

    # For password reset
    password_reset_token = db.Column(db.String(100), nullable=True)
    password_reset_token_expires_at = db.Column(db.DateTime, nullable=True)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_verification_code(self, length=6):
        return "".join(random.choices(string.digits, k=length))

    def set_email_verification_code(self):
        self.email_verification_code = self.generate_verification_code()
        self.email_verification_code_expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        return self.email_verification_code

    def verify_email_code(self, code):
        if self.email_verification_code == code and \
           self.email_verification_code_expires_at and \
           self.email_verification_code_expires_at > datetime.datetime.utcnow():
            self.email_confirmed = True
            self.email_verification_code = None
            self.email_verification_code_expires_at = None
            return True
        return False

    def set_phone_verification_code(self):
        self.phone_verification_code = self.generate_verification_code()
        self.phone_verification_code_expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        return self.phone_verification_code

    def verify_phone_code(self, code):
        if self.phone_verification_code == code and \
           self.phone_verification_code_expires_at and \
           self.phone_verification_code_expires_at > datetime.datetime.utcnow():
            self.phone_confirmed = True
            self.phone_verification_code = None
            self.phone_verification_code_expires_at = None
            return True
        return False

    # For Password Reset Token (using itsdangerous)
    def get_password_reset_token(self, expires_in=600): # 10 minutes
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        self.password_reset_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)
        # Store only the token part for easier DB storage if needed, or just verify against expiry directly
        return s.dumps(self.email, salt='password-reset-salt')

    @staticmethod
    def verify_password_reset_token(token, max_age=600):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            email = s.loads(token, salt='password-reset-salt', max_age=max_age)
        except (SignatureExpired, BadSignature):
            return None
        user = User.query.filter_by(email=email).first()
        # Optional: check if token was used or a new one generated
        # by comparing token generation time with user.password_reset_token_expires_at
        return user

    def set_languages(self, lang_list):
        if not lang_list: # Ensure it's not an empty list if languages are required
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
        return f'<User {self.username}>'