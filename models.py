from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app as app # Changed alias to 'app' for consistency
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
    phone_number = db.Column(db.String(30), unique=True, nullable=True)
    languages = db.Column(db.Text, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    email_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    email_verification_code = db.Column(db.String(6), nullable=True)
    email_verification_code_expires_at = db.Column(db.DateTime, nullable=True)

    phone_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    phone_verification_code = db.Column(db.String(10), nullable=True)
    phone_verification_code_expires_at = db.Column(db.DateTime, nullable=True)

    role = db.Column(db.String(20), default='Memorizer', nullable=False)

    password_reset_token_expires_at = db.Column(db.DateTime, nullable=True)

    # Relationship to MemorizationProgress (added)
    # backref 'progress_entries' will be on the User instance
    # 'user' will be on the MemorizationProgress instance

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def _generate_numeric_code(self, length=6):
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
            app.logger.info(f"[User.verify_email_code] User {self.id}: email_confirmed set to True on instance.")
            self.email_verification_code = None
            self.email_verification_code_expires_at = None
            return True
        app.logger.warning(f"[User.verify_email_code] User {self.id}: Code '{code}' verification failed. Stored: '{self.email_verification_code}', Expires: {self.email_verification_code_expires_at}")
        return False

    def set_phone_verification_code_details(self, code_from_api, expiry_minutes=10):
        self.phone_verification_code = str(code_from_api) 
        self.phone_verification_code_expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiry_minutes)
        app.logger.debug(f"User {self.id}: Set phone verification code and expiry.")

    def verify_phone_code(self, code):
        current_time = datetime.datetime.utcnow()
        is_code_match = (self.phone_verification_code is not None) and (str(self.phone_verification_code) == str(code))
        is_not_expired = (self.phone_verification_code_expires_at is not None) and (self.phone_verification_code_expires_at > current_time)

        app.logger.debug(f"Verifying phone code for user {self.id}. Submitted: '{code}', Stored: '{self.phone_verification_code}', Expires: {self.phone_verification_code_expires_at}, Current: {current_time}. Match: {is_code_match}, Not Expired: {is_not_expired}")

        if is_code_match and is_not_expired:
            self.phone_verification_code = None
            self.phone_verification_code_expires_at = None
            app.logger.info(f"Phone code verification successful for user {self.id}.")
            return True
        
        if self.phone_verification_code:
             app.logger.warning(f"Phone code verification FAILED for user {self.id}. Clearing code.")
             self.phone_verification_code = None 
             self.phone_verification_code_expires_at = None
        return False

    def get_password_reset_token(self, expires_in_seconds=600):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        self.password_reset_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in_seconds)
        return s.dumps(self.email, salt='password-reset-salt')

    @staticmethod
    def verify_password_reset_token(token, max_age_seconds=600):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            email = s.loads(token, salt='password-reset-salt', max_age=max_age_seconds)
        except (SignatureExpired, BadSignature) as e:
            app.logger.warning(f"Password reset token verification failed: {e}")
            return None
        
        user = User.query.filter_by(email=email).first()
        if user and user.password_reset_token_expires_at and \
           user.password_reset_token_expires_at < datetime.datetime.utcnow():
            app.logger.warning(f"Password reset token for {email} has expired based on DB record.")
            return None
        if not user:
             app.logger.warning(f"Password reset token valid for email {email} but no user found.")
             return None
        return user

    def set_languages(self, lang_list):
        if not lang_list:
            raise ValueError("Languages cannot be empty.") 
        self.languages = json.dumps(lang_list)

    def get_languages(self):
        if self.languages:
            try:
                return json.loads(self.languages)
            except (json.JSONDecodeError, TypeError):
                app.logger.error(f"Error decoding languages JSON for user {self.id}: {self.languages}")
                return []
        return []

    def __repr__(self):
        return f'<User {self.username} ({self.id})>'

# New Model for Memorization Progress
class MemorizationProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_memorizationprogress_user_id'), nullable=False) # Explicit FK name
    page_number_quran = db.Column(db.Integer, nullable=False) # Overall page number (1-604)
    juz_number = db.Column(db.Integer, nullable=False) # Store for easier querying
    
    mistakes_count = db.Column(db.Integer, default=0, nullable=False)
    is_memorized = db.Column(db.Boolean, default=False, nullable=False) # User's self-marking
    
    memorized_at = db.Column(db.DateTime, nullable=True) # When it was marked as memorized
    last_reviewed_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Relationship to User (added)
    user = db.relationship('User', backref=db.backref('progress_entries', lazy='dynamic'))

    # Unique constraint: a user can only have one entry per Quran page
    __table_args__ = (db.UniqueConstraint('user_id', 'page_number_quran', name='_user_page_uc'),)

    def __repr__(self):
        return f'<MemorizationProgress UserID:{self.user_id} Page:{self.page_number_quran} Memorized:{self.is_memorized} Mistakes:{self.mistakes_count}>'