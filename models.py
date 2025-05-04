from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    age = db.Column(db.Integer)
    phone_number = db.Column(db.String(20), unique=True, nullable=True)
    languages = db.Column(db.Text, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    role = db.Column(db.String(20), default='Memorizer', nullable=False) # 'Memorizer' or 'Listener'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_email_confirmation_token(self, salt='email-confirm-salt'):
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        return serializer.dumps(self.email, salt=salt)

    @staticmethod
    def verify_email_confirmation_token(token, salt='email-confirm-salt', max_age=3600):
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            email = serializer.loads(token, salt=salt, max_age=max_age)
        except Exception:
            return None
        return User.query.filter_by(email=email).first()

    def set_languages(self, lang_list):
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