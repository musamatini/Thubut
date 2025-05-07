# app.py
import os
import eventlet
eventlet.monkey_patch()

import datetime
import logging
import phonenumbers # For normalizing phone number before saving

from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app
from flask_socketio import SocketIO # emit, join_room, leave_room not used directly here
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

load_dotenv()

from models import db, User
# Updated form imports
from forms import SignupForm, LoginForm, VerificationCodeForm, PasswordResetRequestForm, ResetPasswordForm
# Updated util imports
from utils import send_email_verification_code, send_phone_verification_sms, send_password_reset_email

# App Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_default_fallback_secret_key_please_change')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///../instance/app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAILGUN_API_KEY'] = os.environ.get('MAILGUN_API_KEY')
app.config['MAILGUN_DOMAIN'] = os.environ.get('MAILGUN_DOMAIN')
app.config['MAILGUN_API_BASE_URL'] = os.environ.get('MAILGUN_API_BASE_URL', 'https://api.mailgun.net/v3')
app.config['MAILGUN_SENDER_NAME'] = os.environ.get('MAILGUN_SENDER_NAME', 'Thubut Team')

# Placeholder for Twilio or other SMS service config
app.config['TWILIO_ACCOUNT_SID'] = os.environ.get('TWILIO_ACCOUNT_SID')
app.config['TWILIO_AUTH_TOKEN'] = os.environ.get('TWILIO_AUTH_TOKEN')
app.config['TWILIO_PHONE_NUMBER'] = os.environ.get('TWILIO_PHONE_NUMBER')


# Initialize Extensions
db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please log in to access this page.'

@app.context_processor
def inject_now():
    return {'now': datetime.datetime.utcnow()}

@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        try:
            return User.query.get(int(user_id))
        except Exception as e:
            app.logger.error(f"Error loading user {user_id}: {e}")
            return None

socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*") # SocketIO remains

instance_path = app.instance_path
if not os.path.exists(instance_path):
    try:
        os.makedirs(instance_path)
        app.logger.info(f"Created instance folder at: {instance_path}")
    except OSError as e:
        app.logger.error(f"Error creating instance folder: {e}")

# --- Route Definitions ---

@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = SignupForm()
    if form.validate_on_submit():
        try:
            # Normalize phone number to E.164 before storing
            raw_phone = form.phone_number.data
            parsed_phone = phonenumbers.parse(raw_phone, None) # Assumes intl-tel-input provides full number
            e164_phone_number = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.E164)

            user = User(
                fullname=form.fullname.data,
                username=form.username.data,
                email=form.email.data.lower(),
                birthday=form.birthday.data,
                phone_number=e164_phone_number # Store normalized number
            )
            user.set_password(form.password.data)
            user.set_languages(form.languages.data) # This now expects a list
            
            email_code = user.set_email_verification_code()
            # phone_code = user.set_phone_verification_code() # Generate phone code too

            db.session.add(user)
            db.session.commit()

            send_email_verification_code(user, email_code)
            # send_phone_verification_sms(user, phone_code) # Send phone code via SMS

            flash('Account created! Please check your email for a verification code.', 'success')
            # Redirect to a page that tells them to check email AND phone, or directly to email verification
            session['signup_email_for_verification'] = user.email # Store email for pre-filling on verify page
            return redirect(url_for('verify_email')) # Changed from confirm_request
        except phonenumbers.phonenumberutil.NumberParseException:
            db.session.rollback()
            app.logger.error(f"Error during signup: Invalid phone number format for {form.phone_number.data}")
            flash('Invalid phone number format. Please use international format (e.g., +12223334444).', 'danger')
        except ValueError as ve: # Catch specific errors like empty languages
             db.session.rollback()
             app.logger.error(f"Error during signup for {form.email.data}: {ve}", exc_info=True)
             flash(str(ve), 'danger') # Show the specific error from User model
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during signup for {form.email.data}: {e}", exc_info=True)
            flash('An error occurred during signup. Please try again.', 'danger')
    elif request.method == 'POST':
         app.logger.warning(f"Signup form validation failed: {form.errors}")
    return render_template('auth/signup.html', title='Sign Up', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            if not user.email_confirmed:
                 flash('Please confirm your email address first. Enter the code sent to your email.', 'warning')
                 session['signup_email_for_verification'] = user.email
                 return redirect(url_for('verify_email'))

            # Optionally, check for phone confirmation too if it becomes mandatory for login
            # if not user.phone_confirmed:
            #     flash('Please confirm your phone number.', 'warning')
            #     session['user_id_for_phone_verification'] = user.id
            #     return redirect(url_for('verify_phone'))

            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('auth/login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

# Removed old /confirm_request and /confirm/<token> routes

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    form = VerificationCodeForm()
    email_to_verify = session.get('signup_email_for_verification')
    user_to_verify = None

    if current_user.is_authenticated and not current_user.email_confirmed:
        user_to_verify = current_user
        email_to_verify = current_user.email
    elif email_to_verify:
        user_to_verify = User.query.filter_by(email=email_to_verify).first()

    if not user_to_verify:
        flash('No email found for verification. Please sign up or log in.', 'warning')
        return redirect(url_for('signup'))
    
    if user_to_verify.email_confirmed:
        flash('Your email is already confirmed.', 'info')
        if 'signup_email_for_verification' in session: # Clear session variable
            session.pop('signup_email_for_verification', None)
        return redirect(url_for('login'))

    if form.validate_on_submit():
        if user_to_verify.verify_email_code(form.code.data):
            try:
                db.session.commit()
                flash('Your email has been confirmed! You can now log in.', 'success')
                if 'signup_email_for_verification' in session:
                    session.pop('signup_email_for_verification', None)
                
                # Log in the user if they aren't already
                if not current_user.is_authenticated:
                    login_user(user_to_verify)
                    return redirect(url_for('dashboard'))
                return redirect(url_for('login')) # Or dashboard if already logged in and just verifying
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error saving email confirmation for {user_to_verify.email}: {e}", exc_info=True)
                flash('An error occurred. Please try again.', 'danger')
        else:
            flash('Invalid or expired verification code. Please try again or request a new one.', 'danger')
    
    return render_template('auth/verify_email.html', title='Verify Email', form=form, email=email_to_verify)


@app.route('/resend_verification_email', methods=['POST'])
def resend_verification_email():
    email = request.form.get('email')
    if not email:
        flash('Email address is required to resend verification.', 'warning')
        return redirect(url_for('verify_email'))

    user = User.query.filter_by(email=email.lower()).first()
    if user:
        if user.email_confirmed:
            flash('This email is already confirmed.', 'info')
            return redirect(url_for('login'))
        
        new_code = user.set_email_verification_code()
        try:
            db.session.commit()
            send_email_verification_code(user, new_code)
            flash('A new verification code has been sent to your email.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error resending verification email for {user.email}: {e}", exc_info=True)
            flash('Could not resend verification code. Please try again later.', 'danger')
    else:
        flash('No account found with that email address.', 'warning')
    return redirect(url_for('verify_email'))


# --- Phone Verification (Basic Structure) ---
@app.route('/verify_phone', methods=['GET', 'POST'])
@login_required # Typically user is logged in for this
def verify_phone():
    # This route is more for users who are already logged in and want to verify/change phone
    # Or if phone verification is mandatory after email verification.
    form = VerificationCodeForm()
    user = current_user

    if user.phone_confirmed:
        flash('Your phone number is already confirmed.', 'info')
        return redirect(url_for('dashboard'))

    if not user.phone_number:
        flash('You need to add a phone number to your profile first.', 'warning')
        return redirect(url_for('dashboard')) # Or a profile edit page

    if form.validate_on_submit():
        if user.verify_phone_code(form.code.data):
            try:
                db.session.commit()
                flash('Your phone number has been confirmed!', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error saving phone confirmation for {user.username}: {e}", exc_info=True)
                flash('An error occurred during phone verification. Please try again.', 'danger')
        else:
            flash('Invalid or expired phone verification code.', 'danger')
    
    return render_template('auth/verify_phone.html', title='Verify Phone Number', form=form, phone_number=user.phone_number)

@app.route('/resend_phone_code', methods=['POST'])
@login_required
def resend_phone_code():
    user = current_user
    if user.phone_confirmed:
        flash('Phone already confirmed.', 'info')
    elif user.phone_number:
        new_code = user.set_phone_verification_code()
        try:
            db.session.commit()
            send_phone_verification_sms(user, new_code) # Actual SMS sending
            flash('A new verification code has been sent to your phone.', 'success')
        except Exception as e:
            db.session.rollback()
            # Log error
            flash('Could not resend phone code.', 'danger')
    else:
        flash('No phone number on record to send code to.', 'warning')
    return redirect(url_for('verify_phone'))


# --- Password Reset Routes ---
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request_route():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            token = user.get_password_reset_token()
            # In a real app, you'd also save user.password_reset_token_expires_at to db.session.commit() here
            # if your get_password_reset_token method doesn't do it.
            # My User.get_password_reset_token doesn't save to DB, the verification will check expiry.
            # It's better to save expiry:
            user.password_reset_token = token # If you decide to store the token itself
            # user.password_reset_token_expires_at is set in get_password_reset_token
            db.session.commit() # Save expiry if you do this.
            
            send_password_reset_email(user, token)
            flash('An email has been sent with instructions to reset your password.', 'info')
        else:
            # Don't reveal if email exists for security, generic message
            flash('If an account with that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('auth/reset_password_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token_route(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    user = User.verify_password_reset_token(token)
    if not user:
        flash('That is an invalid or expired password reset token.', 'warning')
        return redirect(url_for('reset_password_request_route'))
    
    # Additional check: if user.password_reset_token_expires_at < datetime.datetime.utcnow():
    #    flash('Token expired.', 'warning')
    #    return redirect(url_for('reset_password_request_route'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.password_reset_token = None # Invalidate token
        user.password_reset_token_expires_at = None
        try:
            db.session.commit()
            flash('Your password has been reset successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error resetting password for {user.email}: {e}", exc_info=True)
            flash('An error occurred while resetting your password. Please try again.', 'danger')
    return render_template('auth/reset_password_token.html', title='Reset Your Password', form=form, token=token)


# --- Main Application Routes ---
@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.email_confirmed:
        flash('Please confirm your email address to access all features.', 'warning')
        # Optionally, redirect to verification page or just show warning.
    # if not current_user.phone_confirmed: # If phone verification is important
    #     flash('Please confirm your phone number.', 'warning')
    return render_template('dashboard.html', title='Dashboard')

@app.route('/call')
@login_required
def call():
     if not current_user.email_confirmed:
        flash('Please confirm your email address before joining a call.', 'warning')
        return redirect(url_for('dashboard'))
     return render_template('call.html', title='Voice Call')

# --- Error Handlers (remain the same) ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    try:
        db.session.rollback()
        app.logger.error("Rolled back database session due to internal error.")
    except Exception as e:
        app.logger.error(f"Error rolling back database session: {e}")
    app.logger.error(f"Internal Server Error: {error}", exc_info=True)
    return render_template('errors/500.html'), 500


# --- SocketIO Event Handlers (remain the same) ---
# ... (Your existing SocketIO handlers: on_connect, on_disconnect, on_join, etc.) ...
# Ensure loggers and current_user checks are robust as in your original.
# I'll copy a few key ones to show they are still there.

rooms_data = {} # Assuming this is still used globally for SocketIO

@socketio.on('connect')
def on_connect():
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    if current_user.is_authenticated:
        logger.info(f"Authenticated client connected: {current_user.username} ({request.sid})")
        if not current_user.email_confirmed: # Added check
            socketio.emit('auth_status', {'email_confirmed': False}, room=request.sid)
    else:
        logger.warning(f"Unauthenticated client connected: {request.sid}")
        socketio.emit('auth_status', {'authenticated': False}, room=request.sid)


# ... Your other socketio handlers ...
# Make sure they check current_user.is_authenticated and current_user.email_confirmed
# before allowing actions like 'join_call'.

# --- Flask CLI Commands (remain the same) ---
@app.cli.command('db-create')
def db_create_command(): # Renamed to avoid conflict with function name 'db_create'
    """Creates database tables."""
    with app.app_context():
        try:
            db.create_all()
            print('Database tables created!')
        except Exception as e:
            print(f"Error creating database tables: {e}")

@app.cli.command('db-drop')
def db_drop_command(): # Renamed
    """Drops all database tables."""
    if input('Are you sure you want to drop all tables? (y/N): ').lower() == 'y':
        with app.app_context():
             try:
                 db.drop_all()
                 print('Database tables dropped!')
             except Exception as e:
                 print(f"Error dropping database tables: {e}")
    else:
        print('Aborted.')

# --- Main Execution (remains largely the same) ---
if __name__ == '__main__':
    print("Starting Thubut server...")
    log_level = logging.DEBUG if os.environ.get('FLASK_DEBUG', 'False').lower() == 'true' else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 10000))
    use_flask_debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    print(f"Attempting to start SocketIO server on {host}:{port}")
    try:
        socketio.run(app, host=host, port=port, use_reloader=False, log_output=use_flask_debug, debug=use_flask_debug)
    except Exception as e:
         logging.error(f"Failed to start SocketIO server: {e}", exc_info=True)