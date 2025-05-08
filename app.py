import eventlet
eventlet.monkey_patch() # IMPORTANT: Must be the very first effective line
import os
import datetime
import logging
import phonenumbers

from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app, jsonify # Added jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

load_dotenv()

# Adjusted model import to include MemorizationProgress
from models import db, User, MemorizationProgress
from forms import SignupForm, LoginForm, VerificationCodeForm, PasswordResetRequestForm, ResetPasswordForm
from utils import send_email_verification_code, send_phone_verification_sms, send_password_reset_email

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_default_fallback_secret_key_please_change')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///../instance/app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAILGUN_API_KEY'] = os.environ.get('MAILGUN_API_KEY')
app.config['MAILGUN_DOMAIN'] = os.environ.get('MAILGUN_DOMAIN')
app.config['MAILGUN_API_BASE_URL'] = os.environ.get('MAILGUN_API_BASE_URL', 'https://api.mailgun.net/v3')
app.config['MAILGUN_SENDER_NAME'] = os.environ.get('MAILGUN_SENDER_NAME', 'Thubut Team')

app.config['TWILIO_ACCOUNT_SID'] = os.environ.get('TWILIO_ACCOUNT_SID')
app.config['TWILIO_AUTH_TOKEN'] = os.environ.get('TWILIO_AUTH_TOKEN')
app.config['TWILIO_PHONE_NUMBER'] = os.environ.get('TWILIO_PHONE_NUMBER')

app.config['RAPIDAPI_KEY'] = os.environ.get('RAPIDAPI_KEY')
app.config['RAPIDAPI_SMS_VERIFY_HOST'] = os.environ.get('RAPIDAPI_SMS_VERIFY_HOST', 'sms-verify3.p.rapidapi.com')

db.init_app(app)
csrf = CSRFProtect(app) # CSRF protection for forms and AJAX POST if needed

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please log in to access this page.'

# --- Quran Structure Constants and Helpers ---
QURAN_TOTAL_PAGES = 604
_QURAN_JUZ_INFO_LIST = [
    {'juz': 1, 'start_page': 1, 'num_pages': 21}, {'juz': 2, 'start_page': 22, 'num_pages': 20},
    {'juz': 3, 'start_page': 42, 'num_pages': 20}, {'juz': 4, 'start_page': 62, 'num_pages': 20},
    {'juz': 5, 'start_page': 82, 'num_pages': 20}, {'juz': 6, 'start_page': 102, 'num_pages': 20},
    {'juz': 7, 'start_page': 122, 'num_pages': 20}, {'juz': 8, 'start_page': 142, 'num_pages': 20},
    {'juz': 9, 'start_page': 162, 'num_pages': 20}, {'juz': 10, 'start_page': 182, 'num_pages': 20},
    {'juz': 11, 'start_page': 202, 'num_pages': 20}, {'juz': 12, 'start_page': 222, 'num_pages': 20},
    {'juz': 13, 'start_page': 242, 'num_pages': 20}, {'juz': 14, 'start_page': 262, 'num_pages': 20},
    {'juz': 15, 'start_page': 282, 'num_pages': 20}, {'juz': 16, 'start_page': 302, 'num_pages': 20},
    {'juz': 17, 'start_page': 322, 'num_pages': 20}, {'juz': 18, 'start_page': 342, 'num_pages': 20},
    {'juz': 19, 'start_page': 362, 'num_pages': 20}, {'juz': 20, 'start_page': 382, 'num_pages': 20},
    {'juz': 21, 'start_page': 402, 'num_pages': 20}, {'juz': 22, 'start_page': 422, 'num_pages': 20},
    {'juz': 23, 'start_page': 442, 'num_pages': 20}, {'juz': 24, 'start_page': 462, 'num_pages': 20},
    {'juz': 25, 'start_page': 482, 'num_pages': 20}, {'juz': 26, 'start_page': 502, 'num_pages': 20},
    {'juz': 27, 'start_page': 522, 'num_pages': 20}, {'juz': 28, 'start_page': 542, 'num_pages': 20},
    {'juz': 29, 'start_page': 562, 'num_pages': 20}, {'juz': 30, 'start_page': 582, 'num_pages': 23}
]

QURAN_JUZ_INFO_MAP = {
    item['juz']: {
        'start_page': item['start_page'],
        'num_pages': item['num_pages'],
        'end_page': item['start_page'] + item['num_pages'] - 1
    }
    for item in _QURAN_JUZ_INFO_LIST
}

def get_juz_for_page(page_number_quran):
    for juz_info_item in _QURAN_JUZ_INFO_LIST:
        if juz_info_item['start_page'] <= page_number_quran < juz_info_item['start_page'] + juz_info_item['num_pages']:
            return juz_info_item['juz']
    return None

def get_pages_in_juz(juz_number):
    if juz_number in QURAN_JUZ_INFO_MAP:
        info = QURAN_JUZ_INFO_MAP[juz_number]
        return list(range(info['start_page'], info['end_page'] + 1))
    return []

def get_page_number_within_juz(page_number_quran):
    juz_num = get_juz_for_page(page_number_quran)
    if juz_num and juz_num in QURAN_JUZ_INFO_MAP:
        juz_start_page = QURAN_JUZ_INFO_MAP[juz_num]['start_page']
        return page_number_quran - juz_start_page + 1 # 1-indexed
    return None
# --- End Quran Structure ---

@app.context_processor
def inject_now():
    return {'now': datetime.datetime.utcnow()}

@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        try:
            return db.session.get(User, int(user_id))
        except Exception as e:
            app.logger.error(f"Error loading user {user_id}: {e}")
            return None

socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

rooms_data = {}
user_states_in_rooms = {}

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
            raw_phone = form.phone_number.data
            e164_phone_number = None
            if raw_phone:
                parsed_phone = phonenumbers.parse(raw_phone, None) # Region None for international numbers
                if phonenumbers.is_valid_number(parsed_phone):
                     e164_phone_number = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.E164)
                else: # Form validator should catch this, but as a fallback
                    flash('Invalid phone number format. Please ensure it is correct and includes a country code.', 'danger')
                    return render_template('auth/signup.html', title='Sign Up', form=form)


            user = User(
                fullname=form.fullname.data,
                username=form.username.data,
                email=form.email.data.lower(),
                birthday=form.birthday.data,
                phone_number=e164_phone_number
            )
            user.set_password(form.password.data)
            user.set_languages(form.languages.data)
            email_code = user.set_email_verification_code()
            db.session.add(user)
            db.session.commit()

            send_email_verification_code(user, email_code)

            flash_message = 'Account created! Please check your email for a verification code.'
            if user.phone_number:
                flash_message += ' If you provided a phone number, you will be prompted to verify it after email confirmation.'
            flash(flash_message, 'success')
            session['signup_email_for_verification'] = user.email
            return redirect(url_for('verify_email'))

        except phonenumbers.phonenumberutil.NumberParseException:
            db.session.rollback()
            app.logger.error(f"Error during signup: Invalid phone number format for {form.phone_number.data}")
            flash('Invalid phone number format. Please use international format (e.g., +12223334444).', 'danger')
        except ValueError as ve:
             db.session.rollback()
             app.logger.error(f"Error during signup for {form.email.data}: {ve}", exc_info=True)
             flash(str(ve), 'danger')
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
        user_from_db = User.query.filter_by(email=form.email.data.lower()).first()
        if user_from_db and user_from_db.check_password(form.password.data):
            login_user(user_from_db, remember=form.remember.data)

            if not current_user.email_confirmed:
                 session['signup_email_for_verification'] = user_from_db.email
                 logout_user() 
                 flash('Your email address is not verified. Please check your inbox or use the verification page to get a new code.', 'warning')
                 return redirect(url_for('verify_email'))

            if current_user.phone_number and not current_user.phone_confirmed:
                flash('Please confirm your phone number to complete login. A code is being sent.', 'warning')
                send_phone_verification_sms(current_user)
                return redirect(url_for('verify_phone')) 

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

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    form = VerificationCodeForm()
    email_to_verify = session.get('signup_email_for_verification')
    user_to_verify = None

    if current_user.is_authenticated and not current_user.email_confirmed:
        user_to_verify = current_user
    elif email_to_verify:
        user_to_verify = User.query.filter_by(email=email_to_verify).first()

    if not user_to_verify:
        flash('No email found for verification. Please sign up or log in.', 'warning')
        return redirect(url_for('signup'))
    
    if user_to_verify.email_confirmed:
        flash('Your email is already confirmed.', 'info')
        if 'signup_email_for_verification' in session:
            session.pop('signup_email_for_verification', None)
        return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('login'))

    if form.validate_on_submit():
        if user_to_verify.verify_email_code(form.code.data):
            try:
                db.session.add(user_to_verify) 
                db.session.commit()
                flash('Your email has been confirmed!', 'success')
                if 'signup_email_for_verification' in session:
                    session.pop('signup_email_for_verification', None)
                
                if not current_user.is_authenticated or current_user.id != user_to_verify.id:
                    login_user(user_to_verify) 
                elif current_user.id == user_to_verify.id and not current_user.email_confirmed:
                    login_user(user_to_verify, force=True)
                
                if current_user.phone_number and not current_user.phone_confirmed:
                    send_phone_verification_sms(current_user)
                    return redirect(url_for('verify_phone'))
                
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"[verify_email] Error saving email confirmation for {user_to_verify.email}: {e}", exc_info=True)
                flash('An error occurred. Please try again.', 'danger')
        else:
            flash('Invalid or expired verification code. Please try again or request a new one.', 'danger')
    
    return render_template('auth/verify_email.html', title='Verify Email', form=form, email=user_to_verify.email)

@app.route('/resend_verification_email', methods=['POST'])
def resend_verification_email():
    email = request.form.get('email') 
    if not email:
        email = session.get('signup_email_for_verification')
        if not email and current_user.is_authenticated and not current_user.email_confirmed:
            email = current_user.email

    if not email:
        flash('Could not determine email address to resend verification.', 'danger')
        return redirect(url_for('login'))

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
    
    if email:
        session['signup_email_for_verification'] = email
    return redirect(url_for('verify_email'))

@app.route('/verify_phone', methods=['GET', 'POST'])
@login_required
def verify_phone():
    form = VerificationCodeForm()
    user = db.session.get(User, int(current_user.get_id()))
    if not user:
        flash('An unexpected error occurred. Please try again.', 'danger')
        return redirect(url_for('login'))

    if not user.phone_number:
        flash('You do not have a phone number registered.', 'warning')
        return redirect(url_for('dashboard'))

    if user.phone_confirmed:
        flash('Your phone number is already confirmed.', 'info')
        return redirect(url_for('dashboard'))

    if form.validate_on_submit():
        if user.verify_phone_code(form.code.data):
            try:
                user.phone_confirmed = True
                db.session.commit()
                login_user(user, force=True) 
                flash('Your phone number has been confirmed!', 'success')
                
                if not user.email_confirmed: 
                    flash('Phone confirmed! Please also verify your email.', 'info')
                    session['signup_email_for_verification'] = user.email
                    return redirect(url_for('verify_email'))
                else:
                    flash('All required verifications complete! Welcome!', 'success')
                    return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"[verify_phone] Error during phone confirmation logic for {user.username if user else 'UNKNOWN USER'}: {e}", exc_info=True)
                flash('An error occurred during phone verification. Please try again.', 'danger')
        else:
            flash('Invalid or expired phone verification code.', 'danger')
    
    return render_template('auth/verify_phone.html', title='Verify Phone Number', form=form, phone_number=user.phone_number)

@app.route('/resend_phone_code', methods=['POST'])
@login_required
def resend_phone_code():
    user = current_user
    if not user.phone_number:
        flash('No phone number on record to send a code to.', 'warning')
        return redirect(url_for('dashboard'))

    if user.phone_confirmed:
        flash('Your phone number is already confirmed.', 'info')
        return redirect(url_for('dashboard'))
        
    send_phone_verification_sms(user) # This now uses user.id
    flash('A new verification code is being sent to your phone. Please wait a moment.', 'success')
    return redirect(url_for('verify_phone'))

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request_route():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            token = user.get_password_reset_token()
            db.session.commit() # Save password_reset_token_expires_at
            send_password_reset_email(user, token)
            flash('An email has been sent with instructions to reset your password.', 'info')
        else:
            flash('If an account with that email exists, a reset link has been sent.', 'info') # Generic message for privacy
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
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.password_reset_token_expires_at = None # Clear expiry after successful reset
        try:
            db.session.commit()
            flash('Your password has been reset successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error resetting password for {user.email}: {e}", exc_info=True)
            flash('An error occurred while resetting your password. Please try again.', 'danger')
    return render_template('auth/reset_password_token.html', title='Reset Your Password', form=form, token=token)

@app.route('/dashboard')
@login_required
def dashboard():
    app.logger.info(f"[dashboard] Entered. User: {current_user.email} (ID: {current_user.id}). Email_confirmed: {current_user.email_confirmed}, Phone_confirmed: {current_user.phone_confirmed}, Has Phone: {bool(current_user.phone_number)}")

    if not current_user.email_confirmed:
        flash('Please verify your email address to access the dashboard.', 'warning')
        session['signup_email_for_verification'] = current_user.email
        return redirect(url_for('verify_email'))
    
    if current_user.phone_number and not current_user.phone_confirmed:
        flash('Please verify your phone number to access the dashboard.', 'warning')
        return redirect(url_for('verify_phone'))
    
    # --- Progress Tracking Data Calculation ---
    user_progress_entries = MemorizationProgress.query.filter_by(user_id=current_user.id).all()
    progress_map = {entry.page_number_quran: entry for entry in user_progress_entries}

    memorized_pages_count = sum(1 for entry in user_progress_entries if entry.is_memorized)
    overall_quran_progress_percent = (memorized_pages_count / QURAN_TOTAL_PAGES) * 100 if QURAN_TOTAL_PAGES > 0 else 0

    juz_progress_data = []
    for juz_num_iter in range(1, 31): # Iterate 1 to 30
        juz_info = QURAN_JUZ_INFO_MAP.get(juz_num_iter)
        if not juz_info:
            app.logger.error(f"Missing juz_info for juz_num_iter {juz_num_iter}")
            continue

        pages_in_this_juz = get_pages_in_juz(juz_num_iter)
        memorized_pages_in_juz_count = 0
        for page_quran_num in pages_in_this_juz:
            entry = progress_map.get(page_quran_num)
            if entry and entry.is_memorized:
                memorized_pages_in_juz_count += 1
        
        juz_completion_percent = (memorized_pages_in_juz_count / juz_info['num_pages']) * 100 if juz_info['num_pages'] > 0 else 0
        
        juz_progress_data.append({
            'juz_number': juz_num_iter,
            'completion_percent': round(juz_completion_percent, 1),
            'total_pages': juz_info['num_pages'],
            'memorized_pages': memorized_pages_in_juz_count
        })
    # --- End Progress Tracking Data ---
    
    app.logger.info(f"[dashboard] User {current_user.id} passed all verification checks. Rendering dashboard.")
    return render_template('dashboard.html', title='Dashboard',
                           overall_quran_progress_percent=round(overall_quran_progress_percent, 1),
                           juz_progress_data=juz_progress_data,
                           QURAN_TOTAL_PAGES=QURAN_TOTAL_PAGES)


# --- API Endpoints for Progress Tracking ---
@app.route('/api/progress/juz/<int:juz_number>')
@login_required
def get_juz_page_details(juz_number):
    if not (1 <= juz_number <= 30):
        return jsonify({'error': 'Invalid Juz number'}), 400

    juz_info = QURAN_JUZ_INFO_MAP.get(juz_number)
    if not juz_info: # Should not happen with valid juz_number
        return jsonify({'error': 'Juz info not found'}), 404

    pages_quran_numbers_in_juz = get_pages_in_juz(juz_number)
    
    user_progress_for_juz = MemorizationProgress.query.filter(
        MemorizationProgress.user_id == current_user.id,
        MemorizationProgress.page_number_quran.in_(pages_quran_numbers_in_juz)
    ).all()
    
    progress_map = {entry.page_number_quran: entry for entry in user_progress_for_juz}
    
    page_details_list = []
    for i, page_quran_num in enumerate(pages_quran_numbers_in_juz):
        page_num_in_juz_display = i + 1 # 1-indexed for display
        entry = progress_map.get(page_quran_num)
        
        mistakes = 0
        is_memorized_flag = False
        status_color = 'grey' # Default for not memorized or no data

        if entry: # If there's any record for this page
            mistakes = entry.mistakes_count
            is_memorized_flag = entry.is_memorized
            if entry.is_memorized:
                if mistakes == 0:
                    status_color = 'green'
                elif 1 <= mistakes <= 3:
                    status_color = 'orange'
                else: # more than three
                    status_color = 'red'
            # else, it remains 'grey' as it's not marked memorized
        
        page_details_list.append({
            'page_number_quran': page_quran_num,
            'page_number_in_juz': page_num_in_juz_display,
            'is_memorized': is_memorized_flag,
            'mistakes_count': mistakes,
            'status_color': status_color
        })
           
    return jsonify({
        'juz_number': juz_number,
        'num_pages_in_juz': juz_info['num_pages'],
        'pages': page_details_list
    })

@app.route('/api/progress/mark_page_memorized/<int:page_number_quran>', methods=['POST'])
@login_required
def mark_page_memorized(page_number_quran):
    if not (1 <= page_number_quran <= QURAN_TOTAL_PAGES):
        return jsonify({'error': 'Invalid Quran page number'}), 400

    juz_num_for_page = get_juz_for_page(page_number_quran)
    if not juz_num_for_page:
        return jsonify({'error': 'Could not determine Juz for page'}), 400

    progress_entry = MemorizationProgress.query.filter_by(
        user_id=current_user.id,
        page_number_quran=page_number_quran
    ).first()

    if not progress_entry:
        progress_entry = MemorizationProgress(
            user_id=current_user.id,
            page_number_quran=page_number_quran,
            juz_number=juz_num_for_page,
            is_memorized=True,
            memorized_at=datetime.datetime.utcnow(),
            mistakes_count=0 # Default to 0 mistakes when self-marking
        )
        db.session.add(progress_entry)
    else:
        progress_entry.is_memorized = True
        progress_entry.memorized_at = datetime.datetime.utcnow()
        progress_entry.mistakes_count = 0 # Reset mistakes on self-re-affirmation of memorization

    try:
        db.session.commit()
        return jsonify({'success': True, 'message': f'Page {page_number_quran} marked as memorized.'}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error marking page {page_number_quran} memorized for user {current_user.id}: {e}")
        return jsonify({'error': 'Could not update progress.'}), 500

@app.route('/api/progress/unmark_page_memorized/<int:page_number_quran>', methods=['POST'])
@login_required
def unmark_page_memorized(page_number_quran):
    progress_entry = MemorizationProgress.query.filter_by(
        user_id=current_user.id,
        page_number_quran=page_number_quran
    ).first()

    if progress_entry:
        progress_entry.is_memorized = False
        # progress_entry.memorized_at = None # Optional: clear memorized_at
        # Keep mistake_count as is, or reset? For now, keep.
        try:
            db.session.commit()
            return jsonify({'success': True, 'message': f'Page {page_number_quran} unmarked.'}), 200
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error unmarking page {page_number_quran} for user {current_user.id}: {e}")
            return jsonify({'error': 'Could not update progress.'}), 500
    return jsonify({'error': 'Progress entry not found for this page and user.'}), 404
# --- End API Endpoints ---


@app.route('/call')
@login_required
def call():
    app.logger.info(f"[call] Entered. User: {current_user.email} (ID: {current_user.id}).")
    if not current_user.email_confirmed:
        flash('Please confirm your email address before making/joining a call.', 'warning')
        return redirect(url_for('verify_email'))
    if current_user.phone_number and not current_user.phone_confirmed:
        flash('Please verify your phone number before making/joining calls.', 'warning')
        return redirect(url_for('verify_phone'))
    # Removed hard requirement for phone number for calls, as per original description for Listeners (only voice interview).
    # Memorizers just need basic verification.
    # if not current_user.phone_number:
    #     flash('A verified phone number is required to make/join calls. Please add and verify one in your profile.', 'warning')
    #     return redirect(url_for('dashboard')) 

    app.logger.info(f"[call] User {current_user.id} passed checks for call. Rendering call page.")
    return render_template('call.html', title='Voice Call')


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

# --- SocketIO Event Handlers ---
# (SocketIO handlers remain unchanged from your provided code)
@socketio.on('connect')
def on_connect(auth=None): 
    logger = current_app.logger
    if current_user.is_authenticated:
        logger.info(f"Authenticated client connected: {current_user.username} ({request.sid})")
        auth_status_payload = {'authenticated': True, 'email_confirmed': current_user.email_confirmed}
        if not current_user.email_confirmed:
            auth_status_payload['message'] = 'Email not verified.'
            logger.warning(f"User {current_user.username} connected via SocketIO but email not verified.")
        
        # Add phone status if phone exists
        if current_user.phone_number:
            auth_status_payload['phone_exists'] = True
            auth_status_payload['phone_confirmed'] = current_user.phone_confirmed
            if not current_user.phone_confirmed:
                 auth_status_payload['message'] = auth_status_payload.get('message', '') + ' Phone not verified.'
        else:
            auth_status_payload['phone_exists'] = False
        
        emit('auth_status', auth_status_payload, room=request.sid)
    else:
        logger.warning(f"Unauthenticated client connected: {request.sid}")
        emit('auth_status', {'authenticated': False, 'message': 'Not authenticated.'}, room=request.sid)

@socketio.on('disconnect')
def on_disconnect(*args):
    logger = current_app.logger
    logger.info(f"Client disconnected: {request.sid}")
    
    sid_to_remove = request.sid
    for room_id, sids_in_room in list(rooms_data.items()):
        if sid_to_remove in sids_in_room:
            sids_in_room.remove(sid_to_remove)
            logger.info(f"User {sid_to_remove} removed from room {room_id}. Users remaining: {len(sids_in_room)}")
            if not sids_in_room:
                del rooms_data[room_id]
                if room_id in user_states_in_rooms:
                    del user_states_in_rooms[room_id]
                logger.info(f"Room {room_id} is now empty and removed.")
            else:
                emit('peer_left', {'sid': sid_to_remove, 'room': room_id}, room=room_id, include_self=False)
                if room_id in user_states_in_rooms and sid_to_remove in user_states_in_rooms[room_id]:
                    del user_states_in_rooms[room_id][sid_to_remove]
            break

@socketio.on('join_call')
def on_join_call(data):
    logger = current_app.logger
    if not current_user.is_authenticated:
        logger.warning(f"Unauthenticated user {request.sid} attempted to join call.")
        emit('error_joining', {'message': 'Authentication required to join a call.'})
        return

    if not current_user.email_confirmed:
        logger.warning(f"User {current_user.username} ({request.sid}) attempted to join call with unverified email.")
        emit('error_joining', {'message': 'Email verification required to join a call.'})
        return
    
    room_id = data.get('room')
    if not room_id:
        logger.warning(f"User {request.sid} tried to join without specifying a room.")
        emit('error_joining', {'message': 'Room ID is required.'})
        return

    join_room(room_id)
    logger.info(f"User {current_user.username} ({request.sid}) joined room: {room_id}")

    if room_id not in rooms_data: rooms_data[room_id] = set()
    if room_id not in user_states_in_rooms: user_states_in_rooms[room_id] = {}

    other_sids_in_room = list(rooms_data[room_id])
    rooms_data[room_id].add(request.sid)
    user_states_in_rooms[room_id][request.sid] = {"speaking": False, "muted": False, "username": current_user.username}

    if other_sids_in_room:
        emit('existing_peers', {'sids': other_sids_in_room, 'room': room_id}, room=request.sid)
    emit('peer_joined', {'sid': request.sid, 'username': current_user.username, 'room': room_id}, room=room_id, include_self=False)

@socketio.on('leave_call')
def on_leave_call(data):
    logger = current_app.logger
    if not current_user.is_authenticated: return

    room_id = data.get('room')
    if not room_id: return

    if room_id in rooms_data and request.sid in rooms_data[room_id]:
        leave_room(room_id)
        rooms_data[room_id].remove(request.sid)
        logger.info(f"User {current_user.username} ({request.sid}) left room: {room_id}")

        if room_id in user_states_in_rooms and request.sid in user_states_in_rooms[room_id]:
            del user_states_in_rooms[room_id][request.sid]

        emit('peer_left', {'sid': request.sid, 'room': room_id}, room=room_id, include_self=False)

        if not rooms_data[room_id]:
            del rooms_data[room_id]
            if room_id in user_states_in_rooms: del user_states_in_rooms[room_id]
            logger.info(f"Room {room_id} is now empty and removed after user left.")

@socketio.on('signal')
def on_signal(data):
    logger = current_app.logger
    if not current_user.is_authenticated: return

    to_sid = data.get('to_sid')
    signal_payload = data.get('signal')
    if not to_sid or signal_payload is None: return
    emit('signal', {'from_sid': request.sid, 'signal': signal_payload}, room=to_sid)

@socketio.on('speaking_status')
def on_speaking_status(data):
    logger = current_app.logger
    if not current_user.is_authenticated: return

    room_id = data.get('room')
    speaking = data.get('speaking')
    if room_id is None or speaking is None: return

    if room_id in rooms_data and request.sid in rooms_data[room_id]:
        if room_id in user_states_in_rooms and request.sid in user_states_in_rooms[room_id]:
            user_states_in_rooms[room_id][request.sid]['speaking'] = speaking
        emit('speaking_status', {'sid': request.sid, 'speaking': speaking, 'room': room_id}, room=room_id, include_self=False)

@socketio.on('remote_mute_request')
def on_remote_mute_request(data):
    logger = current_app.logger
    if not current_user.is_authenticated: return

    room_id = data.get('room')
    target_sid = data.get('target_sid')
    if not room_id or not target_sid: return

    if room_id in rooms_data and request.sid in rooms_data[room_id] and target_sid in rooms_data[room_id]:
        emit('force_mute', {'requester_sid': request.sid, 'room': room_id}, room=target_sid)
# --- End SocketIO ---

# --- Flask CLI Commands ---
@app.cli.command('db-create')
def db_create_command():
    with app.app_context():
        try:
            db.create_all()
            print('Database tables created!')
        except Exception as e:
            print(f"Error creating database tables: {e}")

@app.cli.command('db-drop')
def db_drop_command():
    if input('Are you sure you want to drop all tables? (y/N): ').lower() == 'y':
        with app.app_context():
             try:
                 db.drop_all()
                 print('Database tables dropped!')
             except Exception as e:
                 print(f"Error dropping database tables: {e}")
    else:
        print('Aborted.')

# --- Main Execution ---
if __name__ == '__main__':
    print("Starting Thubut server...")
    log_level = logging.DEBUG if os.environ.get('FLASK_DEBUG', 'False').lower() == 'true' else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 10000))
    use_flask_debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    print(f"Attempting to start SocketIO server on {host}:{port}")
    try:
        socketio.run(app, host=host, port=port, use_reloader=use_flask_debug, log_output=True, debug=use_flask_debug)
    except Exception as e:
         logging.error(f"Failed to start SocketIO server: {e}", exc_info=True)