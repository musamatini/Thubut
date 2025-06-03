# app.py
import eventlet
eventlet.monkey_patch() # IMPORTANT: Must be the very first effective line
import os
import datetime
import logging
import phonenumbers

from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

load_dotenv()

# MODIFIED: Added UserJuzProgress, UserPageRecord
from models import db, User, UserJuzProgress, UserPageRecord 
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
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please log in to access this page.'

# --- Quran Structure Constants ---
# For simplicity, assuming 20 pages per Juzz.
# A more accurate mapping would be:
# JUZ_PAGES_COUNT = {
#     1: 21, 2: 20, 3: 20, 4: 20, 5: 20, 6: 20, 7: 20, 8: 20, 9: 20, 10: 20,
#     11: 20, 12: 20, 13: 20, 14: 20, 15: 20, 16: 20, 17: 20, 18: 20, 19: 20, 20: 20,
#     21: 20, 22: 20, 23: 20, 24: 20, 25: 20, 26: 20, 27: 20, 28: 20, 29: 20, 30: 23
# }
# For this implementation, we'll use a default for display simplicity in grids.
# The number of squares on the Juzz detail page will be based on this.
DEFAULT_PAGES_PER_JUZ = 20
NUMBER_OF_JUZ = 30

# This function provides the number of pages for a given Juzz.
# You can replace this with a more accurate JUZ_PAGES_COUNT dictionary later.
def get_pages_in_juz(juz_number):
    # if juz_number in JUZ_PAGES_COUNT:
    #     return JUZ_PAGES_COUNT[juz_number]
    return DEFAULT_PAGES_PER_JUZ


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

# Global state for SocketIO rooms and user states (e.g., speaking, muted)
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
                parsed_phone = phonenumbers.parse(raw_phone, None)
                e164_phone_number = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.E164)

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
    
    return render_template('auth/verify_email.html', title='Verify Email', form=form, email=user_to_verify.email if user_to_verify else email_to_verify)

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
    user = current_user # Fresh from load_user
    if not user.phone_number:
        flash('No phone number on record to send a code to.', 'warning')
        return redirect(url_for('dashboard'))

    if user.phone_confirmed:
        flash('Your phone number is already confirmed.', 'info')
        return redirect(url_for('dashboard'))
        
    send_phone_verification_sms(user) # This updates user.phone_verification_code and commits
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
            # To prevent email enumeration, show the same message
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
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.password_reset_token_expires_at = None # Invalidate the token
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
    
    app.logger.info(f"[dashboard] User {current_user.id} passed all verification checks.")

    # --- Quran Juzz Progress Logic ---
    juzz_display_data = []
    for juz_num in range(1, NUMBER_OF_JUZ + 1):
        # Ensure UserJuzProgress record exists
        user_juz_prog = UserJuzProgress.query.filter_by(user_id=current_user.id, juz_number=juz_num).first()
        if not user_juz_prog:
            user_juz_prog = UserJuzProgress(user_id=current_user.id, juz_number=juz_num)
            db.session.add(user_juz_prog)
            # No commit here, will commit in bulk later or rely on auto-commit if configured,
            # but explicit commit at end of loop or batch is safer.

        # Calculate completion percentage for this Juzz
        pages_in_this_juz = get_pages_in_juz(juz_num)
        
        # A page is considered "completed" if its mistake_count is 0.
        # You might want a more sophisticated definition of "completed" later.
        completed_pages_count = UserPageRecord.query.filter(
            UserPageRecord.user_id == current_user.id,
            UserPageRecord.juz_number == juz_num,
            UserPageRecord.mistake_count == 0 # Define "completed" as 0 mistakes
        ).count()

        percentage = 0
        if pages_in_this_juz > 0:
            percentage = round((completed_pages_count / pages_in_this_juz) * 100, 1)
        
        juzz_display_data.append({
            'number': juz_num,
            'percentage': percentage,
            'pages_in_juz': pages_in_this_juz # For display or future use
        })
    
    try:
        db.session.commit() # Commit any new UserJuzProgress records
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error committing new UserJuzProgress records for user {current_user.id}: {e}")
        flash("An error occurred while preparing your dashboard. Please try again.", "danger")
        # Potentially redirect or handle error, for now, it might show 0% for uncommitted.

    return render_template('dashboard.html', title='Dashboard', juzz_progress_list=juzz_display_data)

@app.route('/juzz/<int:juz_number>')
@login_required
def juz_detail(juz_number):
    if not (1 <= juz_number <= NUMBER_OF_JUZ):
        flash("Invalid Juzz number.", "danger")
        return redirect(url_for('dashboard'))

    # Ensure verifications are passed
    if not current_user.email_confirmed:
        return redirect(url_for('verify_email'))
    if current_user.phone_number and not current_user.phone_confirmed:
        return redirect(url_for('verify_phone'))

    pages_in_this_juz = get_pages_in_juz(juz_number)
    page_records_display_data = []

    for page_num_in_juz in range(1, pages_in_this_juz + 1):
        page_record = UserPageRecord.query.filter_by(
            user_id=current_user.id,
            juz_number=juz_number,
            page_number_in_juz=page_num_in_juz
        ).first()

        mistakes = -1 # Default for not yet recorded / not started
        color_class = "page-grey" # Default color

        if page_record:
            mistakes = page_record.mistake_count
            if mistakes == 0:
                color_class = "page-green"
            elif 1 <= mistakes <= 2:
                color_class = "page-orange"
            elif mistakes > 2:
                color_class = "page-red"
        
        page_records_display_data.append({
            'number_in_juz': page_num_in_juz,
            'mistakes': mistakes, # -1 if no record
            'color_class': color_class,
            'record_id': page_record.id if page_record else None # For potential future actions
        })

    return render_template('juz_detail.html',
                           title=f'Juzz {juz_number} Details',
                           juz_number=juz_number,
                           page_records_list=page_records_display_data,
                           pages_in_this_juz=pages_in_this_juz)


# (Keep existing /call route and SocketIO handlers as they are, unless they need changes related to this)
# ...
@app.route('/call')
@login_required
def call():
    app.logger.info(f"[call] Entered. User: {current_user.email} (ID: {current_user.id}). Email_confirmed: {current_user.email_confirmed}, Phone_confirmed: {current_user.phone_confirmed}, Has Phone: {bool(current_user.phone_number)}")

    if not current_user.email_confirmed:
        flash('Please confirm your email address before making/joining a call.', 'warning')
        return redirect(url_for('verify_email'))
    
    if current_user.phone_number and not current_user.phone_confirmed:
        flash('Please verify your phone number before making/joining calls.', 'warning')
        return redirect(url_for('verify_phone'))
    # Removed this check: elif not current_user.phone_number: as phone is optional now
    # If phone becomes mandatory for calls, add it back.

    app.logger.info(f"[call] User {current_user.id} passed verification checks for call. Rendering call page.")
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
# ... (Keep existing SocketIO handlers)
@socketio.on('connect')
def on_connect(auth=None): 
    logger = current_app.logger
    if current_user.is_authenticated:
        logger.info(f"Authenticated client connected: {current_user.username} ({request.sid})")
        if not current_user.email_confirmed:
            emit('auth_status', {'email_confirmed': False, 'authenticated': True, 'message': 'Email not verified.'}, room=request.sid)
            logger.warning(f"User {current_user.username} connected via SocketIO but email not verified.")
        else:
            emit('auth_status', {'authenticated': True, 'email_confirmed': True, 'phone_confirmed': current_user.phone_confirmed if current_user.phone_number else True}, room=request.sid)
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
        emit('error_joining', {'message': 'Authentication required to join a call.'})
        return

    if not current_user.email_confirmed:
        emit('error_joining', {'message': 'Email verification required to join a call.'})
        return
    
    room_id = data.get('room')
    if not room_id:
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
        if room_id in user_states_in_rooms and request.sid in user_states_in_rooms[room_id]:
            del user_states_in_rooms[room_id][request.sid]
        emit('peer_left', {'sid': request.sid, 'room': room_id}, room=room_id, include_self=False)
        if not rooms_data[room_id]:
            del rooms_data[room_id]
            if room_id in user_states_in_rooms: del user_states_in_rooms[room_id]

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

# --- Flask CLI Commands ---
@app.cli.command('db-create')
def db_create_command():
    with app.app_context():
        try:
            db.create_all()
            print('Database tables created!')
            # Add default Juzz progress for existing users if needed, or handle on first dashboard view.
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