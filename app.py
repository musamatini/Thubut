# app.py
import eventlet
eventlet.monkey_patch() # Should be the very first effective line
import os
import datetime # Ensure datetime is imported
import logging
import phonenumbers

from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app
# MODIFIED: Added emit, join_room, leave_room, disconnect
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

load_dotenv()

from models import db, User
from forms import SignupForm, LoginForm, VerificationCodeForm, PasswordResetRequestForm, ResetPasswordForm
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

app.config['TWILIO_ACCOUNT_SID'] = os.environ.get('TWILIO_ACCOUNT_SID') # Retained if used elsewhere
app.config['TWILIO_AUTH_TOKEN'] = os.environ.get('TWILIO_AUTH_TOKEN')   # Retained
app.config['TWILIO_PHONE_NUMBER'] = os.environ.get('TWILIO_PHONE_NUMBER') # Retained

app.config['RAPIDAPI_KEY'] = os.environ.get('RAPIDAPI_KEY')
app.config['RAPIDAPI_SMS_VERIFY_HOST'] = os.environ.get('RAPIDAPI_SMS_VERIFY_HOST', 'sms-verify3.p.rapidapi.com')

# Initialize Extensions
db.init_app(app)
csrf = CSRFProtect(app) # CSRF protection enabled

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
    with app.app_context(): # Keep app_context for safety with extensions
        try:
            # Updated to use db.session.get()
            return db.session.get(User, int(user_id))
        except Exception as e:
            app.logger.error(f"Error loading user {user_id}: {e}")
            return None

socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# --- Global state for SocketIO rooms and users ---
# ADDED: Initialization for rooms_data and user_states_in_rooms
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
            if raw_phone: # Only parse if phone number is provided
                parsed_phone = phonenumbers.parse(raw_phone, None) # Assumes intl-tel-input gives full number
                e164_phone_number = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.E164)

            user = User(
                fullname=form.fullname.data,
                username=form.username.data,
                email=form.email.data.lower(),
                birthday=form.birthday.data,
                phone_number=e164_phone_number # Store normalized number, can be None
            )
            user.set_password(form.password.data)
            user.set_languages(form.languages.data)
            
            email_code = user.set_email_verification_code()
           
            db.session.add(user)
            db.session.commit()

            send_email_verification_code(user, email_code)
            
            if user.phone_number:
                send_phone_verification_sms(user) # API generates code, stores it via background task

            flash_message = 'Account created! Please check your email for a verification code.'
            if user.phone_number:
                flash_message += ' If you provided a phone number, an SMS code will be sent for phone verification after you verify your email.'
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
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            if not user.email_confirmed:
                 flash('Your email address is not verified. Please check your inbox or use the verification page to get a new code.', 'warning')
                 session['signup_email_for_verification'] = user.email
                 return redirect(url_for('verify_email'))

            # Optional: If phone confirmation becomes mandatory for login later
            if user.phone_number and not user.phone_confirmed:
                flash('Please confirm your phone number to complete login.', 'warning')
                return redirect(url_for('verify_phone'))

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
        if 'signup_email_for_verification' in session:
            session.pop('signup_email_for_verification', None)
        # If somehow they land here and are confirmed, send to dashboard or login
        return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('login'))

    if form.validate_on_submit():
        if user_to_verify.verify_email_code(form.code.data):
            try:
                db.session.commit()
                flash('Your email has been confirmed!', 'success')
                if 'signup_email_for_verification' in session:
                    session.pop('signup_email_for_verification', None)
                
                if not current_user.is_authenticated:
                    login_user(user_to_verify) # Login the user

                # Now current_user is user_to_verify
                active_user = current_user # Use current_user after potential login
                if active_user.phone_number and not active_user.phone_confirmed:
                    flash('Email confirmed! Next, please verify your phone number.', 'info')
                    return redirect(url_for('verify_phone'))
                
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error saving email confirmation for {user_to_verify.email}: {e}", exc_info=True)
                flash('An error occurred. Please try again.', 'danger')
        else:
            flash('Invalid or expired verification code. Please try again or request a new one.', 'danger')
    
    return render_template('auth/verify_email.html', title='Verify Email', form=form, email=email_to_verify)

@app.route('/resend_verification_email', methods=['POST'])
def resend_verification_email():
    # CSRF protection is handled globally by Flask-WTF for POST requests if enabled
    email = request.form.get('email') 
    if not email: # Should come from the hidden field in verify_email.html
        # If email is not in form, try to get from session (e.g. if user refreshes verify_email page)
        email = session.get('signup_email_for_verification')
        if not email and current_user.is_authenticated and not current_user.email_confirmed:
            email = current_user.email

    if not email:
        flash('Could not determine email address to resend verification. Please try logging in again or contacting support.', 'danger')
        return redirect(url_for('login')) # Or a more appropriate page

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
    
    # Redirect back to verify_email page, pre-filling the email if it was successfully used
    if email:
        session['signup_email_for_verification'] = email
    return redirect(url_for('verify_email'))


# --- Phone Verification ---
@app.route('/verify_phone', methods=['GET', 'POST'])
@login_required
def verify_phone():
    form = VerificationCodeForm()
    user = current_user # User must be logged in

    if not user.phone_number:
        flash('You do not have a phone number registered. Please add one in your profile.', 'warning')
        return redirect(url_for('dashboard')) # Or profile settings page

    if user.phone_confirmed:
        flash('Your phone number is already confirmed.', 'info')
        return redirect(url_for('dashboard'))

    if form.validate_on_submit():
        if user.verify_phone_code(form.code.data):
            try:
                user.phone_confirmed = True # Mark phone as confirmed
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
    if not user.phone_number:
        flash('No phone number on record to send a code to.', 'warning')
        return redirect(url_for('dashboard')) # Or profile page

    if user.phone_confirmed:
        flash('Your phone number is already confirmed.', 'info')
        return redirect(url_for('dashboard'))
        
    send_phone_verification_sms(user) # API generates and sends code
    flash('A new verification code is being sent to your phone. Please wait a moment.', 'success')
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
            # user.password_reset_token_expires_at is set in get_password_reset_token
            # No need to store token itself in DB if using itsdangerous correctly
            db.session.commit() # Save expiry time
            
            send_password_reset_email(user, token)
            flash('An email has been sent with instructions to reset your password.', 'info')
        else:
            flash('If an account with that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('auth/reset_password_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token_route(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    user = User.verify_password_reset_token(token) # Verifies expiry too
    if not user:
        flash('That is an invalid or expired password reset token.', 'warning')
        return redirect(url_for('reset_password_request_route'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.password_reset_token = None # Invalidate by clearing related DB fields if you stored token
        user.password_reset_token_expires_at = None # Clear expiry
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
        flash('Please verify your email address to access the dashboard.', 'warning')
        session['signup_email_for_verification'] = current_user.email # Help prefill verify page
        return redirect(url_for('verify_email'))
    
    # Optional: if phone verification is also a soft requirement for full features
    # if current_user.phone_number and not current_user.phone_confirmed:
    #     flash('Your phone number is not yet verified. Some features might be limited. Please verify it from your profile or the prompt.', 'info')
        # No redirect here, just a message. User can verify via verify_phone.html link.

    return render_template('dashboard.html', title='Dashboard')

@app.route('/call')
@login_required
def call():
    if not current_user.email_confirmed:
        flash('Please confirm your email address before joining a call.', 'warning')
        return redirect(url_for('dashboard')) # Or verify_email
    
    # Optional: if phone verification is required for calls
    # if current_user.phone_number and not current_user.phone_confirmed:
    #     flash('Please verify your phone number before making/joining calls.', 'warning')
    #     return redirect(url_for('verify_phone'))
    # elif not current_user.phone_number:
    #     flash('A verified phone number is required to make/join calls. Please add and verify one.', 'warning')
    #     return redirect(url_for('dashboard')) # Or profile page to add phone

    return render_template('call.html', title='Voice Call')

# --- Error Handlers ---
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

@socketio.on('connect')
# MODIFIED: Changed signature to accept auth argument
def on_connect(auth=None): 
    logger = current_app.logger
    if current_user.is_authenticated:
        logger.info(f"Authenticated client connected: {current_user.username} ({request.sid})")
        if not current_user.email_confirmed:
            emit('auth_status', {'email_confirmed': False, 'authenticated': True, 'message': 'Email not verified.'}, room=request.sid)
            logger.warning(f"User {current_user.username} connected via SocketIO but email not verified.")
            # Optionally, you could disconnect them here or prevent joining rooms later
        # elif current_user.phone_number and not current_user.phone_confirmed:
        #     emit('auth_status', {'phone_confirmed': False, 'email_confirmed': True, 'authenticated': True, 'message': 'Phone not verified.'}, room=request.sid)
        else:
            emit('auth_status', {'authenticated': True, 'email_confirmed': True}, room=request.sid)
    else:
        logger.warning(f"Unauthenticated client connected: {request.sid}")
        emit('auth_status', {'authenticated': False, 'message': 'Not authenticated.'}, room=request.sid)
        # Consider disconnecting unauthenticated users immediately if calls require auth
        # disconnect() # Now disconnect is imported, so no 'from flask_socketio import disconnect' needed here


@socketio.on('disconnect')
# MODIFIED: Changed signature to accept *args
def on_disconnect(*args):
    logger = current_app.logger
    logger.info(f"Client disconnected: {request.sid}")
    
    # Ensure rooms_data and user_states_in_rooms are globally accessible if modified
    # (already handled by them being global variables)

    # Clean up user from all rooms they might have been in
    for room_id, sids_in_room in list(rooms_data.items()): # Iterate over a copy for safe modification
        if request.sid in sids_in_room:
            sids_in_room.remove(request.sid)
            if not sids_in_room: # If room becomes empty
                del rooms_data[room_id]
                if room_id in user_states_in_rooms: # Clean up user states too
                    del user_states_in_rooms[room_id]
                logger.info(f"Room {room_id} is now empty and removed.")
            else:
                # Notify other users in the room that this peer has left
                emit('peer_left', {'sid': request.sid, 'room': room_id}, room=room_id, include_self=False)
                # Clean up specific user state if any
                if room_id in user_states_in_rooms and request.sid in user_states_in_rooms[room_id]:
                    del user_states_in_rooms[room_id][request.sid]
            logger.info(f"User {request.sid} removed from room {room_id}. Users remaining: {len(sids_in_room)}")


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

    # Optional: Check phone verification if it becomes a requirement for calls
    # if not current_user.phone_number or not current_user.phone_confirmed:
    #     logger.warning(f"User {current_user.username} ({request.sid}) attempted to join call with unverified/missing phone.")
    #     emit('error_joining', {'message': 'A verified phone number is required to join calls.'})
    #     return

    room_id = data.get('room')
    if not room_id:
        logger.warning(f"User {request.sid} tried to join without specifying a room.")
        emit('error_joining', {'message': 'Room ID is required.'})
        return

    join_room(room_id)
    logger.info(f"User {current_user.username} ({request.sid}) joined room: {room_id}")

    # Initialize room if it doesn't exist
    if room_id not in rooms_data:
        rooms_data[room_id] = set()
    if room_id not in user_states_in_rooms:
        user_states_in_rooms[room_id] = {}

    # Get list of other SIDs already in the room
    other_sids_in_room = list(rooms_data[room_id]) # Convert set to list for emitting

    # Add current user to the room
    rooms_data[room_id].add(request.sid)
    user_states_in_rooms[room_id][request.sid] = {"speaking": False, "muted": False, "username": current_user.username} # Store username

    # Send the list of existing peers (SIDs) to the newly joined user
    if other_sids_in_room:
        emit('existing_peers', {'sids': other_sids_in_room, 'room': room_id}, room=request.sid)
        logger.info(f"Sent existing peers {other_sids_in_room} to {request.sid} for room {room_id}")

    # Notify other users in the room that a new peer has joined
    # Send user details along with SID
    emit('peer_joined', {'sid': request.sid, 'username': current_user.username, 'room': room_id}, room=room_id, include_self=False)
    logger.info(f"Notified room {room_id} that {request.sid} ({current_user.username}) joined.")


@socketio.on('leave_call')
def on_leave_call(data):
    logger = current_app.logger
    if not current_user.is_authenticated: # Should not happen if join required auth
        logger.warning(f"Unauthenticated user {request.sid} attempted to leave call.")
        return

    room_id = data.get('room')
    if not room_id:
        logger.warning(f"User {request.sid} tried to leave without specifying a room.")
        return

    if room_id in rooms_data and request.sid in rooms_data[room_id]:
        leave_room(room_id)
        rooms_data[room_id].remove(request.sid)
        logger.info(f"User {current_user.username} ({request.sid}) left room: {room_id}")

        # Clean up user state
        if room_id in user_states_in_rooms and request.sid in user_states_in_rooms[room_id]:
            del user_states_in_rooms[room_id][request.sid]

        # Notify other users in the room
        emit('peer_left', {'sid': request.sid, 'room': room_id}, room=room_id, include_self=False)

        if not rooms_data[room_id]: # If room is now empty
            del rooms_data[room_id]
            if room_id in user_states_in_rooms:
                del user_states_in_rooms[room_id]
            logger.info(f"Room {room_id} is now empty and removed after user left.")
    else:
        logger.warning(f"User {request.sid} tried to leave room {room_id} but was not found in it.")


@socketio.on('signal')
def on_signal(data):
    logger = current_app.logger
    if not current_user.is_authenticated:
        logger.warning(f"Unauthenticated user {request.sid} attempted to send a signal.")
        return

    to_sid = data.get('to_sid')
    signal_payload = data.get('signal')

    if not to_sid or signal_payload is None:
        logger.warning(f"Invalid signal data from {request.sid}: {data}")
        return

    # logger.debug(f"Relaying signal from {request.sid} to {to_sid}. Type: {signal_payload.get('type', 'candidate')}")
    emit('signal', {'from_sid': request.sid, 'signal': signal_payload}, room=to_sid)


@socketio.on('speaking_status')
def on_speaking_status(data):
    logger = current_app.logger
    if not current_user.is_authenticated:
        logger.warning(f"Unauthenticated user {request.sid} sent speaking status.")
        return

    room_id = data.get('room')
    speaking = data.get('speaking')

    if room_id is None or speaking is None:
        logger.warning(f"Invalid speaking_status data from {request.sid}: {data}")
        return

    if room_id in rooms_data and request.sid in rooms_data[room_id]:
        # Update server-side state if you're tracking it
        if room_id in user_states_in_rooms and request.sid in user_states_in_rooms[room_id]:
            user_states_in_rooms[room_id][request.sid]['speaking'] = speaking
        
        # logger.debug(f"User {request.sid} in room {room_id} speaking: {speaking}")
        emit('speaking_status', {'sid': request.sid, 'speaking': speaking, 'room': room_id}, room=room_id, include_self=False)
    else:
        logger.warning(f"User {request.sid} sent speaking status for room {room_id} but is not in it or room doesn't exist.")

@socketio.on('remote_mute_request')
def on_remote_mute_request(data):
    logger = current_app.logger
    if not current_user.is_authenticated:
        logger.warning(f"Unauthenticated user {request.sid} attempted remote mute.")
        return

    room_id = data.get('room')
    target_sid = data.get('target_sid')

    if not room_id or not target_sid:
        logger.warning(f"Invalid remote_mute_request data from {request.sid}: {data}")
        return

    # Security check: Requester and target must be in the same room
    if room_id in rooms_data and \
       request.sid in rooms_data[room_id] and \
       target_sid in rooms_data[room_id]:
        
        logger.info(f"User {request.sid} requests mute for {target_sid} in room {room_id}.")
        emit('force_mute', {'requester_sid': request.sid, 'room': room_id}, room=target_sid)
        # Optionally, you could implement roles/permissions here for who can mute whom
    else:
        logger.warning(f"User {request.sid} attempted to mute {target_sid} in room {room_id}, but conditions not met (not in room, target not in room, or room invalid).")


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
    port = int(os.environ.get('PORT', 10000)) # Render typically sets PORT env var
    use_flask_debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    print(f"Attempting to start SocketIO server on {host}:{port}")
    try:
        # use_reloader should be False for eventlet/gunicorn in production
        # For local development with eventlet, use_reloader=True can sometimes cause issues,
        # but it's often desired. Set based on your FLASK_DEBUG.
        socketio.run(app, host=host, port=port, use_reloader=use_flask_debug, log_output=True, debug=use_flask_debug)
    except Exception as e:
         logging.error(f"Failed to start SocketIO server: {e}", exc_info=True)