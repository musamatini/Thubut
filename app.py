# app.py
import os
import eventlet
eventlet.monkey_patch()
import datetime, logging


from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
# REMOVED: from flask_mail import Mail # No longer using Flask-Mail
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Local imports
from models import db, User
from forms import SignupForm, LoginForm
from utils import send_confirmation_email # This will now use the API

# App Configuration
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_default_fallback_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///../instance/app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- REMOVED Flask-Mail SMTP Configuration ---
# app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
# app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
# app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
# app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
# app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
# app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
# app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# --- ADDED Mailgun API Configuration ---
# Ensure these are set in your Render environment variables / .env file
app.config['MAILGUN_API_KEY'] = os.environ.get('MAILGUN_API_KEY')
app.config['MAILGUN_DOMAIN'] = os.environ.get('MAILGUN_DOMAIN')
# Optional: Default to US region if not specified
app.config['MAILGUN_API_BASE_URL'] = os.environ.get('MAILGUN_API_BASE_URL', 'https://api.mailgun.net/v3')
# Recommended sender format for Mailgun API
app.config['MAILGUN_SENDER_NAME'] = os.environ.get('MAILGUN_SENDER_NAME', 'Thubut Team') # e.g., "Your App Name"


# Initialize Extensions
db.init_app(app)
# REMOVED: mail = Mail(app) # No longer needed
csrf = CSRFProtect(app) # Enable CSRF protection globally

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
# *** IMPORTANT: Update login_view if you use blueprints ***
# If signup/login are NOT in a blueprint named 'auth', adjust this:
login_manager.login_view = 'login' # Use the function name directly if not in a blueprint
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please log in to access this page.'

@app.context_processor
def inject_now():
    """Injects the current UTC date/time into the template context."""
    return {'now': datetime.datetime.utcnow()}

@login_manager.user_loader
def load_user(user_id):
    # Ensure logger is available even before request context sometimes
    with app.app_context():
        try:
            return User.query.get(int(user_id))
        except Exception as e:
            app.logger.error(f"Error loading user {user_id}: {e}")
            return None


# SocketIO Setup
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# Ensure instance folder exists for SQLite
try:
    # Use app.instance_path for clarity, though your method works too
    instance_path = app.instance_path
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
        app.logger.info(f"Created instance folder at: {instance_path}")
except OSError as e:
    app.logger.error(f"Error creating instance folder: {e}")
    pass

# --- Global Data for WebRTC ---
rooms_data = {}

# --- Route Definitions ---

@app.route('/')
def landing():
    if current_user.is_authenticated:
        # Use 'dashboard' directly if not in a blueprint
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

# Simplified Auth Routes directly in app.py:
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard')) # Use 'dashboard' directly
    form = SignupForm()
    if form.validate_on_submit():
        try:
            user = User(
                fullname=form.fullname.data,
                username=form.username.data,
                email=form.email.data.lower(),
                age=form.age.data,
                phone_number=form.phone_number.data or None
            )
            user.set_password(form.password.data)
            user.set_languages(form.languages.data)
            db.session.add(user)
            db.session.commit()
            # This now uses the API via utils.py
            send_confirmation_email(user)
            flash('A confirmation email has been sent. Please check your inbox (and spam folder).', 'success')
            # Use 'confirm_request' directly
            return redirect(url_for('confirm_request'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during signup for {form.email.data}: {e}", exc_info=True) # Add stack trace
            flash('An error occurred during signup. Please try again.', 'danger')
    # Log form errors if validation fails
    elif request.method == 'POST':
         app.logger.warning(f"Signup form validation failed: {form.errors}")
    return render_template('auth/signup.html', title='Sign Up', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard')) # Use 'dashboard' directly
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            if not user.email_confirmed:
                 flash('Please confirm your email address first. Check your inbox or request a new confirmation email.', 'warning')
                 return redirect(url_for('login')) # Use 'login' directly

            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            # Use 'dashboard' directly
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('auth/login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing')) # Use 'landing' directly

@app.route('/confirm_request')
def confirm_request():
    # Simple page telling user to check email
    return render_template('auth/confirm_request.html', title='Check Your Email')

# *** IMPORTANT: Route name is 'confirm_email', not 'auth.confirm_email' ***
@app.route('/confirm/<token>')
def confirm_email(token):
    if current_user.is_authenticated and current_user.email_confirmed:
        flash('Account already confirmed.', 'info')
        return redirect(url_for('dashboard')) # Use 'dashboard' directly

    user = User.verify_email_confirmation_token(token)

    if user is None:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('landing')) # Use 'landing' directly

    if user.email_confirmed:
        flash('Account already confirmed. Please login.', 'info')
    else:
        user.email_confirmed = True
        # Consider adding a try/except block around DB operations
        try:
            db.session.add(user)
            db.session.commit()
            flash('Your email has been confirmed! You can now log in.', 'success')
            login_user(user) # Log the user in directly after confirmation
            return redirect(url_for('dashboard')) # Redirect to dashboard
        except Exception as e:
             db.session.rollback()
             app.logger.error(f"Error confirming email for user {user.id}: {e}", exc_info=True)
             flash('An error occurred while confirming your email. Please contact support.', 'danger')
             return redirect(url_for('login')) # Go back to login

    return redirect(url_for('login')) # Use 'login' directly


# --- Main Application Routes ---
@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.email_confirmed:
        flash('Please confirm your email address to access all features.', 'warning')
    return render_template('dashboard.html', title='Dashboard')

@app.route('/call')
@login_required
def call():
     if not current_user.email_confirmed:
        flash('Please confirm your email address before joining a call.', 'warning')
        return redirect(url_for('dashboard')) # Use 'dashboard' directly
     return render_template('call.html', title='Voice Call')

# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    # Ensure rollback happens within app context if needed
    try:
        db.session.rollback()
        app.logger.error("Rolled back database session due to internal error.")
    except Exception as e:
        app.logger.error(f"Error rolling back database session: {e}")
    app.logger.error(f"Internal Server Error: {error}", exc_info=True) # Log the error details
    return render_template('errors/500.html'), 500


# --- SocketIO Event Handlers ---
# (Your existing SocketIO handlers remain largely the same)
# ... include all your @socketio.on handlers here ...
@socketio.on('connect')
def on_connect():
    # Use logger safely
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    if current_user.is_authenticated:
        logger.info(f"Authenticated client connected: {current_user.username} ({request.sid})")
    else:
        logger.warning(f"Unauthenticated client connected: {request.sid}")

@socketio.on('disconnect')
def on_disconnect():
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    disconnected_sid = request.sid
    # Safely get username
    username = "Unknown User"
    if 'user_id' in session: # Check if user was logged in during this session
        user = User.query.get(session['user_id']) # Assuming you store user_id in session
        if user:
            username = user.username
        # Fallback if not using session['user_id'] but current_user might still be valid
        elif current_user and current_user.is_authenticated:
             username = current_user.username


    logger.info(f"Client disconnected: {username} ({disconnected_sid})")

    # Use list() to avoid issues iterating while modifying
    for room, sids in list(rooms_data.items()):
        if disconnected_sid in sids:
            sids.remove(disconnected_sid)
            leave_room(room, sid=disconnected_sid)
            logger.info(f"Removed {disconnected_sid} from room {room} and SocketIO room")
            if not sids:
                # Safely delete the room key
                if room in rooms_data:
                    del rooms_data[room]
                    logger.info(f"Room {room} is now empty and removed.")
            else:
                # Use specific room targeting
                socketio.emit('peer_left', {'sid': disconnected_sid}, room=room)
                logger.info(f"Notified peers in {room} about {disconnected_sid} leaving.")
            break # Exit loop once SID is found and handled


@socketio.on('join_call')
def on_join(data):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    if not current_user.is_authenticated:
        logger.warning(f"Unauthenticated user {request.sid} attempted to join call.")
        # Use specific SID targeting for error messages
        socketio.emit('join_error', {'error': 'Authentication required.'}, room=request.sid)
        return
    if not current_user.email_confirmed:
        logger.warning(f"Unconfirmed user {current_user.username} ({request.sid}) attempted to join call.")
        socketio.emit('join_error', {'error': 'Email confirmation required.'}, room=request.sid)
        return

    room = data.get('room')
    if not room:
        logger.error(f"Join attempt by {current_user.username} ({request.sid}) without room ID")
        socketio.emit('join_error', {'error': 'Room ID is required'}, room=request.sid)
        return

    joiner_sid = request.sid
    logger.info(f"{current_user.username} ({joiner_sid}) attempting to join room {room}")

    # Get existing peers *before* adding the new one
    existing_peer_sids = list(rooms_data.get(room, set()))

    # Ensure room exists before adding
    if room not in rooms_data:
        rooms_data[room] = set()
    rooms_data[room].add(joiner_sid)

    join_room(room, sid=joiner_sid) # Use sid= argument for clarity
    logger.info(f"{joiner_sid} joined SocketIO room {room}")

    logger.info(f"Sending existing_peers {existing_peer_sids} to {joiner_sid}")
    # Target the specific joiner
    socketio.emit('existing_peers', {'sids': existing_peer_sids}, room=joiner_sid)

    # Notify others after the new peer is ready
    if existing_peer_sids:
        logger.info(f"Notifying existing peers in {room} about new peer {joiner_sid}")
        # Use skip_sid to avoid sending to self
        socketio.emit('peer_joined', {'sid': joiner_sid}, room=room, skip_sid=joiner_sid)

    logger.info(f"Current peers in room {room}: {rooms_data[room]}")


@socketio.on('leave_call')
def on_leave(data):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    room = data.get('room')
    leaver_sid = request.sid
    username = current_user.username if current_user.is_authenticated else "Unknown User"

    if room and room in rooms_data and leaver_sid in rooms_data[room]:
        logger.info(f"{username} ({leaver_sid}) leaving room {room}")
        leave_room(room, sid=leaver_sid) # Use sid= argument
        rooms_data[room].remove(leaver_sid)
        logger.info(f"{leaver_sid} left SocketIO room {room}")

        if not rooms_data[room]:
             # Safely delete the room key
             if room in rooms_data:
                 del rooms_data[room]
                 logger.info(f"Room {room} is now empty and removed.")
        else:
            # Target the specific room
            socketio.emit('peer_left', {'sid': leaver_sid}, room=room)
            logger.info(f"Notified peers in {room} about {leaver_sid} leaving.")
            logger.info(f"Remaining peers in {room}: {rooms_data[room]}")
    else:
         logger.warning(f"Attempt to leave failed for {username} ({leaver_sid}): Not found in room '{room}' or room doesn't exist.")


@socketio.on('signal')
def on_signal(data):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    target_sid = data.get('to_sid')
    sender_sid = request.sid
    signal_payload = data.get('signal')

    if not target_sid:
        logger.warning(f"Signal from {sender_sid} missing target_sid")
        return
    if not signal_payload:
        logger.warning(f"Signal from {sender_sid} to {target_sid} missing payload")
        return

    # Basic validation: check if target SID is known in any room (optional but good)
    # target_exists = any(target_sid in sids for sids in rooms_data.values())
    # if not target_exists:
    #     logger.warning(f"Signal target {target_sid} not found in any active room.")
    #     return

    signal_data_to_send = {
        'from_sid': sender_sid,
        'signal': signal_payload
    }
    # Target the specific SID
    socketio.emit('signal', signal_data_to_send, room=target_sid)


@socketio.on('remote_mute_request')
def on_remote_mute_request(data):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    if not current_user.is_authenticated:
        logger.warning(f"Unauthenticated mute request from {request.sid}")
        return

    room = data.get('room')
    target_sid = data.get('target_sid')
    requester_sid = request.sid

    if not room or not target_sid:
        logger.warning(f"Invalid remote_mute_request received from {requester_sid}")
        return

    # Check if both requester and target are in the specified room
    if room in rooms_data and requester_sid in rooms_data[room] and target_sid in rooms_data[room]:
        logger.info(f"Relaying mute request from {requester_sid} to {target_sid} in room {room}")
        # Target the specific SID
        socketio.emit('force_mute', {}, room=target_sid)
    else:
        logger.warning(f"Mute request validation failed: Room '{room}' or SIDs {requester_sid}, {target_sid} not found/matched.")


@socketio.on('speaking_status')
def on_speaking_status(data):
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    room = data.get('room')
    is_speaking = data.get('speaking')
    sender_sid = request.sid

    if room and room in rooms_data and sender_sid in rooms_data[room]:
        # Use skip_sid to avoid sending back to self
        socketio.emit('speaking_status', {
            'sid': sender_sid,
            'speaking': is_speaking
        }, room=room, skip_sid=sender_sid)


# --- Flask CLI Commands ---
@app.cli.command('db-create')
def db_create():
    """Creates database tables."""
    with app.app_context():
        try:
            db.create_all()
            print('Database tables created!')
        except Exception as e:
            print(f"Error creating database tables: {e}")

@app.cli.command('db-drop')
def db_drop():
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

# --- Main Execution ---
if __name__ == '__main__':
    print("Starting Thubut server...")
    # Configure logging level based on environment
    log_level = logging.DEBUG if os.environ.get('FLASK_DEBUG', 'False').lower() == 'true' else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Get host and port from environment variables
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 10000))

    # Use Gunicorn's recommended setup via Procfile for Render, but socketio.run for local dev
    print(f"Attempting to start SocketIO server on {host}:{port}")
    try:
        # use_reloader should generally be False with eventlet
        # debug=True can be problematic, rely on FLASK_DEBUG env var for Flask's debug mode instead
        use_flask_debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        socketio.run(app, host=host, port=port, use_reloader=False, log_output=use_flask_debug)
    except Exception as e:
         # Catch potential errors during startup (like port binding)
         logging.error(f"Failed to start SocketIO server: {e}", exc_info=True)