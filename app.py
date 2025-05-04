import os
import eventlet
eventlet.monkey_patch()
import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Local imports
from models import db, User
from forms import SignupForm, LoginForm
from utils import send_confirmation_email

# App Configuration
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_default_fallback_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///../instance/app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail Configuration - Ensure these are set in your .env file
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Initialize Extensions
db.init_app(app)
mail = Mail(app) # Initialize Mail directly here or use extensions.py pattern
csrf = CSRFProtect(app) # Enable CSRF protection globally

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login' # Route name for the login page
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please log in to access this page.'

@app.context_processor
def inject_now():
    """Injects the current UTC date/time into the template context."""
    return {'now': datetime.datetime.utcnow()}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# SocketIO Setup
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# Ensure instance folder exists for SQLite
try:
    if not os.path.exists(os.path.join(os.path.dirname(__file__), 'instance')):
        os.makedirs(os.path.join(os.path.dirname(__file__), 'instance'))
except OSError:
    pass

# --- Global Data for WebRTC ---
# Note: Storing room data globally like this is simple but not scalable for large applications.
# Consider using Redis or another external store for production if needed.
rooms_data = {}

# --- Route Definitions ---

@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('landing.html')

# --- Auth Blueprint (Example, or keep routes in app.py for simplicity) ---
# For larger apps, use Flask Blueprints:
# from auth_routes import auth_bp
# app.register_blueprint(auth_bp, url_prefix='/auth')

# Simplified Auth Routes directly in app.py:
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
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
            send_confirmation_email(user)
            flash('A confirmation email has been sent to your email address. Please check your inbox (and spam folder).', 'success')
            return redirect(url_for('confirm_request'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during signup: {e}")
            flash('An error occurred during signup. Please try again.', 'danger')
    return render_template('auth/signup.html', title='Sign Up', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            if not user.email_confirmed:
                 flash('Please confirm your email address first. Check your inbox or request a new confirmation email.', 'warning')
                 # Optionally add a route to resend confirmation here
                 return redirect(url_for('login')) # Stay on login or redirect to a specific page

            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('auth/login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

@app.route('/confirm_request')
def confirm_request():
    # Simple page telling user to check email
    return render_template('auth/confirm_request.html', title='Check Your Email')

@app.route('/confirm/<token>')
def confirm_email(token):
    if current_user.is_authenticated and current_user.email_confirmed:
        flash('Account already confirmed.', 'info')
        return redirect(url_for('main.dashboard'))

    user = User.verify_email_confirmation_token(token)

    if user is None:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('landing')) # Or to resend confirmation page

    if user.email_confirmed:
        flash('Account already confirmed. Please login.', 'info')
    else:
        user.email_confirmed = True
        db.session.add(user)
        db.session.commit()
        flash('Your email has been confirmed! You can now log in.', 'success')
        login_user(user) # Log the user in directly after confirmation
        return redirect(url_for('main.dashboard')) # Redirect to dashboard after successful confirmation

    return redirect(url_for('login'))


# --- Main Application Routes ---
# Using a 'main' prefix conceptually, even without a blueprint here
@app.route('/dashboard')
@login_required
def dashboard():
    # Check confirmation again just in case
    if not current_user.email_confirmed:
        flash('Please confirm your email address to access all features.', 'warning')
        # Optionally limit features or redirect
        # return redirect(url_for('confirm_request'))
    return render_template('dashboard.html', title='Dashboard')

@app.route('/call')
@login_required
def call():
     if not current_user.email_confirmed:
        flash('Please confirm your email address before joining a call.', 'warning')
        return redirect(url_for('main.dashboard'))
     # Pass user info if needed by JS, though socket.id is often enough
     return render_template('call.html', title='Voice Call')

# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback() # Rollback session in case of DB errors
    return render_template('errors/500.html'), 500


# --- SocketIO Event Handlers (Mostly Unchanged Logic, Context Added) ---

@socketio.on('connect')
def on_connect():
    if current_user.is_authenticated:
        app.logger.info(f"Authenticated client connected: {current_user.username} ({request.sid})")
        # You could potentially join a user-specific room here if needed
        # join_room(current_user.username)
    else:
        app.logger.warning(f"Unauthenticated client connected: {request.sid}")
        # Depending on your security model, you might want to disconnect unauthenticated users
        # or prevent them from joining call rooms later.
        # disconnect() # Example: Force disconnect


@socketio.on('disconnect')
def on_disconnect():
    disconnected_sid = request.sid
    username = current_user.username if current_user.is_authenticated else "Unknown User"
    app.logger.info(f"Client disconnected: {username} ({disconnected_sid})")

    for room, sids in list(rooms_data.items()):
        if disconnected_sid in sids:
            sids.remove(disconnected_sid)
            leave_room(room, sid=disconnected_sid)
            app.logger.info(f"Removed {disconnected_sid} from room {room} and SocketIO room")
            if not sids:
                del rooms_data[room]
                app.logger.info(f"Room {room} is now empty and removed.")
            else:
                emit('peer_left', {'sid': disconnected_sid}, room=room)
                app.logger.info(f"Notified peers in {room} about {disconnected_sid} leaving.")
            break


@socketio.on('join_call')
def on_join(data):
    if not current_user.is_authenticated:
        app.logger.warning(f"Unauthenticated user {request.sid} attempted to join call.")
        emit('join_error', {'error': 'Authentication required.'}, to=request.sid)
        return
    if not current_user.email_confirmed:
        app.logger.warning(f"Unconfirmed user {current_user.username} ({request.sid}) attempted to join call.")
        emit('join_error', {'error': 'Email confirmation required.'}, to=request.sid)
        return

    room = data.get('room')
    if not room:
        app.logger.error(f"Join attempt by {current_user.username} ({request.sid}) without room ID")
        emit('join_error', {'error': 'Room ID is required'}, to=request.sid)
        return

    joiner_sid = request.sid
    app.logger.info(f"{current_user.username} ({joiner_sid}) attempting to join room {room}")

    existing_peer_sids = list(rooms_data.get(room, set()))

    if room not in rooms_data:
        rooms_data[room] = set()
    rooms_data[room].add(joiner_sid)

    join_room(room, sid=joiner_sid)
    app.logger.info(f"{joiner_sid} joined SocketIO room {room}")

    app.logger.info(f"Sending existing_peers {existing_peer_sids} to {joiner_sid}")
    emit('existing_peers', {'sids': existing_peer_sids}, to=joiner_sid)

    if existing_peer_sids:
        app.logger.info(f"Notifying existing peers in {room} about new peer {joiner_sid}")
        emit('peer_joined', {'sid': joiner_sid}, room=room, skip_sid=joiner_sid)

    app.logger.info(f"Current peers in room {room}: {rooms_data[room]}")


@socketio.on('leave_call')
def on_leave(data):
    # No explicit authentication check needed here as 'disconnect' handles cleanup,
    # but we ensure the user *was* in the room.
    room = data.get('room')
    leaver_sid = request.sid
    username = current_user.username if current_user.is_authenticated else "Unknown User"

    if room and room in rooms_data and leaver_sid in rooms_data[room]:
        app.logger.info(f"{username} ({leaver_sid}) leaving room {room}")
        leave_room(room, sid=leaver_sid)
        rooms_data[room].remove(leaver_sid)
        app.logger.info(f"{leaver_sid} left SocketIO room {room}")

        if not rooms_data[room]:
            del rooms_data[room]
            app.logger.info(f"Room {room} is now empty and removed.")
        else:
            emit('peer_left', {'sid': leaver_sid}, room=room)
            app.logger.info(f"Notified peers in {room} about {leaver_sid} leaving.")
            app.logger.info(f"Remaining peers in {room}: {rooms_data[room]}")
    else:
         app.logger.warning(f"Attempt to leave failed for {username} ({leaver_sid}): Not found in room {room} or room doesn't exist.")


@socketio.on('signal')
def on_signal(data):
    # Relay signals point-to-point. Basic validation.
    target_sid = data.get('to_sid')
    sender_sid = request.sid
    signal_payload = data.get('signal')

    if not target_sid:
        app.logger.warning(f"Signal from {sender_sid} missing target_sid")
        return
    if not signal_payload:
        app.logger.warning(f"Signal from {sender_sid} to {target_sid} missing payload")
        return

    # You could add checks here to ensure sender and target are in the same room if needed.
    # room_of_sender = next((r for r, sids in rooms_data.items() if sender_sid in sids), None)
    # room_of_target = next((r for r, sids in rooms_data.items() if target_sid in sids), None)
    # if not (room_of_sender and room_of_target and room_of_sender == room_of_target):
    #    app.logger.warning(f"Signal relay blocked: {sender_sid} and {target_sid} not in the same room.")
    #    return

    signal_data_to_send = {
        'from_sid': sender_sid,
        'signal': signal_payload
    }
    emit('signal', signal_data_to_send, to=target_sid)


@socketio.on('remote_mute_request')
def on_remote_mute_request(data):
    # Ensure sender is authenticated
    if not current_user.is_authenticated:
        app.logger.warning(f"Unauthenticated mute request from {request.sid}")
        return

    room = data.get('room')
    target_sid = data.get('target_sid')
    requester_sid = request.sid

    if not room or not target_sid:
        app.logger.warning(f"Invalid remote_mute_request received from {requester_sid}")
        return

    if room in rooms_data and requester_sid in rooms_data[room] and target_sid in rooms_data[room]:
        # Potentially add role check here: Only Listeners can mute Memorizers?
        # if current_user.role == 'Listener': # Example role check
        app.logger.info(f"Relaying mute request from {requester_sid} to {target_sid} in room {room}")
        emit('force_mute', {}, to=target_sid)
        # else:
        #    app.logger.warning(f"Mute request denied: {requester_sid} does not have permission.")
    else:
        app.logger.warning(f"Mute request validation failed: Room '{room}' or SIDs not found.")


@socketio.on('speaking_status')
def on_speaking_status(data):
    room = data.get('room')
    is_speaking = data.get('speaking')
    sender_sid = request.sid

    if room and room in rooms_data and sender_sid in rooms_data[room]:
        emit('speaking_status', {
            'sid': sender_sid,
            'speaking': is_speaking
        }, room=room, skip_sid=sender_sid)


# Command to create database tables (run once locally: flask db-create)
@app.cli.command('db-create')
def db_create():
    """Creates database tables."""
    with app.app_context():
        db.create_all()
    print('Database tables created!')

# Command to drop database tables (use with caution!)
@app.cli.command('db-drop')
def db_drop():
    """Drops all database tables."""
    if input('Are you sure you want to drop all tables? (y/N): ').lower() == 'y':
        with app.app_context():
            db.drop_all()
        print('Database tables dropped!')
    else:
        print('Aborted.')

# --- Main Execution ---
if __name__ == '__main__':
    print("Starting Thubut server...")
    # Use socketio.run for development with eventlet
    # For production with Gunicorn/Render: gunicorn --worker-class eventlet -w 1 app:app
    # The host '0.0.0.0' makes it accessible externally, port 10000 as before.
    # Debug=True enables auto-reloading BUT can cause issues with eventlet/socketio sometimes.
    # use_reloader=False is often recommended when using eventlet with debug=True.
    # Set debug=False for production.
    use_debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 10000)), debug=use_debug, use_reloader=False)