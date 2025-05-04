from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room
import eventlet
import logging
import eventlet.wsgi

# Enable basic logging for Flask-SocketIO
# logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'np+(cyaq5vt2$6hjm5v0rrpchdcjl5)p(o1-f3(7q@ykj=_v1t!'
socketio = SocketIO(app, cors_allowed_origins="*") 
rooms_data = {}

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def on_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('speaking_status')
def on_speaking_status(data):
    """ Broadcast whether a user started or stopped speaking """
    room = data.get('room')
    is_speaking = data.get('speaking')
    sender_sid = request.sid

    if room and room in rooms_data and sender_sid in rooms_data[room]:
        # print(f"User {sender_sid} speaking status in room {room}: {is_speaking}") # Optional: for debugging
        emit('speaking_status', {
            'sid': sender_sid,
            'speaking': is_speaking
        }, room=room, skip_sid=sender_sid) # Broadcast to others in the room

@socketio.on('disconnect')
def on_disconnect():
    print(f"Client disconnected: {request.sid}")
    # Find which room the user was in and notify others
    disconnected_sid = request.sid
    # Using a copy of items for safe iteration if modifying dict
    for room, sids in list(rooms_data.items()):
        if disconnected_sid in sids:
            sids.remove(disconnected_sid)
            # Leave the socketio room explicitly
            leave_room(room, sid=disconnected_sid)
            print(f"Removed {disconnected_sid} from room {room} and SocketIO room")
            if not sids: # Remove room from tracking if empty
                del rooms_data[room]
                print(f"Room {room} is now empty and removed.")
            else:
                 # Notify remaining users in the room
                emit('peer_left', {'sid': disconnected_sid}, room=room)
                print(f"Notified peers in {room} about {disconnected_sid} leaving.")
            break # Assuming user is only in one room for this app


@socketio.on('join_call')
def on_join(data):
    room = data.get('room')
    if not room:
        print("Join attempt without room ID")
        # Optionally emit an error back to the user
        # emit('join_error', {'error': 'Room ID is required'})
        return

    joiner_sid = request.sid
    print(f"{joiner_sid} attempting to join room {room}")

    # Get existing peers in the room (if any) BEFORE adding the new one
    existing_peer_sids = list(rooms_data.get(room, set()))

    # Add the new peer to the room (create room if it doesn't exist)
    if room not in rooms_data:
        rooms_data[room] = set()
    rooms_data[room].add(joiner_sid)

    # Join the SocketIO room for broadcasting within the room
    join_room(room, sid=joiner_sid) # Explicitly join with SID
    print(f"{joiner_sid} joined SocketIO room {room}")

    # 1. Notify the joining user about existing peers
    print(f"Sending existing_peers {existing_peer_sids} to {joiner_sid}")
    emit('existing_peers', {'sids': existing_peer_sids}, to=joiner_sid) # Use 'to' instead of 'room' for direct message

    # 2. Notify existing peers about the new user
    if existing_peer_sids:
        print(f"Notifying existing peers in {room} about new peer {joiner_sid}")
        emit('peer_joined', {'sid': joiner_sid}, room=room, skip_sid=joiner_sid) # Send to everyone in room except the new joiner

    print(f"Current peers in room {room}: {rooms_data[room]}")


@socketio.on('leave_call')
def on_leave(data):
    room = data.get('room')
    leaver_sid = request.sid
    if room and room in rooms_data and leaver_sid in rooms_data[room]:
        print(f"{leaver_sid} leaving room {room}")
        # Leave the SocketIO room first
        leave_room(room, sid=leaver_sid)
        rooms_data[room].remove(leaver_sid)
        print(f"{leaver_sid} left SocketIO room {room}")

        if not rooms_data[room]: # Clean up empty room
            del rooms_data[room]
            print(f"Room {room} is now empty and removed.")
        else:
            # Notify remaining users
            emit('peer_left', {'sid': leaver_sid}, room=room)
            print(f"Notified peers in {room} about {leaver_sid} leaving.")
            print(f"Remaining peers in {room}: {rooms_data[room]}")
    else:
         print(f"Attempt to leave failed: {leaver_sid} not found in room {room} or room doesn't exist.")


@socketio.on('signal')
def on_signal(data):
    """ Relay signals (offer, answer, candidate) point-to-point """
    target_sid = data.get('to_sid')
    sender_sid = request.sid
    signal_payload = data.get('signal') # Contains desc or candidate

    if not target_sid:
        print(f"Signal from {sender_sid} missing target_sid")
        return
    if not signal_payload:
        print(f"Signal from {sender_sid} to {target_sid} missing payload")
        return

    # Add sender's ID to the payload so the receiver knows who it's from
    signal_data_to_send = {
        'from_sid': sender_sid,
        'signal': signal_payload
    }

    # Emit the signal directly to the target peer using 'to'
    emit('signal', signal_data_to_send, to=target_sid)
    # print(f"Relayed signal from {sender_sid} to {target_sid}") # Can be noisy


# --- NEW: Handler for remote mute requests ---
@socketio.on('remote_mute_request')
def on_remote_mute_request(data):
    """ Received when a user clicks 'Mute Peer' for someone else """
    room = data.get('room')
    target_sid = data.get('target_sid')
    requester_sid = request.sid

    if not room or not target_sid:
        print(f"Invalid remote_mute_request received from {requester_sid}")
        return

    # Basic validation: Check if requester and target are actually in the room
    if room in rooms_data and requester_sid in rooms_data[room] and target_sid in rooms_data[room]:
        print(f"Relaying mute request from {requester_sid} to {target_sid} in room {room}")
        # Send a specific 'force_mute' event ONLY to the target user
        emit('force_mute', {}, to=target_sid)
    else:
        print(f"Mute request validation failed: Room '{room}' or SIDs not found.")



if __name__ == '__main__':
    print("Starting server on 0.0.0.0:10000")
    # Use use_reloader=False if debug=True and using eventlet to avoid issues
    # Consider debug=False for production/stable testing
    socketio.run(app, host='0.0.0.0', port=10000, debug=True, use_reloader=False)