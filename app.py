from flask import Flask, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
import eventlet

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('join_call')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('user_joined', {'msg': 'A user has joined the call.'}, room=room)

@socketio.on('leave_call')
def on_leave(data):
    room = data['room']
    leave_room(room)
    emit('user_left', {'msg': 'A user has left the call.'}, room=room)

@socketio.on('signal')
def on_signal(data):
    emit('signal', data, room=data['room'])

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=10000)
