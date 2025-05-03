const socket = io();
let localStream;
let peerConnection;
let room;
const config = {
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
};

function joinCall() {
    room = document.getElementById("room").value;
    document.getElementById("status").innerText = "Joined room: " + room;
    socket.emit("join_call", { room });

    navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
        localStream = stream;
        startPeer();
    });
}

function leaveCall() {
    socket.emit("leave_call", { room });
    document.getElementById("status").innerText = "Left room: " + room;
    if (peerConnection) peerConnection.close();
}

socket.on('signal', data => {
    if (data.desc) {
        peerConnection.setRemoteDescription(new RTCSessionDescription(data.desc)).then(() => {
            if (data.desc.type === 'offer') {
                peerConnection.createAnswer().then(answer => {
                    peerConnection.setLocalDescription(answer);
                    socket.emit('signal', { desc: answer, room });
                });
            }
        });
    } else if (data.candidate) {
        peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
    }
});

function startPeer() {
    peerConnection = new RTCPeerConnection(config);
    localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));

    peerConnection.ontrack = e => {
        document.getElementById("remoteAudio").srcObject = e.streams[0];
    };

    peerConnection.onicecandidate = e => {
        if (e.candidate) {
            socket.emit('signal', { candidate: e.candidate, room });
        }
    };

    peerConnection.onnegotiationneeded = () => {
        peerConnection.createOffer().then(offer => {
            peerConnection.setLocalDescription(offer);
            socket.emit('signal', { desc: offer, room });
        });
    };
}
