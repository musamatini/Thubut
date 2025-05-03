// Use 'const' for variables that won't be reassigned, 'let' for those that will.
const socket = io(); // Assumes server is running on the same host/port by default
const peerConnections = {}; // Store multiple peer connections { peerSocketId: RTCPeerConnection }
let localStream = null;
let currentRoom = null;
const config = {
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] // Free STUN server
    // Add TURN servers here if needed for complex networks:
    // { urls: 'turn:your.turn.server.com', username: 'user', credential: 'password' }
};

const joinBtn = document.getElementById('joinBtn');
const leaveBtn = document.getElementById('leaveBtn');
const roomInput = document.getElementById('room');
const statusDiv = document.getElementById('status');
const remoteAudiosDiv = document.getElementById('remoteAudios');
const localAudio = document.getElementById('localAudio');

// --- Core Functions ---

async function joinCall() {
    const roomValue = roomInput.value.trim();
    if (!roomValue) {
        statusDiv.innerText = "Please enter a Room ID.";
        return;
    }
    currentRoom = roomValue;

    statusDiv.innerText = "Requesting microphone access...";
    joinBtn.disabled = true;
    roomInput.disabled = true;

    try {
        // 1. Get microphone access first
        localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
        localAudio.srcObject = localStream; // Let user hear themselves (muted)
        statusDiv.innerText = "Microphone accessed. Joining room...";
        console.log("Local stream obtained");

        // 2. Emit join_call to the server
        socket.emit("join_call", { room: currentRoom });
        console.log(`Emitted join_call for room: ${currentRoom}`);

        // Update UI
        leaveBtn.disabled = false;
        statusDiv.innerText = `Joined room: ${currentRoom}. Waiting for peers...`;

    } catch (error) {
        console.error("Error accessing media devices or joining call:", error);
        statusDiv.innerText = `Error: ${error.message}. Check permissions and try again.`;
        // Reset UI state if failed
        currentRoom = null;
        joinBtn.disabled = false;
        roomInput.disabled = false;
        leaveBtn.disabled = true;
        if (localStream) {
            localStream.getTracks().forEach(track => track.stop());
            localStream = null;
            localAudio.srcObject = null;
        }
    }
}

function leaveCall() {
    if (!currentRoom) return;

    statusDiv.innerText = `Leaving room: ${currentRoom}...`;
    console.log(`Leaving room: ${currentRoom}`);

    // 1. Notify server
    socket.emit("leave_call", { room: currentRoom });

    // 2. Close all peer connections
    for (const peerId in peerConnections) {
        closePeerConnection(peerId);
    }

    // 3. Stop local media stream
    if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
        localStream = null;
        localAudio.srcObject = null;
        console.log("Local stream stopped.");
    }

    // 4. Clean up UI and state
    remoteAudiosDiv.innerHTML = ''; // Clear remote audio elements
    currentRoom = null;
    roomInput.disabled = false;
    joinBtn.disabled = false;
    leaveBtn.disabled = true;
    statusDiv.innerText = "Left the call. Enter a Room ID to join again.";
    console.log("Leave call process completed.");
}

// --- Peer Connection Management ---

// Creates and configures a peer connection for a given peer ID
function createPeerConnection(peerId, isInitiator) {
    if (peerConnections[peerId]) {
        console.warn(`Peer connection for ${peerId} already exists.`);
        return peerConnections[peerId]; // Avoid duplicates
    }

    console.log(`Creating peer connection for ${peerId}, initiator: ${isInitiator}`);
    const pc = new RTCPeerConnection(config);
    peerConnections[peerId] = pc;

    // --- Event Handlers for the Peer Connection ---

    // Handle incoming ICE candidates from the remote peer
    pc.onicecandidate = (event) => {
        if (event.candidate) {
            console.log(`Sending ICE candidate to ${peerId}`);
            sendSignal(peerId, { candidate: event.candidate });
        }
    };

    // Handle receiving remote stream
    pc.ontrack = (event) => {
        console.log(`Track received from ${peerId}`);
        addRemoteAudio(peerId, event.streams[0]);
    };

    // Handle ICE connection state changes (useful for debugging)
    pc.oniceconnectionstatechange = () => {
        console.log(`ICE connection state for ${peerId}: ${pc.iceConnectionState}`);
        updateStatus(); // Update overall status based on peer states
        if (pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'disconnected' || pc.iceConnectionState === 'closed') {
            // Handle connection failure/closure if needed, maybe attempt reconnect or just clean up
             console.warn(`Connection with ${peerId} ${pc.iceConnectionState}.`);
             // Maybe close and remove the connection more proactively here
             // closePeerConnection(peerId);
        }
    };

     // Handle negotiation needed (e.g., adding/removing tracks later)
     // For initial connection, we rely on the initiator model, but this can be useful later.
    pc.onnegotiationneeded = async () => {
        // This *can* fire unexpectedly. Be cautious.
        // We primarily use the join/existing peer logic for initial offers.
        // Only let the designated initiator create the *initial* offer.
        if (isInitiator) {
             console.log(`Negotiation needed for ${peerId}. Creating offer...`);
             try {
                 const offer = await pc.createOffer();
                 await pc.setLocalDescription(offer);
                 console.log(`Sending offer to ${peerId}`);
                 sendSignal(peerId, { desc: pc.localDescription });
             } catch (error) {
                 console.error(`Error creating/sending offer to ${peerId}:`, error);
             }
        } else {
             console.log(`Negotiation needed for ${peerId}, but not initiator. Waiting for offer.`);
        }
    };


    // --- Add Local Stream Tracks ---
    if (localStream) {
        localStream.getTracks().forEach(track => {
            try {
                 pc.addTrack(track, localStream);
                 console.log(`Added local track to connection with ${peerId}`);
            } catch (error) {
                 console.error(`Error adding track to ${peerId}:`, error);
            }
        });
    } else {
        console.warn("Local stream not available when creating peer connection for", peerId);
    }

    return pc;
}


// Closes a specific peer connection and removes its audio element
function closePeerConnection(peerId) {
    const pc = peerConnections[peerId];
    if (pc) {
        console.log(`Closing peer connection with ${peerId}`);
        pc.close();
        delete peerConnections[peerId];
        removeRemoteAudio(peerId);
        updateStatus();
    }
}

// --- Signaling ---

// Send signal data (offer, answer, candidate) to a specific peer via the server
function sendSignal(toId, signalPayload) {
    socket.emit('signal', {
        to_sid: toId,
        signal: signalPayload
    });
}

// Handle signals received from the server (sent by other peers)
socket.on('signal', async (data) => {
    const fromId = data.from_sid;
    const signal = data.signal;

    console.log(`Signal received from ${fromId}:`, signal.type || (signal.candidate ? 'candidate' : 'unknown'));

    let pc = peerConnections[fromId];

    // If receiving an offer, and connection doesn't exist, create it (as non-initiator)
    if (signal.desc && signal.desc.type === 'offer' && !pc) {
        pc = createPeerConnection(fromId, false); // We are receiving offer, so we are not initiator
    } else if (!pc) {
        console.error(`Received signal from unknown peer ${fromId}`);
        return; // Ignore signals from unknown peers or if connection doesn't exist yet
    }

    try {
        if (signal.desc) { // Handle Offer or Answer
            if (signal.desc.type === 'offer') {
                 console.log(`Processing offer from ${fromId}`);
                 await pc.setRemoteDescription(new RTCSessionDescription(signal.desc));
                 console.log(`Set remote description (offer) from ${fromId}`);
                 const answer = await pc.createAnswer();
                 await pc.setLocalDescription(answer);
                 console.log(`Sending answer to ${fromId}`);
                 sendSignal(fromId, { desc: pc.localDescription });
            } else if (signal.desc.type === 'answer') {
                 console.log(`Processing answer from ${fromId}`);
                 await pc.setRemoteDescription(new RTCSessionDescription(signal.desc));
                 console.log(`Set remote description (answer) from ${fromId}`);
                 // Offer/Answer complete, connection should start establishing
            } else {
                 console.warn("Unknown description type:", signal.desc.type);
            }
        } else if (signal.candidate) { // Handle ICE Candidate
             console.log(`Adding ICE candidate from ${fromId}`);
             await pc.addIceCandidate(new RTCIceCandidate(signal.candidate));
        }
    } catch (error) {
        console.error(`Error handling signal from ${fromId}:`, error);
        // Consider closing the connection on critical errors
        // closePeerConnection(fromId);
    }
});

// --- Server Events Handling ---

// Received when YOU join a room, lists peers already present
socket.on('existing_peers', (data) => {
    const existingPeerSids = data.sids;
    console.log(`Received existing peers: ${existingPeerSids.join(', ')}`);
    statusDiv.innerText = `In room ${currentRoom}. Connecting to ${existingPeerSids.length} existing peer(s)...`;

    if (!localStream) {
        console.error("Local stream not ready when 'existing_peers' received!");
        // You might want to handle this case, perhaps wait or show an error
        return;
    }

    // Initiate connection to each existing peer
    existingPeerSids.forEach(peerId => {
        // Create connection (as initiator) and let onnegotiationneeded handle offer
         const pc = createPeerConnection(peerId, true);
         // Explicitly trigger offer if onnegotiationneeded doesn't fire reliably
         // (Often needed, especially if tracks were added *before* this event)
         if(pc.localDescription == null) { // Check if an offer hasn't already been started
            console.log(`Explicitly creating offer for existing peer ${peerId}`);
            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .then(() => {
                    console.log(`Sending explicit offer to ${peerId}`);
                    sendSignal(peerId, { desc: pc.localDescription });
                })
                .catch(error => console.error(`Error creating explicit offer for ${peerId}:`, error));
        }
    });
     updateStatus();
});

// Received when a NEW peer joins the room AFTER you are already in it
socket.on('peer_joined', (data) => {
    const newPeerId = data.sid;
    console.log(`Peer joined: ${newPeerId}`);
    statusDiv.innerText = `Peer ${newPeerId.substring(0, 6)}... joined the room.`;

    // Don't initiate connection here. The new peer (who received 'existing_peers')
    // will initiate the connection (send the offer) to us.
    // We just need to be ready to receive their offer via the 'signal' handler.
    // We could optionally create the peer connection object here (as non-initiator)
    // in anticipation, but the 'signal' handler already does this if needed.
    // createPeerConnection(newPeerId, false); // Optional pre-creation
     updateStatus();
});

// Received when a peer leaves the room
socket.on('peer_left', (data) => {
    const leftPeerId = data.sid;
    console.log(`Peer left: ${leftPeerId}`);
    statusDiv.innerText = `Peer ${leftPeerId.substring(0, 6)}... left the room.`;
    closePeerConnection(leftPeerId); // Clean up connection and UI
});

// Handle potential connection errors from Socket.IO itself
socket.on('connect_error', (error) => {
  console.error('Socket.IO connection error:', error);
  statusDiv.innerText = `Connection Error: ${error.message}. Please check server and network.`;
   // Maybe disable buttons or attempt reconnection logic here
   joinBtn.disabled = true;
   leaveBtn.disabled = true;
   roomInput.disabled = true;
});

socket.on('disconnect', (reason) => {
  console.log(`Socket.IO disconnected: ${reason}`);
  statusDiv.innerText = `Disconnected from server: ${reason}. Please rejoin.`;
  // Clean up like leaveCall but without emitting leave_call again
    for (const peerId in peerConnections) {
        closePeerConnection(peerId);
    }
    if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
        localStream = null;
        localAudio.srcObject = null;
    }
    remoteAudiosDiv.innerHTML = '';
    currentRoom = null;
    roomInput.disabled = false;
    joinBtn.disabled = false;
    leaveBtn.disabled = true;
});


// --- UI Helper Functions ---

// Add a new audio element for a remote peer
function addRemoteAudio(peerId, stream) {
    let audio = document.getElementById(`audio_${peerId}`);
    if (!audio) {
        console.log(`Creating audio element for ${peerId}`);
        audio = document.createElement('audio');
        audio.id = `audio_${peerId}`;
        audio.autoplay = true;
        audio.controls = true; // Add controls for debugging/volume
        audio.setAttribute('data-peer-id', peerId); // Store peer ID with element
        // Add a label maybe
        const label = document.createElement('p');
        label.id = `label_${peerId}`;
        label.innerText = `Audio from ${peerId.substring(0, 6)}...`;
        remoteAudiosDiv.appendChild(label);
        remoteAudiosDiv.appendChild(audio);
    }
     // Check if stream is already attached to prevent issues
    if (audio.srcObject !== stream) {
         audio.srcObject = stream;
         console.log(`Attached stream from ${peerId} to audio element.`);
    } else {
         console.log(`Stream from ${peerId} already attached.`);
    }
}

// Remove the audio element for a disconnected peer
function removeRemoteAudio(peerId) {
    const audio = document.getElementById(`audio_${peerId}`);
    const label = document.getElementById(`label_${peerId}`);
    if (audio) {
        console.log(`Removing audio element for ${peerId}`);
        audio.srcObject = null; // Release stream resources
        audio.remove();
    }
    if (label) {
        label.remove();
    }
}

// Update the main status message based on connected peers
function updateStatus() {
    const peerCount = Object.keys(peerConnections).length;
     if (currentRoom) {
        const connectedPeers = Object.values(peerConnections)
                                     .filter(pc => pc.iceConnectionState === 'connected' || pc.iceConnectionState === 'completed')
                                     .length;
        statusDiv.innerText = `In room ${currentRoom}. Connected to ${connectedPeers} / ${peerCount} peer(s).`;
     }
     // If currentRoom is null, leaveCall or disconnect would have set the status already.
}

// --- Initial Setup ---
// Disable leave button initially
leaveBtn.disabled = true;
