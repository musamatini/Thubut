// webrtc.js

// Use 'const' for variables that won't be reassigned, 'let' for those that will.
const socket = io(); // Assumes server is running on the same host/port by default
const peerConnections = {}; // Store multiple peer connections { peerSocketId: RTCPeerConnection }
const earlyCandidates = {}; // { peerId: [candidate, candidate, ...] } - For buffering early ICE candidates

let localStream = null;
let currentRoom = null;
let isMuted = false;
let localAudioAnalyser = null; // For analysing local audio level
let audioContext = null;
let analysisFrameId = null; // To control the analysis loop

// UPDATED ICE Server Configuration
const config = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun.openrelay.metered.ca:80' }, // Using openrelay's STUN
        { // TURN over UDP (preferred by WebRTC usually)
            urls: 'turn:turn.openrelay.metered.ca:80',
            username: 'openrelayproject',
            credential: 'openrelayproject'
        },
        { // TURN over TCP (fallback)
            urls: 'turn:turn.openrelay.metered.ca:80?transport=tcp',
            username: 'openrelayproject',
            credential: 'openrelayproject'
        },
        { // TURN over TLS/UDP
            urls: 'turns:turn.openrelay.metered.ca:443',
            username: 'openrelayproject',
            credential: 'openrelayproject'
        },
        { // TURN over TLS/TCP (most robust fallback)
            urls: 'turns:turn.openrelay.metered.ca:443?transport=tcp',
            username: 'openrelayproject',
            credential: 'openrelayproject'
        }
    ]
};


const joinBtn = document.getElementById('joinBtn');
const leaveBtn = document.getElementById('leaveBtn');
const muteBtn = document.getElementById('muteBtn');
const roomInput = document.getElementById('room');
const statusDiv = document.getElementById('status');
const remoteAudiosDiv = document.getElementById('remoteAudios');
const participantListDiv = document.getElementById('participantList');


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
        localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
        statusDiv.innerText = "Microphone accessed. Setting up audio analysis...";
        console.log("Local stream obtained");

        setupAudioAnalysis();
        startAudioAnalysis();

        socket.emit("join_call", { room: currentRoom });
        console.log(`Emitted join_call for room: ${currentRoom}`);

        leaveBtn.disabled = false;
        muteBtn.disabled = false;
        statusDiv.innerText = `Joined room: ${currentRoom}. Waiting for peers...`;
        updateLocalUserUI();

    } catch (error) {
        console.error("Error accessing media devices or joining call:", error);
        statusDiv.innerText = `Error: ${error.message}. Check permissions and try again.`;
        cleanUpCall();
    }
}

function leaveCall() {
    if (!currentRoom) return;

    statusDiv.innerText = `Leaving room: ${currentRoom}...`;
    console.log(`Leaving room: ${currentRoom}`);
    socket.emit("leave_call", { room: currentRoom });
    cleanUpCall();
    statusDiv.innerText = "Left the call. Enter a Room ID to join again.";
    console.log("Leave call process completed.");
}

function cleanUpCall() {
    stopAudioAnalysis();
    if (audioContext && audioContext.state !== 'closed') {
        audioContext.close().catch(e => console.warn("Error closing audio context:", e));
        audioContext = null;
    }

    for (const peerId in peerConnections) {
        closePeerConnection(peerId);
    }
    // Clear any remaining early candidates
    for (const peerId in earlyCandidates) {
        delete earlyCandidates[peerId];
    }


    if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
        localStream = null;
        console.log("Local stream stopped.");
    }

    participantListDiv.innerHTML = '';
    remoteAudiosDiv.innerHTML = '';

    currentRoom = null;
    isMuted = false;

    roomInput.disabled = false;
    joinBtn.disabled = false;
    leaveBtn.disabled = true;
    muteBtn.disabled = true;
    muteBtn.innerText = 'Mute';
    muteBtn.classList.remove('muted');
}

function toggleMute(forceState = null) {
    if (!localStream) return;
    const targetMutedState = (forceState !== null) ? forceState : !isMuted;
    if (targetMutedState === isMuted) return;

    isMuted = targetMutedState;
    localStream.getAudioTracks().forEach(track => { track.enabled = !isMuted; });
    muteBtn.innerText = isMuted ? 'Unmute' : 'Mute';
    muteBtn.classList.toggle('muted', isMuted);
    updateLocalUserUI();
    console.log(isMuted ? "Microphone Muted" : "Microphone Unmuted");
}

function requestRemoteMute(targetSid) {
    if (!currentRoom) return;
    console.log(`Requesting mute for peer: ${targetSid}`);
    socket.emit('remote_mute_request', { room: currentRoom, target_sid: targetSid });
}

// --- Speaking Detection (using Web Audio API) ---
function setupAudioAnalysis() {
    if (!localStream || !localStream.getAudioTracks().length) {
        console.error("Cannot setup audio analysis: No local audio stream.");
        return;
    }
    try {
        audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const source = audioContext.createMediaStreamSource(localStream);
        localAudioAnalyser = audioContext.createAnalyser();
        localAudioAnalyser.fftSize = 512;
        localAudioAnalyser.smoothingTimeConstant = 0.1;
        source.connect(localAudioAnalyser);
        console.log("Audio analyser setup complete.");
    } catch (e) {
        console.error("Error setting up AudioContext or Analyser:", e);
        audioContext = null;
        localAudioAnalyser = null;
    }
}

let isSpeaking = false;
const speakingThreshold = 5;
const silenceDelay = 500;
let silenceTimer = null;

function analyseAudioLevel() {
    if (!localAudioAnalyser || !audioContext || audioContext.state === 'closed') return;

    const dataArray = new Uint8Array(localAudioAnalyser.frequencyBinCount);
    localAudioAnalyser.getByteFrequencyData(dataArray);
    let sum = 0;
    dataArray.forEach(value => sum += value);
    let average = sum / dataArray.length;
    const currentlySpeaking = average > speakingThreshold && !isMuted;

    if (currentlySpeaking) {
        clearTimeout(silenceTimer);
        silenceTimer = null;
        if (!isSpeaking) {
            isSpeaking = true;
            updateLocalUserUI();
            socket.emit('speaking_status', { room: currentRoom, speaking: true });
        }
    } else {
        if (isSpeaking && !silenceTimer) {
             silenceTimer = setTimeout(() => {
                 isSpeaking = false;
                 updateLocalUserUI();
                 socket.emit('speaking_status', { room: currentRoom, speaking: false });
                 silenceTimer = null;
             }, silenceDelay);
        }
    }
    analysisFrameId = requestAnimationFrame(analyseAudioLevel);
}

function startAudioAnalysis() {
    if (!analysisFrameId && localAudioAnalyser) {
         console.log("Starting audio analysis loop.");
         analyseAudioLevel();
    }
}

function stopAudioAnalysis() {
     if (analysisFrameId) {
        console.log("Stopping audio analysis loop.");
        cancelAnimationFrame(analysisFrameId);
        analysisFrameId = null;
        clearTimeout(silenceTimer);
        silenceTimer = null;
        if(isSpeaking) {
            isSpeaking = false;
            updateLocalUserUI();
            if (currentRoom) {
                socket.emit('speaking_status', { room: currentRoom, speaking: false });
            }
        }
     }
}

// --- Peer Connection Management ---
function createPeerConnection(peerId, isInitiator) {
    if (peerConnections[peerId]) {
        console.warn(`Peer connection for ${peerId} already exists.`);
        return peerConnections[peerId];
    }

    console.log(`Creating peer connection for ${peerId}, initiator: ${isInitiator}`);
    const pc = new RTCPeerConnection(config);
    peerConnections[peerId] = pc;
    earlyCandidates[peerId] = []; // Initialize buffer for this peer's early ICE candidates

    addParticipantUI(peerId, 'connecting');

    pc.onicecandidate = (event) => {
        if (event.candidate) {
            // console.log(`Sending ICE candidate to ${peerId}`, event.candidate);
            sendSignal(peerId, { candidate: event.candidate });
        }
    };

    pc.ontrack = (event) => {
        console.log(`Track received from ${peerId}`, event.streams);
        addRemoteAudioElement(peerId, event.streams[0]);
    };

    pc.oniceconnectionstatechange = () => {
        const state = pc.iceConnectionState;
        console.log(`ICE connection state for ${peerId}: ${state}`);
        updateParticipantUI(peerId, { connectionState: state });
        if (['failed', 'disconnected', 'closed'].includes(state)) {
            console.warn(`Connection with ${peerId} ${state}. Cleaning up.`);
            closePeerConnection(peerId);
        }
    };

    pc.onnegotiationneeded = async () => {
        // Only the initiator handles onnegotiationneeded by creating an offer
        // This simplifies glare handling significantly if only one side initiates.
        // The 'existing_peers' and subsequent offer/answer flow establishes this.
        // For re-negotiation, ensure a clear initiator or a more robust glare handling mechanism.
        if (isInitiator) {
            console.log(`Negotiation needed for ${peerId} (Initiator). Creating offer...`);
            try {
                if (pc.signalingState !== 'stable') {
                    console.warn(`Negotiation needed for ${peerId} but signaling state is ${pc.signalingState}. Waiting.`);
                    return;
                }
                const offer = await pc.createOffer();
                if (pc.signalingState !== 'stable') { // Double check before setting
                    console.warn(`Signaling state changed for ${peerId} before setLocalDescription. Aborting offer.`);
                    return;
                }
                await pc.setLocalDescription(offer);
                console.log(`Sending offer to ${peerId}`);
                sendSignal(peerId, { desc: pc.localDescription });
            } catch (error) {
                console.error(`Error creating/sending offer to ${peerId}:`, error);
            }
        } else {
            console.log(`Negotiation needed for ${peerId} (Non-Initiator). Usually waiting for offer. If this fires unexpectedly, review logic.`);
        }
    };

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

function closePeerConnection(peerId) {
    const pc = peerConnections[peerId];
    if (pc) {
        console.log(`Closing peer connection with ${peerId}`);
        pc.onicecandidate = null;
        pc.ontrack = null;
        pc.oniceconnectionstatechange = null;
        pc.onnegotiationneeded = null;
        // Stop any transceivers (important for clean shutdown)
        if (pc.getTransceivers) {
            pc.getTransceivers().forEach(transceiver => {
                if (transceiver.stop) {
                    transceiver.stop();
                }
            });
        }
        pc.close();
        delete peerConnections[peerId];
        delete earlyCandidates[peerId]; // Clear any early candidates for this peer
        removeParticipantUI(peerId);
        removeRemoteAudioElement(peerId);
        updateOverallStatus();
    }
}

// --- Signaling ---
function sendSignal(toId, signalPayload) {
    socket.emit('signal', { to_sid: toId, signal: signalPayload });
}

socket.on('signal', async (data) => {
    const fromId = data.from_sid;
    const signal = data.signal;
    let pc = peerConnections[fromId];

    // console.log(`Signal received from ${fromId}:`, signal.type || (signal.candidate ? 'candidate' : 'unknown'));

    if (signal.desc && signal.desc.type === 'offer' && !pc) {
        console.log(`Received offer from new peer ${fromId}. Creating connection as non-initiator.`);
        pc = createPeerConnection(fromId, false); // We are receiving offer, so we are not initiator
    } else if (!pc) {
        console.warn(`Received signal from unknown or already closed peer ${fromId}. Ignoring. Signal:`, signal);
        return;
    }

    try {
        if (signal.desc) { // Handle Offer or Answer
            // Basic glare handling: prefer 'stable' state for offers, 'have-local-offer' for answers
            const currentSignalingState = pc.signalingState;
            const isOffer = signal.desc.type === 'offer';
            const isAnswer = signal.desc.type === 'answer';

            if (isOffer && currentSignalingState !== 'stable' && currentSignalingState !== 'have-remote-offer') {
                console.warn(`Offer received from ${fromId} in unexpected state ${currentSignalingState}. Might be glare. Ignoring for now.`);
                // More sophisticated glare handling might involve rollback or specific flags.
                return;
            }
            if (isAnswer && currentSignalingState !== 'have-local-offer') {
                console.warn(`Answer received from ${fromId} in unexpected state ${currentSignalingState}. Ignoring.`);
                return;
            }

            console.log(`Setting remote description (${signal.desc.type}) from ${fromId}`);
            await pc.setRemoteDescription(new RTCSessionDescription(signal.desc));

            // After setting remote description, process any buffered ICE candidates
            if (earlyCandidates[fromId] && earlyCandidates[fromId].length > 0) {
                console.log(`Processing ${earlyCandidates[fromId].length} buffered ICE candidates for ${fromId}`);
                for (const candidate of earlyCandidates[fromId]) {
                    try {
                        await pc.addIceCandidate(candidate);
                        // console.log(`Added buffered ICE candidate for ${fromId}`);
                    } catch (e) {
                        console.error(`Error adding buffered ICE candidate for ${fromId}:`, e);
                    }
                }
                earlyCandidates[fromId] = []; // Clear buffer
            }

            if (isOffer) {
                console.log(`Creating answer for ${fromId}`);
                const answer = await pc.createAnswer();
                await pc.setLocalDescription(answer);
                console.log(`Sending answer to ${fromId}`);
                sendSignal(fromId, { desc: pc.localDescription });
            }
        } else if (signal.candidate) { // Handle ICE Candidate
            const candidate = new RTCIceCandidate(signal.candidate);
            if (pc.remoteDescription && pc.remoteDescription.type) {
                 try {
                    // console.log(`Adding ICE candidate from ${fromId}`);
                    await pc.addIceCandidate(candidate);
                 } catch (e) {
                    // This can happen if candidates are malformed or arrive for a closed connection.
                    console.error(`Error adding received ICE candidate for ${fromId}:`, e);
                 }
            } else {
                 console.warn(`Remote description not set for ${fromId}. Buffering ICE candidate.`);
                 earlyCandidates[fromId].push(candidate); // Buffer it
            }
        }
    } catch (error) {
        console.error(`Error handling signal from ${fromId} (signal: ${JSON.stringify(signal)}):`, error);
        // closePeerConnection(fromId); // Consider this for critical errors
    }
});


// --- Server Events Handling ---
socket.on('existing_peers', (data) => {
    const existingPeerSids = data.sids;
    console.log(`Received existing peers: ${existingPeerSids.join(', ')}`);
    statusDiv.innerText = `In room ${currentRoom}. Connecting to ${existingPeerSids.length} existing peer(s)...`;

    if (!localStream) {
        console.error("Local stream not ready when 'existing_peers' received!");
        statusDiv.innerText = "Error: Microphone not ready. Cannot connect to peers.";
        return;
    }

    existingPeerSids.forEach(peerId => {
         if (peerId === socket.id) return; // Don't connect to self
         console.log(`Initiating connection to existing peer ${peerId}`);
         createPeerConnection(peerId, true); // New joiner is initiator to existing peers
    });
    updateOverallStatus();
});

socket.on('peer_joined', (data) => {
    const newPeerId = data.sid;
    if (newPeerId === socket.id) return; // Ignore self-join notification

    console.log(`Peer joined: ${newPeerId}`);
    // Don't create connection here. The new peer will initiate with an offer.
    // We just add UI placeholder. The 'signal' handler (on offer) will create the PeerConnection.
    addParticipantUI(newPeerId, 'new');
    statusDiv.innerText = `Peer ${newPeerId.substring(0, 6)}... joined. Waiting for their connection...`;
    updateOverallStatus();
});

socket.on('peer_left', (data) => {
    const leftPeerId = data.sid;
    console.log(`Peer left: ${leftPeerId}`);
    closePeerConnection(leftPeerId);
    statusDiv.innerText = `Peer ${leftPeerId.substring(0, 6)}... left the room.`;
    updateOverallStatus();
});

socket.on('speaking_status', (data) => {
    updateParticipantUI(data.sid, { speaking: data.speaking });
});

socket.on('force_mute', () => {
    console.log("Received request to mute from another peer.");
    toggleMute(true); // Force mute
});

// --- Socket.IO Connection Handling ---
socket.on('connect_error', (error) => {
  console.error('Socket.IO connection error:', error);
  statusDiv.innerText = `Connection Error: ${error.message}. Server might be down.`;
  cleanUpCall();
  joinBtn.disabled = false;
  roomInput.disabled = false;
});

socket.on('disconnect', (reason) => {
  console.log(`Socket.IO disconnected: ${reason}`);
  statusDiv.innerText = `Disconnected: ${reason}. Try rejoining.`;
  cleanUpCall();
  joinBtn.disabled = false;
  roomInput.disabled = false;
});


// --- UI Helper Functions ---
function updateLocalUserUI() {
    let localDiv = document.getElementById('participant_local');
    if (!localDiv && currentRoom) {
        localDiv = document.createElement('div');
        localDiv.id = 'participant_local';
        localDiv.className = 'participant local';
        participantListDiv.prepend(localDiv);
    }
    if (localDiv) {
        const localIdShort = socket.id ? socket.id.substring(0, 6) : 'connecting';
        localDiv.innerHTML = `
            <span class="participant-info">You (${localIdShort}...)</span>
            <span class="participant-status local-status ${isMuted ? 'muted' : ''}">
                ${isMuted ? 'Muted' : 'Mic On'}
            </span>
        `;
        localDiv.classList.toggle('speaking', isSpeaking && !isMuted);
    }
}

function addParticipantUI(peerId, initialState = 'connecting') {
    if (document.getElementById(`participant_${peerId}`)) return;
    const participantDiv = document.createElement('div');
    participantDiv.id = `participant_${peerId}`;
    participantDiv.className = 'participant remote';
    participantDiv.innerHTML = `
        <span class="participant-info">Peer (${peerId.substring(0, 6)}...)</span>
        <span class="participant-status status-${initialState}">${initialState}</span>
        <button class="mute-peer-btn" onclick="requestRemoteMute('${peerId}')" title="Request Mute">Mute</button>
    `;
    participantListDiv.appendChild(participantDiv);
}

function updateParticipantUI(peerId, updates) {
    const participantDiv = document.getElementById(`participant_${peerId}`);
    if (!participantDiv) return;

    if (updates.connectionState) {
        const statusSpan = participantDiv.querySelector('.participant-status');
        if (statusSpan) {
             let stateClass = updates.connectionState.toLowerCase();
             if (stateClass === 'new') stateClass = 'connecting';
             if (stateClass === 'completed') stateClass = 'connected';
            statusSpan.textContent = stateClass;
            statusSpan.className = 'participant-status';
            statusSpan.classList.add(`status-${stateClass}`);
        }
    }
    if (updates.speaking !== undefined) {
        participantDiv.classList.toggle('speaking', updates.speaking);
    }
}

function removeParticipantUI(peerId) {
    const participantDiv = document.getElementById(`participant_${peerId}`);
    if (participantDiv) participantDiv.remove();
}

function addRemoteAudioElement(peerId, stream) {
    let audio = document.getElementById(`audio_${peerId}`);
    if (!audio) {
        console.log(`Creating hidden audio element for ${peerId}`);
        audio = document.createElement('audio');
        audio.id = `audio_${peerId}`;
        audio.autoplay = true;
        // audio.playsInline = true; // Good for mobile
        remoteAudiosDiv.appendChild(audio);
    }
    if (audio.srcObject !== stream) {
         audio.srcObject = stream;
         console.log(`Attached stream from ${peerId} to hidden audio element.`);
         audio.play().catch(e => console.warn("Audio play failed for remote stream:", e)); // Attempt to play
    }
}

function removeRemoteAudioElement(peerId) {
    const audio = document.getElementById(`audio_${peerId}`);
    if (audio) {
        console.log(`Removing hidden audio element for ${peerId}`);
        audio.srcObject = null;
        audio.remove();
    }
}

function updateOverallStatus() {
    if (!currentRoom) return;
    const peerCount = Object.keys(peerConnections).length;
    const connectedPeers = Object.values(peerConnections)
                                 .filter(pc => pc.iceConnectionState === 'connected' || pc.iceConnectionState === 'completed')
                                 .length;
    if (peerCount === 0) {
        statusDiv.innerText = `In room ${currentRoom}. Waiting for others...`;
    } else {
        statusDiv.innerText = `In room ${currentRoom}. Peers: ${connectedPeers} connected / ${peerCount} total.`;
    }
}

// --- Initial Setup ---
leaveBtn.disabled = true;
muteBtn.disabled = true;
joinBtn.addEventListener('click', joinCall);
leaveBtn.addEventListener('click', leaveCall);
muteBtn.addEventListener('click', () => toggleMute());

console.log("WebRTC script loaded. Ready to join. ICE Config:", config.iceServers);