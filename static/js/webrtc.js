// Use 'const' for variables that won't be reassigned, 'let' for those that will.
const socket = io(); // Assumes server is running on the same host/port by default
const peerConnections = {}; // Store multiple peer connections { peerSocketId: RTCPeerConnection }
let localStream = null;
let currentRoom = null;
let isMuted = false;
let localAudioAnalyser = null; // For analysing local audio level
let audioContext = null;
let analysisFrameId = null; // To control the analysis loop

// webrtc.js (Updated config section)

const config = {
    iceServers: [
        {
          urls: "stun:stun.relay.metered.ca:80",
        },
        {
          urls: "turn:global.relay.metered.ca:80",
          username: "1438a562f19154f681c1fd38",
          credential: "sb45mPwHRtbISrS+",
        },
        {
          urls: "turn:global.relay.metered.ca:80?transport=tcp",
          username: "1438a562f19154f681c1fd38",
          credential: "sb45mPwHRtbISrS+",
        },
        {
          urls: "turn:global.relay.metered.ca:443",
          username: "1438a562f19154f681c1fd38",
          credential: "sb45mPwHRtbISrS+",
        },
        {
          urls: "turns:global.relay.metered.ca:443?transport=tcp",
          username: "1438a562f19154f681c1fd38",
          credential: "sb45mPwHRtbISrS+",
        },
    ],
};

const joinBtn = document.getElementById('joinBtn');
const leaveBtn = document.getElementById('leaveBtn');
const muteBtn = document.getElementById('muteBtn');
const roomInput = document.getElementById('room');
const statusDiv = document.getElementById('status');
const remoteAudiosDiv = document.getElementById('remoteAudios'); // Hidden container for <audio>
// REMOVED: const localAudio = document.getElementById('localAudio');
const participantListDiv = document.getElementById('participantList');
// REMOVED: const localUserStatusDiv = document.getElementById('localUserStatus');


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
        // REMOVED: localAudio.srcObject = localStream; // No longer playing local audio back
        statusDiv.innerText = "Microphone accessed. Setting up audio analysis...";
        console.log("Local stream obtained");

        // 1.5 Setup local audio analysis for speaking detection
        setupAudioAnalysis();
        startAudioAnalysis(); // Start the loop

        // 2. Emit join_call to the server
        socket.emit("join_call", { room: currentRoom });
        console.log(`Emitted join_call for room: ${currentRoom}`);

        // Update UI
        leaveBtn.disabled = false;
        muteBtn.disabled = false;
        statusDiv.innerText = `Joined room: ${currentRoom}. Waiting for peers...`;
        updateLocalUserUI(); // Show local user in participant list

    } catch (error) {
        console.error("Error accessing media devices or joining call:", error);
        statusDiv.innerText = `Error: ${error.message}. Check permissions and try again.`;
        // Reset UI state if failed
        cleanUpCall(); // Use a dedicated cleanup function
    }
}

function leaveCall() {
    if (!currentRoom) return;

    statusDiv.innerText = `Leaving room: ${currentRoom}...`;
    console.log(`Leaving room: ${currentRoom}`);

    // 1. Notify server
    socket.emit("leave_call", { room: currentRoom });

    // 2. Perform cleanup
    cleanUpCall();

    // 3. Final UI update
    statusDiv.innerText = "Left the call. Enter a Room ID to join again.";
    console.log("Leave call process completed.");
}

// Centralized cleanup function
function cleanUpCall() {
    // Stop audio analysis
    stopAudioAnalysis();
    if (audioContext && audioContext.state !== 'closed') {
        audioContext.close();
        audioContext = null;
    }

    // Close all peer connections
    for (const peerId in peerConnections) {
        closePeerConnection(peerId); // This also removes participant UI
    }

    // Stop local media stream
    if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
        localStream = null;
        // REMOVED: localAudio.srcObject = null;
        console.log("Local stream stopped.");
    }

    // Clear participant list (except potentially local user if needed)
    participantListDiv.innerHTML = '';
    remoteAudiosDiv.innerHTML = ''; // Clear hidden audio elements

    // Reset state variables
    currentRoom = null;
    isMuted = false; // Ensure mute state is reset

    // Reset UI elements
    roomInput.disabled = false;
    joinBtn.disabled = false;
    leaveBtn.disabled = true;
    muteBtn.disabled = true;
    muteBtn.innerText = 'Mute';
    muteBtn.classList.remove('muted');
    // REMOVED: localUserStatusDiv.innerText = 'Mic Check';
    // REMOVED: localUserStatusDiv.className = 'user-status'; // Reset class
}

// --- Mute/Unmute ---
// Modified to accept an optional forceState (true for mute, false for unmute)
function toggleMute(forceState = null) {
    if (!localStream) return;

    const targetMutedState = (forceState !== null) ? forceState : !isMuted;

    if (targetMutedState === isMuted) {
        console.log(`Already ${isMuted ? 'muted' : 'unmuted'}. No change.`);
        return; // Already in the desired state
    }

    isMuted = targetMutedState;

    localStream.getAudioTracks().forEach(track => {
        track.enabled = !isMuted;
    });

    // Update Button UI
    muteBtn.innerText = isMuted ? 'Unmute' : 'Mute';
    muteBtn.classList.toggle('muted', isMuted);

    // Update Local Participant UI in the list
    updateLocalUserUI();

    console.log(isMuted ? "Microphone Muted" : "Microphone Unmuted");

    // Optional: Signal mute status to others for UI feedback (not implemented here)
    // socket.emit('mute_status', { room: currentRoom, muted: isMuted });
}

// --- NEW: Function to request muting another peer ---
function requestRemoteMute(targetSid) {
    if (!currentRoom) return;
    console.log(`Requesting mute for peer: ${targetSid}`);
    socket.emit('remote_mute_request', { room: currentRoom, target_sid: targetSid });
    // Note: We don't visually update the remote peer's button here.
    // The mute action happens on their side. For visual confirmation,
    // they would need to emit their mute status back.
}

// --- Speaking Detection (using Web Audio API) ---
// (No changes needed in setupAudioAnalysis, analyseAudioLevel, startAudioAnalysis, stopAudioAnalysis)
function setupAudioAnalysis() {
    if (!localStream || !localStream.getAudioTracks().length) {
        console.error("Cannot setup audio analysis: No local audio stream.");
        return;
    }
    try {
        audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const source = audioContext.createMediaStreamSource(localStream);
        localAudioAnalyser = audioContext.createAnalyser();
        localAudioAnalyser.fftSize = 512; // Smaller FFT size for faster response
        localAudioAnalyser.smoothingTimeConstant = 0.1; // Some smoothing
        source.connect(localAudioAnalyser);
        // DO NOT connect analyser to destination - we only want to analyse
        console.log("Audio analyser setup complete.");
    } catch (e) {
        console.error("Error setting up AudioContext or Analyser:", e);
        audioContext = null; // Ensure it's null if setup failed
        localAudioAnalyser = null;
    }
}

let isSpeaking = false;
const speakingThreshold = 5; // Adjust this threshold based on mic sensitivity (0-255)
const silenceDelay = 500; // milliseconds of silence before stopping speaking state
let silenceTimer = null;

function analyseAudioLevel() {
    if (!localAudioAnalyser || !audioContext || audioContext.state === 'closed') {
         // console.log("Audio analysis stopped or not ready.");
         return; // Stop if analyser/context is gone
    }

    const dataArray = new Uint8Array(localAudioAnalyser.frequencyBinCount);
    localAudioAnalyser.getByteFrequencyData(dataArray);

    let sum = 0;
    for (let i = 0; i < dataArray.length; i++) {
        sum += dataArray[i];
    }
    let average = sum / dataArray.length;

    const currentlySpeaking = average > speakingThreshold && !isMuted; // Don't show speaking if muted

    if (currentlySpeaking) {
        // If speaking starts or continues
        clearTimeout(silenceTimer); // Reset silence timer
        silenceTimer = null;
        if (!isSpeaking) {
            isSpeaking = true;
            // console.log("Started Speaking");
            updateLocalUserUI(); // Update local UI immediately
            socket.emit('speaking_status', { room: currentRoom, speaking: true });
        }
    } else {
        // If silence is detected
        if (isSpeaking && !silenceTimer) {
             // Start timer only if currently marked as speaking
             silenceTimer = setTimeout(() => {
                 isSpeaking = false;
                 // console.log("Stopped Speaking");
                 updateLocalUserUI(); // Update local UI
                 socket.emit('speaking_status', { room: currentRoom, speaking: false });
                 silenceTimer = null;
             }, silenceDelay);
        }
    }

    // Request next frame
    analysisFrameId = requestAnimationFrame(analyseAudioLevel);
}

function startAudioAnalysis() {
    if (!analysisFrameId && localAudioAnalyser) {
         console.log("Starting audio analysis loop.");
         analyseAudioLevel(); // Start the loop
    }
}

function stopAudioAnalysis() {
     if (analysisFrameId) {
        console.log("Stopping audio analysis loop.");
        cancelAnimationFrame(analysisFrameId);
        analysisFrameId = null;
        clearTimeout(silenceTimer); // Clear any pending silence timer
        silenceTimer = null;
        // If user was speaking when analysis stopped, send stop event
        if(isSpeaking) {
            isSpeaking = false;
            updateLocalUserUI();
            // Check room exists before emitting on cleanup
            if (currentRoom) {
                socket.emit('speaking_status', { room: currentRoom, speaking: false });
            }
        }
     }
}

// --- Peer Connection Management ---
// (No changes needed in createPeerConnection, closePeerConnection)
function createPeerConnection(peerId, isInitiator) {
    if (peerConnections[peerId]) {
        console.warn(`Peer connection for ${peerId} already exists.`);
        return peerConnections[peerId]; // Avoid duplicates
    }

    console.log(`Creating peer connection for ${peerId}, initiator: ${isInitiator}`);
    const pc = new RTCPeerConnection(config);
    peerConnections[peerId] = pc;

    // Add participant UI element (initially in 'connecting' state)
    addParticipantUI(peerId, 'connecting'); // MODIFIED: Includes Mute button

    // --- Event Handlers for the Peer Connection ---

    pc.onicecandidate = (event) => {
        if (event.candidate) {
            // console.log(`Sending ICE candidate to ${peerId}`); // Can be noisy
            sendSignal(peerId, { candidate: event.candidate });
        }
    };

    pc.ontrack = (event) => {
        console.log(`Track received from ${peerId}`);
        // Attach stream to a hidden audio element
        addRemoteAudioElement(peerId, event.streams[0]);
    };

    pc.oniceconnectionstatechange = () => {
        const state = pc.iceConnectionState;
        console.log(`ICE connection state for ${peerId}: ${state}`);
        // Update the participant's UI with the connection state
        updateParticipantUI(peerId, { connectionState: state });

        if (state === 'failed' || state === 'disconnected' || state === 'closed') {
            console.warn(`Connection with ${peerId} ${state}. Cleaning up.`);
            // Consider closing proactively on 'failed' or 'disconnected' after a timeout
             closePeerConnection(peerId);
        }
    };

    pc.onnegotiationneeded = async () => {
        if (isInitiator) {
             console.log(`Negotiation needed for ${peerId} (Initiator). Creating offer...`);
             try {
                 // Check signaling state to prevent glare issues if possible
                 if (pc.signalingState !== 'stable') {
                     console.warn(`Negotiation needed fired for ${peerId} but signaling state is ${pc.signalingState}. Waiting.`);
                     return;
                 }
                 const offer = await pc.createOffer();
                 // Check state again before setting local description
                 if (pc.signalingState !== 'stable') {
                     console.warn(`Signaling state changed for ${peerId} before setting local description. Aborting offer.`);
                     return;
                 }
                 await pc.setLocalDescription(offer);
                 console.log(`Sending offer to ${peerId}`);
                 sendSignal(peerId, { desc: pc.localDescription });
             } catch (error) {
                 console.error(`Error creating/sending offer to ${peerId}:`, error);
             }
        } else {
             console.log(`Negotiation needed for ${peerId} (Non-Initiator). Waiting for offer.`);
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

function closePeerConnection(peerId) {
    const pc = peerConnections[peerId];
    if (pc) {
        console.log(`Closing peer connection with ${peerId}`);
        pc.onicecandidate = null;
        pc.ontrack = null;
        pc.oniceconnectionstatechange = null;
        pc.onnegotiationneeded = null;
        pc.close();
        delete peerConnections[peerId];
        removeParticipantUI(peerId); // Remove participant from list
        removeRemoteAudioElement(peerId); // Remove hidden audio element
        updateOverallStatus(); // Update general status message
    }
}

// --- Signaling ---
// (No changes needed in sendSignal, socket.on('signal'))
function sendSignal(toId, signalPayload) {
     // console.log(`Sending signal to ${toId}:`, signalPayload.type || (signalPayload.candidate ? 'candidate' : 'desc')); // Debug
    socket.emit('signal', {
        to_sid: toId,
        signal: signalPayload
    });
}

socket.on('signal', async (data) => {
    const fromId = data.from_sid;
    const signal = data.signal;

    // console.log(`Signal received from ${fromId}:`, signal.type || (signal.candidate ? 'candidate' : 'unknown'));

    let pc = peerConnections[fromId];

    // If receiving an offer, and connection doesn't exist, create it (as non-initiator)
    if (signal.desc && signal.desc.type === 'offer' && !pc) {
        console.log(`Received offer from new peer ${fromId}. Creating connection.`);
        pc = createPeerConnection(fromId, false); // We are receiving offer, so we are not initiator
    } else if (!pc) {
        console.warn(`Received signal from unknown or closing peer ${fromId}. Ignoring.`);
        return; // Ignore signals if connection isn't expected or is closing
    }

    try {
        if (signal.desc) { // Handle Offer or Answer
             // Check signaling state before setting remote description (helps with glare)
            const currentSignalingState = pc.signalingState;
            const isStable = currentSignalingState === 'stable';
            const offerCollision = signal.desc.type === 'offer' && !isStable; // Received offer when not stable
            const answerCollision = signal.desc.type === 'answer' && currentSignalingState !== 'have-local-offer'; // Received answer without sending offer

            if (offerCollision || answerCollision) {
                console.warn(`Signaling collision detected for ${fromId}. Current state: ${currentSignalingState}, received: ${signal.desc.type}. Ignoring or handling needed.`);
                // Simple approach: ignore the incoming description for now. More complex handling is possible.
                return;
            }

            console.log(`Setting remote description (${signal.desc.type}) from ${fromId}`);
            await pc.setRemoteDescription(new RTCSessionDescription(signal.desc));

            if (signal.desc.type === 'offer') {
                console.log(`Creating answer for ${fromId}`);
                const answer = await pc.createAnswer();
                await pc.setLocalDescription(answer);
                console.log(`Sending answer to ${fromId}`);
                sendSignal(fromId, { desc: pc.localDescription });
            }
             // If it was an answer, the offer/answer exchange is complete for this side
        } else if (signal.candidate) { // Handle ICE Candidate
            // Add candidate only if remote description is set
            if (pc.remoteDescription) {
                 // console.log(`Adding ICE candidate from ${fromId}`); // Noisy
                 await pc.addIceCandidate(new RTCIceCandidate(signal.candidate));
            } else {
                 console.warn(`Received ICE candidate from ${fromId} before remote description was set. Buffering or ignoring needed.`);
                 // Basic approach: ignore. More complex: buffer candidates.
            }
        }
    } catch (error) {
        console.error(`Error handling signal from ${fromId}:`, error);
        // Consider closing the connection on critical errors
        // closePeerConnection(fromId);
    }
});


// --- Server Events Handling ---
// (No changes needed in existing_peers, peer_joined, peer_left, speaking_status)
socket.on('existing_peers', (data) => {
    const existingPeerSids = data.sids;
    console.log(`Received existing peers: ${existingPeerSids.join(', ')}`);
    statusDiv.innerText = `In room ${currentRoom}. Connecting to ${existingPeerSids.length} existing peer(s)...`;

    if (!localStream) {
        console.error("Local stream not ready when 'existing_peers' received!");
        statusDiv.innerText = "Error: Microphone not ready. Cannot connect to peers.";
        return;
    }

    // Initiate connection to each existing peer
    existingPeerSids.forEach(peerId => {
         console.log(`Initiating connection to existing peer ${peerId}`);
         createPeerConnection(peerId, true); // Create connection (as initiator)
    });
    updateOverallStatus();
});

socket.on('peer_joined', (data) => {
    const newPeerId = data.sid;
    console.log(`Peer joined: ${newPeerId}`);
    // Don't create connection here. Wait for their offer signal.
    // The 'signal' handler will create the PeerConnection when the offer arrives.
    // Add placeholder UI - will be updated by signal handler/ICE state changes
    addParticipantUI(newPeerId, 'new'); // Indicate they just joined (includes Mute button)
    statusDiv.innerText = `Peer ${newPeerId.substring(0, 6)}... joined the room. Waiting for connection...`;
    updateOverallStatus();
});

socket.on('peer_left', (data) => {
    const leftPeerId = data.sid;
    console.log(`Peer left: ${leftPeerId}`);
    closePeerConnection(leftPeerId); // Clean up connection and UI
    statusDiv.innerText = `Peer ${leftPeerId.substring(0, 6)}... left the room.`;
    updateOverallStatus();
});

socket.on('speaking_status', (data) => {
    const peerId = data.sid;
    const speaking = data.speaking;
    // console.log(`Peer ${peerId} speaking: ${speaking}`);
    updateParticipantUI(peerId, { speaking: speaking });
});

// --- NEW: Listener for remote mute request ---
socket.on('force_mute', () => {
    console.log("Received request to mute from another peer.");
    // Force mute state to true
    toggleMute(true);
});


// --- Socket.IO Connection Handling ---
// (No changes needed in connect_error, disconnect)
socket.on('connect_error', (error) => {
  console.error('Socket.IO connection error:', error);
  statusDiv.innerText = `Connection Error: ${error.message}. Server might be down.`;
  cleanUpCall(); // Clean up the call state
  // Keep UI elements enabled to allow re-attempting join
  joinBtn.disabled = false;
  roomInput.disabled = false;
});

socket.on('disconnect', (reason) => {
  console.log(`Socket.IO disconnected: ${reason}`);
  if (reason === 'io server disconnect') {
        // Server initiated disconnect (e.g., kicked)
        statusDiv.innerText = "Disconnected by the server.";
  } else {
        // Client initiated or network issue
        statusDiv.innerText = `Disconnected: ${reason}. Attempting to reconnect or rejoin manually.`;
  }
  cleanUpCall(); // Clean up WebRTC state
  // Let Socket.IO attempt reconnection automatically if configured,
  // otherwise user needs to manually rejoin. Keep UI ready.
  joinBtn.disabled = false;
  roomInput.disabled = false;
});


// --- UI Helper Functions ---

// Adds or updates the local user's representation in the participant list
function updateLocalUserUI() {
    // This function now ONLY updates the entry in the participant list
    let localDiv = document.getElementById('participant_local');
    if (!localDiv && currentRoom) { // Only add if in a room
        localDiv = document.createElement('div');
        localDiv.id = 'participant_local';
        localDiv.className = 'participant local'; // Add 'local' class
        participantListDiv.prepend(localDiv); // Add local user to the top
    }

    if (localDiv) {
        const localIdShort = socket.id ? socket.id.substring(0, 6) : 'connecting';
        localDiv.innerHTML = `
            <span class="participant-info">You (${localIdShort}...)</span>
            <span class="participant-status local-status ${isMuted ? 'muted' : ''}">
                ${isMuted ? 'Muted' : 'Mic On'}
            </span>
            <!-- No separate mute button for yourself here, use the main one -->
        `;
        // Update speaking class based on local state
        localDiv.classList.toggle('speaking', isSpeaking && !isMuted);
    }
}


// MODIFIED: Adds a UI element for a remote participant WITH a mute button
function addParticipantUI(peerId, initialState = 'connecting') {
    if (document.getElementById(`participant_${peerId}`)) return; // Already exists

    const participantDiv = document.createElement('div');
    participantDiv.id = `participant_${peerId}`;
    participantDiv.className = 'participant remote'; // Add 'remote' class

    // Initial content including the Mute button
    participantDiv.innerHTML = `
        <span class="participant-info">Peer (${peerId.substring(0, 6)}...)</span>
        <span class="participant-status status-${initialState}">${initialState}</span>
        <button class="mute-peer-btn" onclick="requestRemoteMute('${peerId}')">Mute Peer</button>
    `;
    // Add specific CSS class 'mute-peer-btn' if needed for styling

    participantListDiv.appendChild(participantDiv);
}

// Updates specific parts of a participant's UI element
// (No changes needed here, but could be extended to show remote mute status if signaled)
function updateParticipantUI(peerId, updates) {
    const participantDiv = document.getElementById(`participant_${peerId}`);
    if (!participantDiv) return; // No UI element found

    // Update Connection State
    if (updates.connectionState) {
        const statusSpan = participantDiv.querySelector('.participant-status');
        if (statusSpan) {
             // Normalize states for consistent class naming
             let stateClass = updates.connectionState.toLowerCase();
             if (stateClass === 'new') stateClass = 'connecting'; // Treat 'new' visually as 'connecting'
             if (stateClass === 'completed') stateClass = 'connected'; // Treat 'completed' as 'connected'

            statusSpan.textContent = stateClass;
            // Remove old status classes before adding new one
             statusSpan.className = 'participant-status'; // Reset base class
             statusSpan.classList.add(`status-${stateClass}`);
        }
    }

    // Update Speaking Indicator
    if (updates.speaking !== undefined) { // Check for boolean value explicitly
        participantDiv.classList.toggle('speaking', updates.speaking);
    }

    // Update Mute Status (Could be implemented if remote peers signal their mute state back)
    // if (updates.muted !== undefined) {
    //     participantDiv.classList.toggle('muted-remote', updates.muted); // Add a class like 'muted-remote'
    //     // Change the "Mute Peer" button text or appearance if needed
    //     const muteButton = participantDiv.querySelector('.mute-peer-btn');
    //     if (muteButton) {
    //         muteButton.textContent = updates.muted ? 'Unmute Peer' : 'Mute Peer'; // Example
    //     }
    // }
}


// Removes a participant's UI element
// (No changes needed here)
function removeParticipantUI(peerId) {
    const participantDiv = document.getElementById(`participant_${peerId}`);
    if (participantDiv) {
        participantDiv.remove();
    }
}

// Add a hidden audio element for a remote peer's stream
// (No changes needed here)
function addRemoteAudioElement(peerId, stream) {
    let audio = document.getElementById(`audio_${peerId}`);
    if (!audio) {
        console.log(`Creating hidden audio element for ${peerId}`);
        audio = document.createElement('audio');
        audio.id = `audio_${peerId}`;
        audio.autoplay = true;
        // audio.controls = true; // Keep hidden
        remoteAudiosDiv.appendChild(audio);
    }
    if (audio.srcObject !== stream) {
         audio.srcObject = stream;
         console.log(`Attached stream from ${peerId} to hidden audio element.`);
    }
}

// Remove the hidden audio element for a disconnected peer
// (No changes needed here)
function removeRemoteAudioElement(peerId) {
    const audio = document.getElementById(`audio_${peerId}`);
    if (audio) {
        console.log(`Removing hidden audio element for ${peerId}`);
        audio.srcObject = null;
        audio.remove();
    }
}

// Update the main status message based on connected peers
// (No changes needed here)
function updateOverallStatus() {
    if (!currentRoom) return;

    const peerCount = Object.keys(peerConnections).length;
    const connectedPeers = Object.values(peerConnections)
                                 .filter(pc => pc.iceConnectionState === 'connected' || pc.iceConnectionState === 'completed')
                                 .length;

    if (peerCount === 0) {
        statusDiv.innerText = `In room ${currentRoom}. Waiting for others to join...`;
    } else {
        statusDiv.innerText = `In room ${currentRoom}. Connected to ${connectedPeers} / ${peerCount} peer(s).`;
    }
}

// --- Initial Setup ---
// Disable buttons appropriately at start
leaveBtn.disabled = true;
muteBtn.disabled = true;

console.log("WebRTC script loaded. Ready to join.");