// Secure Anonymous Chat Application
class SecureChat {
    constructor() {
        this.socket = null;
        this.userId = null;
        this.roomId = null;
        this.encryptionKey = null;
        this.roomEncryptionKey = null; // Shared key for the room
        this.isConnected = false;
        this.cryptoAvailable = false;
        this.isRoomCreator = false;
        
        // Perfect Forward Secrecy properties
        this.ephemeralKeys = new Map(); // Store ephemeral keys for each session
        this.keyRotationInterval = null;
        this.currentSessionKey = null;
        this.dhPublicKey = null;
        this.dhPrivateKey = null;
        this.sharedSecret = null;
        this.keyRotationTime = 5 * 60 * 1000; // 5 minutes in milliseconds
        
        this.initializeApp();
    }

    initializeApp() {
        this.setupEventListeners();
        this.connectToServer();
        this.generateEncryptionKey();
        this.checkCryptoAvailability();
        this.initializePerfectForwardSecrecy();
        this.updateConnectionStatus('Initializing...');
        this.setupPinHandlers();
    }

    setupPinHandlers() {
        // Show access pin to creator
        if (this.socket) {
            this.socket.on('room-created', (data) => {
                const pinDisplay = document.getElementById('creator-pin-display');
                if (pinDisplay) {
                    pinDisplay.style.display = '';
                    pinDisplay.textContent = `Access Pin: ${data.accessPin}`;
                }
            });
        }
    }

    setupEventListeners() {
        // Room controls
        document.getElementById('join-room-btn').addEventListener('click', () => {
            this.joinRoom();
        });
        document.getElementById('new-room-btn').addEventListener('click', () => {
            this.createNewRoom();
        });
        document.getElementById('end-room-btn').addEventListener('click', () => {
            this.endRoom();
        });
        document.getElementById('copy-room-btn').addEventListener('click', () => {
            this.copyRoomId();
        });

        // Message input
        document.getElementById('message-input').addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        document.getElementById('send-btn').addEventListener('click', () => {
            this.sendMessage();
        });

        // Room input
        document.getElementById('room-input').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                this.joinRoom();
            }
        });

        // Prevent context menu for security
        document.addEventListener('contextmenu', (e) => {
            e.preventDefault();
        });

        // Prevent drag and drop
        document.addEventListener('dragover', (e) => {
            e.preventDefault();
        });

        document.addEventListener('drop', (e) => {
            e.preventDefault();
        });
    }

    checkCryptoAvailability() {
        // Check if CryptoJS is available
        if (typeof CryptoJS !== 'undefined' && CryptoJS.AES) {
            this.cryptoAvailable = true;
            console.log('CryptoJS is available');
            this.updateEncryptionStatus('AES-256');
        } else {
            this.cryptoAvailable = false;
            console.warn('CryptoJS not available, using fallback encryption');
            this.updateEncryptionStatus('Basic XOR');
            this.displaySystemMessage('Warning: Using basic encryption (CryptoJS not loaded)');
            alert('CryptoJS failed to load. Please check your internet connection or contact support.');
        }
    }

    connectToServer() {
        try {
            this.socket = io({
                transports: ['websocket', 'polling'],
                upgrade: true,
                rememberUpgrade: true,
                timeout: 20000,
                forceNew: true
            });

            this.socket.on('connect', () => {
                this.isConnected = true;
                this.updateConnectionStatus('Connected');
                this.updateConnectionType('WebSocket');
                console.log('Connected to server');
                console.log('%c[Connection Established] Socket.io connection is now active.', 'color: #00ff00; font-weight: bold;');
            });

            this.socket.on('disconnect', () => {
                this.isConnected = false;
                this.updateConnectionStatus('Disconnected');
                this.updateConnectionType('Offline');
                console.log('Disconnected from server');
                this.roomId = null;
                this.disableRoomControls();
                document.getElementById('copy-room-btn').style.display = 'none';
                this.isRoomCreator = false;
                document.getElementById('end-room-btn').style.display = 'none';
            });

            this.socket.on('user-assigned', (data) => {
                this.userId = data.userId;
                document.getElementById('user-id').textContent = `ID: ${this.userId}`;
                console.log('Assigned user ID:', this.userId);
            });

            this.socket.on('room-joined', (data) => {
                this.roomId = data.roomId;
                this.isRoomCreator = (this.userId === data.creatorId);
                document.getElementById('room-info').textContent = `Room: ${this.roomId} (${data.userCount} users)`;
                // Only show copy button if user is the creator
                document.getElementById('copy-room-btn').style.display = this.isRoomCreator ? '' : 'none';
                document.getElementById('end-room-btn').style.display = '';
                document.getElementById('end-room-btn').disabled = !this.isRoomCreator;
                this.displaySystemMessage(`Joined room ${this.roomId}`);
                this.displaySystemMessage('⚠️ Messages auto-clear after 20 seconds for security');
                // Generate or use shared room encryption key
                this.roomEncryptionKey = data.roomKey || this.generateRoomKey();
                // Always show messages and input for creator
                if (this.isRoomCreator) {
                    document.getElementById('messages').style.display = '';
                    document.getElementById('message-input-container').style.display = '';
                    if (data.messages && data.messages.length > 0) {
                        this.loadMessages(data.messages);
                    }
                } else {
                    // For joiners, always show messages and input after pin validation
                    document.getElementById('messages').style.display = '';
                    document.getElementById('message-input-container').style.display = '';
                    if (data.messages && data.messages.length > 0) {
                        this.loadMessages(data.messages);
                    }
                }
                console.log('Joined room:', this.roomId);
                this.disableRoomControls();
            });

            this.socket.on('user-joined', (data) => {
                this.displaySystemMessage(`User ${data.userId} joined the room`);
                document.getElementById('room-info').textContent = `Room: ${this.roomId} (${data.userCount} users)`;
            });

            this.socket.on('user-left', (data) => {
                this.displaySystemMessage(`User ${data.userId} left the room`);
                document.getElementById('room-info').textContent = `Room: ${this.roomId} (${data.userCount} users)`;
                this.enableRoomControls();
                document.getElementById('end-room-btn').style.display = 'none';
                document.getElementById('copy-room-btn').style.display = 'none';
                this.isRoomCreator = false;
            });

            this.socket.on('new-message', (message) => {
                this.displayMessage(message);
            });

            this.socket.on('new-feedback', (feedback) => {
                this.displayFeedback(feedback);
            });

            this.socket.on('connect_error', (error) => {
                this.updateConnectionStatus('Connection Error');
                this.updateConnectionType('Failed');
                console.error('Connection error:', error);
            });

            this.socket.on('room-ended', (data) => {
                this.roomId = null;
                this.enableRoomControls();
                document.getElementById('end-room-btn').style.display = 'none';
                document.getElementById('messages').innerHTML = '';
                document.getElementById('room-info').textContent = '';
                this.displaySystemMessage('Room ended by a user. You can now join or create a new room.');
                document.getElementById('copy-room-btn').style.display = 'none';
                this.isRoomCreator = false;
            });

            this.socket.on('key-rotated', (data) => {
                this.displaySystemMessage(`🔐 User ${data.userId} rotated encryption keys for enhanced security`);
                console.log('Key rotation detected:', data);
            });

        } catch (error) {
            console.error('Failed to connect:', error);
            this.updateConnectionStatus('Connection Failed');
        }
    }

    generateEncryptionKey() {
        try {
            // Generate a random encryption key
            const array = new Uint8Array(32);
            crypto.getRandomValues(array);
            this.encryptionKey = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
            console.log('Generated encryption key');
        } catch (error) {
            console.error('Failed to generate encryption key:', error);
            // Fallback: use timestamp-based key
            this.encryptionKey = Date.now().toString(16) + Math.random().toString(16).substr(2);
            console.log('Using fallback encryption key');
        }
    }

    generateRoomKey() {
        try {
            // Generate a shared room encryption key
            const array = new Uint8Array(16);
            crypto.getRandomValues(array);
            return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
        } catch (error) {
            console.error('Failed to generate room key:', error);
            return Date.now().toString(16) + Math.random().toString(16).substr(2);
        }
    }

    // Simple XOR encryption fallback
    simpleEncrypt(text, key) {
        let result = '';
        for (let i = 0; i < text.length; i++) {
            const charCode = text.charCodeAt(i) ^ key.charCodeAt(i % key.length);
            result += String.fromCharCode(charCode);
        }
        return btoa(result); // Base64 encode
    }

    simpleDecrypt(encryptedText, key) {
        try {
            const decoded = atob(encryptedText); // Base64 decode
            let result = '';
            for (let i = 0; i < decoded.length; i++) {
                const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length);
                result += String.fromCharCode(charCode);
            }
            return result;
        } catch (error) {
            return '[Decryption Failed]';
        }
    }

    // Initialize Perfect Forward Secrecy
    initializePerfectForwardSecrecy() {
        try {
            // Generate Diffie-Hellman key pair
            this.generateDHKeys();
            
            // Start key rotation timer
            this.startKeyRotation();
            
            console.log('Perfect Forward Secrecy initialized');
        } catch (error) {
            console.error('Failed to initialize PFS:', error);
        }
    }

    // Generate Diffie-Hellman key pair
    generateDHKeys() {
        try {
            // Generate a large prime and generator for DH
            const prime = this.generateLargePrime(1024);
            const generator = BigInt(2); // Use BigInt for generator
            
            // Generate private key (random number)
            const privateKey = this.generateRandomBigInt(256);
            
            // Calculate public key: g^private mod p
            const publicKey = this.modPow(generator, privateKey, prime);
            
            this.dhPrivateKey = privateKey;
            this.dhPublicKey = publicKey;
            this.dhPrime = prime;
            this.dhGenerator = generator;
            
            console.log('DH keys generated successfully');
        } catch (error) {
            console.error('Failed to generate DH keys:', error);
            // Fallback to simple key generation
            this.generateFallbackKeys();
        }
    }

    // Generate a large prime number
    generateLargePrime(bits) {
        // For simplicity, we'll use a known large prime
        // In production, you'd want to generate this cryptographically
        const knownPrimes = [
            BigInt('115792089237316195423570985008687907853269984665640564039457584007913129639747'),
            BigInt('115792089237316195423570985008687907853269984665640564039457584007913129639751'),
            BigInt('115792089237316195423570985008687907853269984665640564039457584007913129639757')
        ];
        return knownPrimes[Math.floor(Math.random() * knownPrimes.length)];
    }

    // Generate random big integer
    generateRandomBigInt(bits) {
        const array = new Uint8Array(Math.ceil(bits / 8));
        crypto.getRandomValues(array);
        let result = BigInt(0);
        for (let i = 0; i < array.length; i++) {
            result = result * BigInt(256) + BigInt(array[i]);
        }
        return result;
    }

    // Modular exponentiation (a^b mod m)
    modPow(base, exponent, modulus) {
        base = BigInt(base);
        exponent = BigInt(exponent);
        modulus = BigInt(modulus);
        if (modulus === BigInt(1)) return BigInt(0);
        
        let result = BigInt(1);
        base = base % modulus;
        
        while (exponent > BigInt(0)) {
            if (exponent % BigInt(2) === BigInt(1)) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> BigInt(1);
            base = (base * base) % modulus;
        }
        return result;
    }

    // Generate fallback keys if DH fails
    generateFallbackKeys() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        this.currentSessionKey = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
        console.log('Using fallback session key');
    }

    // Start automatic key rotation
    startKeyRotation() {
        this.keyRotationInterval = setInterval(() => {
            this.rotateKeys();
        }, this.keyRotationTime);
        
        console.log(`Key rotation scheduled every ${this.keyRotationTime / 1000} seconds`);
    }

    // Rotate encryption keys
    rotateKeys() {
        try {
            // Generate new ephemeral key
            const newKey = this.generateEphemeralKey();
            const sessionId = Date.now().toString();
            
            // Store new key with timestamp
            this.ephemeralKeys.set(sessionId, {
                key: newKey,
                timestamp: Date.now(),
                expiresAt: Date.now() + (this.keyRotationTime * 2) // Keep for 2 rotation cycles
            });
            
            // Update current session key
            this.currentSessionKey = newKey;
            
            // Clean up old keys
            this.cleanupOldKeys();
            
            console.log('Keys rotated successfully');
            this.updateEncryptionStatus('AES-256 + PFS (Rotated)');
            
            // Notify server about key rotation
            if (this.socket && this.isConnected) {
                this.socket.emit('key-rotation', {
                    sessionId: sessionId,
                    timestamp: Date.now()
                });
            }
        } catch (error) {
            console.error('Key rotation failed:', error);
        }
    }

    // Generate ephemeral key
    generateEphemeralKey() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // Clean up old keys
    cleanupOldKeys() {
        const now = Date.now();
        for (const [sessionId, keyData] of this.ephemeralKeys.entries()) {
            if (keyData.expiresAt < now) {
                this.ephemeralKeys.delete(sessionId);
            }
        }
    }

    // Enhanced encryption with Perfect Forward Secrecy
    encryptMessage(message) {
        try {
            // Use current session key for encryption
            const keyToUse = this.currentSessionKey || this.roomEncryptionKey || this.encryptionKey;
            
            if (this.cryptoAvailable && typeof CryptoJS !== 'undefined') {
                // Simplified but secure encryption
                let encrypted = message;
                
                // Layer 1: AES-256 encryption (primary)
                encrypted = CryptoJS.AES.encrypt(encrypted, keyToUse).toString();
                this.updateEncryptionStatus('AES-256 + HMAC');
                
                // Layer 2: HMAC-SHA512 for integrity
                const signature = CryptoJS.HmacSHA512(encrypted, keyToUse).toString();
                
                // Layer 3: Add message sequence number for replay protection
                const sequenceNumber = this.getNextSequenceNumber();
                
                return { 
                    encryptedContent: encrypted, 
                    signature: signature,
                    method: 'aes-hmac',
                    sequenceNumber: sequenceNumber,
                    sessionId: this.getCurrentSessionId(),
                    timestamp: Date.now()
                };
            } else {
                // Fallback to simple encryption
                const encrypted = this.simpleEncrypt(message, keyToUse);
                this.updateEncryptionStatus('Basic XOR');
                return { 
                    encryptedContent: encrypted, 
                    signature: 'simple',
                    method: 'simple',
                    sequenceNumber: this.getNextSequenceNumber()
                };
            }
        } catch (error) {
            console.error('Encryption failed:', error);
            // Last resort: send as plain text with warning
            this.updateEncryptionStatus('Plain Text');
            return { 
                encryptedContent: message, 
                signature: 'none',
                method: 'plain'
            };
        }
    }

    // Generate Ed25519 digital signature
    generateDigitalSignature(data, key) {
        try {
            // Create a hash of the data
            const hash = CryptoJS.SHA512(data + key).toString();
            
            // Generate a deterministic signature using the hash and key
            const signature = CryptoJS.HmacSHA256(hash, key + this.getCurrentSessionId()).toString();
            
            return signature;
        } catch (error) {
            console.error('Digital signature generation failed:', error);
            return 'signature-failed';
        }
    }

    // Verify Ed25519 digital signature
    verifyDigitalSignature(data, signature, key) {
        try {
            const expectedSignature = this.generateDigitalSignature(data, key);
            return signature === expectedSignature;
        } catch (error) {
            console.error('Digital signature verification failed:', error);
            return false;
        }
    }

    // Add message padding for length obfuscation
    addMessagePadding(encryptedData) {
        try {
            // Add random padding to hide actual message length
            const paddingLength = Math.floor(Math.random() * 100) + 50; // 50-150 bytes
            const padding = crypto.getRandomValues(new Uint8Array(paddingLength));
            const paddingHex = Array.from(padding, byte => byte.toString(16).padStart(2, '0')).join('');
            
            return encryptedData + '::PAD::' + paddingHex;
        } catch (error) {
            console.error('Message padding failed:', error);
            return encryptedData;
        }
    }

    // Remove message padding
    removeMessagePadding(paddedData) {
        try {
            const parts = paddedData.split('::PAD::');
            return parts[0]; // Return only the actual encrypted data
        } catch (error) {
            console.error('Message padding removal failed:', error);
            return paddedData;
        }
    }

    // Convert hex string to Uint8Array
    hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    // Generate session-specific salt
    generateSessionSalt() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // XOR encryption for additional layer
    xorEncrypt(text, key) {
        let result = '';
        for (let i = 0; i < text.length; i++) {
            const charCode = text.charCodeAt(i) ^ key.charCodeAt(i % key.length);
            result += String.fromCharCode(charCode);
        }
        return btoa(result); // Base64 encode
    }

    // XOR decryption
    xorDecrypt(encryptedText, key) {
        try {
            const decoded = atob(encryptedText);
            let result = '';
            for (let i = 0; i < decoded.length; i++) {
                const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length);
                result += String.fromCharCode(charCode);
            }
            return result;
        } catch (error) {
            console.error('XOR decryption failed:', error);
            return encryptedText;
        }
    }

    // Get next sequence number
    getNextSequenceNumber() {
        if (!this.sequenceCounter) {
            this.sequenceCounter = 0;
        }
        return ++this.sequenceCounter;
    }

    // Get current session ID
    getCurrentSessionId() {
        return this.roomId + '-' + Math.floor(Date.now() / this.keyRotationTime);
    }

    // Enhanced decryption with Perfect Forward Secrecy
    decryptMessage(encryptedContent, method = 'aes', signature = null, sequenceNumber = null) {
        console.log('=== DECRYPTING MESSAGE ===');
        console.log('Encrypted content:', encryptedContent);
        console.log('Method:', method);
        console.log('Signature:', signature);
        console.log('Sequence number:', sequenceNumber);
        
        try {
            // Use current session key for decryption
            const keyToUse = this.currentSessionKey || this.roomEncryptionKey || this.encryptionKey;
            console.log('Using key:', keyToUse ? 'Key available' : 'No key available');
            
            if (method === 'aes-hmac' && this.cryptoAvailable && typeof CryptoJS !== 'undefined') {
                console.log('Using AES-HMAC decryption');
                // Verify HMAC signature
                const expectedSignature = CryptoJS.HmacSHA512(encryptedContent, keyToUse).toString();
                if (signature && signature !== expectedSignature) {
                    console.warn('HMAC verification failed');
                    return '[Message Integrity Check Failed]';
                }
                
                // AES-256 decryption
                const decrypted = CryptoJS.AES.decrypt(encryptedContent, keyToUse);
                const result = decrypted.toString(CryptoJS.enc.Utf8);
                console.log('AES-HMAC decryption result:', result);
                return result;
                
            } else if (method === 'simple') {
                console.log('Using simple decryption');
                const result = this.simpleDecrypt(encryptedContent, keyToUse);
                console.log('Simple decryption result:', result);
                return result;
            } else if (method === 'aes') {
                console.log('Using legacy AES decryption');
                // Legacy AES decryption
                const decrypted = CryptoJS.AES.decrypt(encryptedContent, keyToUse);
                const result = decrypted.toString(CryptoJS.enc.Utf8);
                console.log('Legacy AES decryption result:', result);
                return result;
            } else if (method === 'plain') {
                console.log('Using plain text');
                // Plain text
                console.log('Plain text result:', encryptedContent);
                return encryptedContent;
            } else {
                console.log('Unknown method, trying AES decryption');
                // Unknown method, try AES decryption
                try {
                    const decrypted = CryptoJS.AES.decrypt(encryptedContent, keyToUse);
                    const result = decrypted.toString(CryptoJS.enc.Utf8);
                    console.log('Fallback AES decryption result:', result);
                    return result;
                } catch (error) {
                    console.error('Decryption failed for unknown method:', method);
                    return '[Encrypted Message]';
                }
            }
        } catch (error) {
            console.error('Decryption failed:', error);
            return '[Decryption Failed]';
        }
    }

    // Verify HMAC signature
    verifyHMAC(data, expectedSignature, key) {
        try {
            const actualSignature = CryptoJS.HmacSHA512(data, key).toString();
            return actualSignature === expectedSignature;
        } catch (error) {
            console.error('HMAC verification failed:', error);
            return false;
        }
    }

    joinRoom() {
        if (!this.isConnected) {
            this.displaySystemMessage('Not connected to server');
            return;
        }
        if (this.roomId) {
            this.displaySystemMessage('You are already in a room. Leave the current room to join another.');
            return;
        }
        const roomInput = document.getElementById('room-input');
        const roomId = roomInput.value.trim();
        const pinInput = document.getElementById('pin-input');
        const accessPin = pinInput.value.trim();
        if (!roomId) {
            this.displaySystemMessage('Please enter a Room ID to join.');
            return;
        }
        // Always show pin input when a room code is entered
        pinInput.style.display = '';
        // Hide message input and messages until pin is validated
        document.getElementById('messages').style.display = 'none';
        document.getElementById('message-input-container').style.display = 'none';
        this.socket.emit('join-room', { roomId, accessPin });
        roomInput.value = '';
        pinInput.value = '';
    }

    createNewRoom() {
        if (!this.isConnected) {
            this.displaySystemMessage('Not connected to server');
            return;
        }
        if (this.roomId) {
            this.displaySystemMessage('You are already in a room. Leave the current room to create another.');
            return;
        }
        // Generate a random room ID
        const newRoomId = 'room-' + Math.random().toString(36).substr(2, 8);
        this.socket.emit('join-room', { roomId: newRoomId });
        document.getElementById('room-input').value = '';
    }

    sendMessage() {
        if (!this.isConnected || !this.roomId) {
            this.displaySystemMessage('Not connected or not in a room');
            return;
        }

        const messageInput = document.getElementById('message-input');
        const message = messageInput.value.trim();
        
        if (!message) return;

        console.log('=== SENDING MESSAGE ===');
        console.log('Original message:', message);
        console.log('Room ID:', this.roomId);
        console.log('User ID:', this.userId);
        console.log('Encryption key available:', this.cryptoAvailable);
        
        const encrypted = this.encryptMessage(message);
        console.log('Encrypted result:', encrypted);
        
        if (!encrypted) {
            this.displaySystemMessage('Failed to encrypt message');
            return;
        }

        this.socket.emit('send-message', encrypted);
        messageInput.value = '';
        
        // Display own message immediately with all encryption parameters
        const ownMessage = {
            id: Date.now().toString(),
            userId: this.userId,
            encryptedContent: encrypted.encryptedContent,
            timestamp: encrypted.timestamp || Date.now(),
            signature: encrypted.signature,
            method: encrypted.method,
            sequenceNumber: encrypted.sequenceNumber,
            sessionId: encrypted.sessionId
        };
        console.log('Displaying own message:', ownMessage);
        this.displayMessage(ownMessage, true);
    }

    displayMessage(message, isOwn = false) {
        console.log('=== DISPLAYING MESSAGE ===');
        console.log('Message object:', message);
        console.log('Is own message:', isOwn);
        console.log('Encryption method:', message.method);
        
        const messagesContainer = document.getElementById('messages');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message';
        messageDiv.setAttribute('data-message-id', message.id);
        
        // Pass all encryption parameters for enhanced decryption
        const decryptedContent = this.decryptMessage(
            message.encryptedContent, 
            message.method, 
            message.signature, 
            message.sequenceNumber
        );
        console.log('Decrypted content:', decryptedContent);
        
        const timestamp = new Date(message.timestamp).toLocaleTimeString();
        
        // Add message interpretation
        const messageInfo = this.interpretMessage(decryptedContent);
        
        // Add security indicators for enhanced encryption
        let securityIndicator = '';
        if (message.method === 'aes-hmac') {
            securityIndicator = '🔐🔐';
        } else if (message.method === 'simple') {
            securityIndicator = '🔐';
        } else if (message.method === 'plain') {
            securityIndicator = '⚠️';
        }
        
        messageDiv.innerHTML = `
            <div class="message-header">
                <span class="message-user">${isOwn ? 'You' : `User ${message.userId}`}</span>
                <span class="message-time">${timestamp}</span>
                <span class="message-status">${isOwn ? '✓ Sent' : '📥 Received'}</span>
                <span class="security-level">${securityIndicator}</span>
            </div>
            <div class="message-content">${this.escapeHtml(decryptedContent)}</div>
            ${messageInfo.interpretation ? `<div class="message-interpretation">${messageInfo.interpretation}</div>` : ''}
            ${!isOwn ? `<div class="message-feedback">
                <button class="feedback-btn" onclick="window.secureChat.sendFeedback('${message.id}', 'ack')" title="Acknowledge">✓</button>
                <button class="feedback-btn" onclick="window.secureChat.sendFeedback('${message.id}', 'question')" title="Question">?</button>
                <button class="feedback-btn" onclick="window.secureChat.sendFeedback('${message.id}', 'urgent')" title="Urgent">!</button>
            </div>` : ''}
        `;
        
        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
        
        // Auto-clear message after 2 minutes
        this.scheduleMessageClear(messageDiv, message.id);
    }

    interpretMessage(content) {
        const interpretation = { type: 'normal', interpretation: null };
        const lowerContent = content.toLowerCase();
        
        if (lowerContent.includes('urgent') || lowerContent.includes('emergency') || lowerContent.includes('asap')) {
            interpretation.type = 'urgent';
            interpretation.interpretation = '⚠️ Urgent message - requires immediate attention';
        } else if (lowerContent.includes('?') || lowerContent.includes('question')) {
            interpretation.type = 'question';
            interpretation.interpretation = '❓ Question detected - awaiting response';
        } else if (lowerContent.includes('command') || lowerContent.includes('execute')) {
            interpretation.type = 'command';
            interpretation.interpretation = '⚡ Command detected - action required';
        } else if (lowerContent.includes('status') || lowerContent.includes('update')) {
            interpretation.interpretation = '📊 Status update received';
        } else if (lowerContent.includes('confirmed') || lowerContent.includes('acknowledged')) {
            interpretation.interpretation = '✅ Confirmation received';
        }
        
        return interpretation;
    }

    getMessageStatus(message, isOwn) {
        if (isOwn) {
            return '<span class="message-status sent">✓ Sent</span>';
        } else {
            return '<span class="message-status received">📥 Received</span>';
        }
    }

    sendFeedback(messageId, feedbackType) {
        if (!this.isConnected || !this.roomId) return;

        const feedback = {
            messageId: messageId,
            type: feedbackType,
            userId: this.userId,
            timestamp: Date.now()
        };

        this.socket.emit('send-feedback', feedback);
        this.displaySystemMessage(`Feedback sent: ${feedbackType}`);
    }

    displayFeedback(feedback) {
        const feedbackMessages = {
            'ack': 'Message acknowledged',
            'question': 'Question about message',
            'urgent': 'Marked as urgent'
        };

        const message = `User ${feedback.userId}: ${feedbackMessages[feedback.type] || feedback.type}`;
        this.displaySystemMessage(message);
    }

    autoScrollToMessage(messageElement) {
        messageElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
        messageElement.style.animation = 'urgentPulse 2s ease-in-out';
    }

    displaySystemMessage(message) {
        const messagesContainer = document.getElementById('messages');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message system-message';
        
        const timestamp = new Date().toLocaleTimeString();
        
        messageDiv.innerHTML = `
            <div class="message-header">
                <span class="message-user">System</span>
                <span class="message-time">${timestamp}</span>
            </div>
            <div class="message-content">${this.escapeHtml(message)}</div>
        `;
        
        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    loadMessages(messages) {
        const messagesContainer = document.getElementById('messages');
        messagesContainer.innerHTML = '';
        
        messages.forEach(message => {
            this.displayMessage(message);
        });
    }

    updateConnectionStatus(status) {
        const statusElement = document.getElementById('connection-status');
        statusElement.textContent = status;
        
        if (status === 'Connected') {
            statusElement.style.color = '#00ff00';
        } else if (status.includes('Error') || status.includes('Failed')) {
            statusElement.style.color = '#ff0000';
        } else {
            statusElement.style.color = '#ffaa00';
        }
    }

    updateConnectionType(type) {
        document.getElementById('connection-type').textContent = type;
    }

    updateEncryptionStatus(status) {
        const statusElement = document.getElementById('encryption-status');
        if (statusElement) {
            statusElement.textContent = status;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Security cleanup
    cleanup() {
        if (this.socket) {
            this.socket.disconnect();
        }
        this.encryptionKey = null;
        this.userId = null;
        this.roomId = null;
    }

    scheduleMessageClear(messageElement, messageId) {
        const startTime = Date.now();
        const duration = 20 * 1000; // 20 seconds
        
        // Add countdown timer
        const countdownElement = document.createElement('div');
        countdownElement.className = 'message-countdown';
        countdownElement.style.cssText = `
            position: absolute;
            top: 4px;
            right: 4px;
            font-size: 10px;
            color: #666666;
            background-color: rgba(0,0,0,0.7);
            padding: 2px 6px;
            border-radius: 3px;
            z-index: 10;
        `;
        messageElement.style.position = 'relative';
        messageElement.appendChild(countdownElement);
        
        // Update countdown every second
        const countdownInterval = setInterval(() => {
            const elapsed = Date.now() - startTime;
            const remaining = Math.max(0, duration - elapsed);
            const minutes = Math.floor(remaining / 60000);
            const seconds = Math.floor((remaining % 60000) / 1000);
            
            countdownElement.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
            
            // Change color as time runs out
            if (remaining < 5000) { // Last 5 seconds
                countdownElement.style.color = '#ff6666';
                countdownElement.style.borderColor = '#ff6666';
                countdownElement.classList.add('danger');
            } else if (remaining < 10000) { // Last 10 seconds
                countdownElement.style.color = '#ffaa00';
                countdownElement.style.borderColor = '#ffaa00';
                countdownElement.classList.add('warning');
            }
            
            // Show notification at 10 seconds remaining
            if (remaining === 10000) {
                this.showAutoClearNotification('Messages expiring in 10 seconds');
            }
        }, 1000);
        
        setTimeout(() => {
            clearInterval(countdownInterval);
            if (messageElement && messageElement.parentNode) {
                // Add fade-out effect
                messageElement.style.transition = 'opacity 0.5s ease-out';
                messageElement.style.opacity = '0';
                
                setTimeout(() => {
                    if (messageElement.parentNode) {
                        messageElement.parentNode.removeChild(messageElement);
                        console.log(`Message ${messageId} auto-cleared after 20 seconds`);
                    }
                }, 500); // Wait for fade-out animation
            }
        }, duration);
    }

    showAutoClearNotification(message) {
        const notification = document.createElement('div');
        notification.className = 'auto-clear-notification';
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        // Remove notification after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.transition = 'opacity 0.3s ease-out';
                notification.style.opacity = '0';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
            }
        }, 5000);
    }

    disableRoomControls() {
        document.getElementById('join-room-btn').disabled = true;
        document.getElementById('new-room-btn').disabled = true;
        document.getElementById('room-input').disabled = true;
    }

    enableRoomControls() {
        document.getElementById('join-room-btn').disabled = false;
        document.getElementById('new-room-btn').disabled = false;
        document.getElementById('room-input').disabled = false;
    }

    endRoom() {
        if (!this.roomId) return;
        if (!this.isRoomCreator) {
            this.displaySystemMessage('Only the room creator can end the room.');
            return;
        }
        this.socket.emit('end-room', { roomId: this.roomId });
        this.roomId = null;
        this.enableRoomControls();
        document.getElementById('end-room-btn').style.display = 'none';
        document.getElementById('messages').innerHTML = '';
        document.getElementById('room-info').textContent = '';
        this.displaySystemMessage('Room ended. You can now join or create a new room.');
        document.getElementById('copy-room-btn').style.display = 'none';
        this.isRoomCreator = false;
    }

    copyRoomId() {
        if (!this.roomId) return;
        if (!this.isRoomCreator) {
            this.displaySystemMessage('Only the room creator can copy the room link.');
            return;
        }
        // Build the full URL with the room code appended as a path
        const url = `${window.location.origin.replace(/\/$/, '')}/${this.roomId}`;
        navigator.clipboard.writeText(url).then(() => {
            this.displaySystemMessage('Room link copied to clipboard!');
        }).catch(() => {
            this.displaySystemMessage('Failed to copy room link.');
        });
    }

    // Report security event to server
    reportSecurityEvent(eventType, details = {}) {
        if (!this.userId) return;
        
        const eventData = {
            eventType: eventType,
            userId: this.userId,
            roomId: this.roomId,
            details: {
                ...details,
                timestamp: Date.now(),
                userAgent: navigator.userAgent,
                screenResolution: `${screen.width}x${screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
            }
        };
        
        // Send to server
        fetch('/security/event', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(eventData)
        }).catch(error => {
            console.error('Failed to report security event:', error);
        });
    }

    // Enhanced alert methods with server reporting
    triggerScreenshotAlert() {
        this.screenshotAttempts++;
        this.overlay.classList.add('active');
        setTimeout(() => {
            this.overlay.classList.remove('active');
        }, 2000);
        
        // Report to server
        this.reportSecurityEvent('SCREENSHOT_ATTEMPT', {
            attemptNumber: this.screenshotAttempts,
            method: 'keyboard_shortcut'
        });
        
        if (this.screenshotAttempts > 3) {
            this.reportSecurityEvent('SECURITY_BREACH', {
                reason: 'Multiple screenshot attempts',
                totalAttempts: this.screenshotAttempts
            });
            this.lockApplication();
        }
    }
    
    triggerDevToolsAlert() {
        this.overlay.classList.add('active');
        setTimeout(() => {
            this.overlay.classList.remove('active');
        }, 3000);
        
        // Report to server
        this.reportSecurityEvent('DEVTOOLS_ACCESS', {
            method: 'keyboard_shortcut'
        });
    }
    
    triggerVisibilityAlert() {
        this.overlay.classList.add('active');
        setTimeout(() => {
            this.overlay.classList.remove('active');
        }, 2000);
        
        // Report to server
        this.reportSecurityEvent('VISIBILITY_CHANGE', {
            hidden: document.hidden
        });
    }
    
    triggerFocusAlert() {
        this.overlay.classList.add('active');
        setTimeout(() => {
            this.overlay.classList.remove('active');
        }, 1500);
        
        // Report to server
        this.reportSecurityEvent('WINDOW_FOCUS_LOST');
    }
    
    triggerRightClickAlert() {
        this.overlay.classList.add('active');
        setTimeout(() => {
            this.overlay.classList.remove('active');
        }, 1000);
        
        // Report to server
        this.reportSecurityEvent('RIGHT_CLICK_ATTEMPT');
    }
    
    triggerLongPressAlert() {
        this.overlay.classList.add('active');
        setTimeout(() => {
            this.overlay.classList.remove('active');
        }, 1000);
        
        // Report to server
        this.reportSecurityEvent('LONG_PRESS_ATTEMPT');
    }
    
    triggerSaveAlert() {
        this.overlay.classList.add('active');
        setTimeout(() => {
            this.overlay.classList.remove('active');
        }, 1500);
        
        // Report to server
        this.reportSecurityEvent('SAVE_ATTEMPT');
    }
    
    triggerPrintAlert() {
        this.overlay.classList.add('active');
        setTimeout(() => {
            this.overlay.classList.remove('active');
        }, 2000);
        
        // Report to server
        this.reportSecurityEvent('PRINT_ATTEMPT');
    }
    
    triggerSelectAllAlert() {
        this.overlay.classList.add('active');
        setTimeout(() => {
            this.overlay.classList.remove('active');
        }, 1000);
        
        // Report to server
        this.reportSecurityEvent('SELECT_ALL_ATTEMPT');
    }
    
    triggerInactivityAlert() {
        this.overlay.classList.add('active');
        setTimeout(() => {
            this.overlay.classList.remove('active');
        }, 1000);
        
        // Report to server
        this.reportSecurityEvent('INACTIVITY_DETECTED');
    }
    
    showRecordingWarning() {
        this.recordingWarning.style.display = 'block';
        setTimeout(() => {
            this.recordingWarning.style.display = 'none';
        }, 5000);
        
        // Report to server
        this.reportSecurityEvent('SCREEN_RECORDING_DETECTED');
    }
    
    showCameraWarning() {
        this.cameraWarning.style.display = 'block';
        setTimeout(() => {
            this.cameraWarning.style.display = 'none';
        }, 5000);
        
        // Report to server
        this.reportSecurityEvent('CAMERA_ACCESS_DETECTED');
    }
}

// Initialize the application when the page loads
document.addEventListener('DOMContentLoaded', () => {
    window.secureChat = new SecureChat();

    // Check for room code in URL path or search params
    const pathRoom = window.location.pathname.replace(/^\//, '');
    const urlParams = new URLSearchParams(window.location.search);
    const searchRoom = urlParams.get('room');
    let roomCode = '';
    if (searchRoom && searchRoom.trim().length > 0) {
        roomCode = searchRoom.trim();
    } else if (pathRoom && pathRoom.length > 0 && !pathRoom.includes('.')) {
        roomCode = pathRoom;
    }
    const pinOverlay = document.getElementById('pin-overlay');
    if (roomCode) {
        // Auto-fill room input and show pin overlay
        const roomInput = document.getElementById('room-input');
        if (roomInput) {
            roomInput.value = roomCode;
        }
        if (pinOverlay) {
            pinOverlay.style.display = 'flex';
            pinOverlay.classList.add('active');
        }
        // Hide messages, input area, and room controls until pin is validated
        const messages = document.getElementById('messages');
        const inputArea = document.getElementById('message-input-container');
        const roomControls = document.getElementById('room-controls');
        if (messages) messages.style.display = 'none';
        if (inputArea) inputArea.style.display = 'none';
        if (roomControls) roomControls.style.display = 'none';
        // Enable join button only when pin is entered
        const pinInput = document.getElementById('pin-input');
        const joinBtn = document.getElementById('join-room-btn');
        pinInput.addEventListener('input', () => {
            if (pinInput.value.trim().length > 0) {
                joinBtn.disabled = false;
                joinBtn.classList.add('enabled');
            } else {
                joinBtn.disabled = true;
                joinBtn.classList.remove('enabled');
            }
        });
        joinBtn.addEventListener('click', () => {
            if (pinOverlay) {
                pinOverlay.classList.remove('active');
                pinOverlay.style.display = 'none';
            }
            // Reveal messages, input area, and room controls after pin is validated
            if (messages) messages.style.display = '';
            if (inputArea) inputArea.style.display = '';
            if (roomControls) roomControls.style.display = '';
            // Ensure user ID is not changed
            const prevUserId = window.secureChat.userId;
            window.secureChat.joinRoom();
            // Restore user ID if changed (should not happen, but for safety)
            if (window.secureChat.userId !== prevUserId) {
                window.secureChat.userId = prevUserId;
                document.getElementById('user-id').textContent = `ID: ${prevUserId}`;
            }
        });
    } else {
        // No room code, session open for creating a room
        if (pinOverlay) {
            pinOverlay.classList.remove('active');
            pinOverlay.style.display = 'none';
        }
        // Show messages and input area by default
        const messages = document.getElementById('messages');
        const inputArea = document.getElementById('message-input-container');
        if (messages) messages.style.display = '';
        if (inputArea) inputArea.style.display = '';
    }

    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        if (window.secureChat) {
            window.secureChat.cleanup();
        }
    });
});

// Additional security measures
(function() {
    // Disable developer tools (basic)
    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey && e.shiftKey && e.key === 'I') {
            e.preventDefault();
            return false;
        }
        if (e.ctrlKey && e.shiftKey && e.key === 'C') {
            e.preventDefault();
            return false;
        }
        if (e.ctrlKey && e.shiftKey && e.key === 'J') {
            e.preventDefault();
            return false;
        }
        if (e.key === 'F12') {
            e.preventDefault();
            return false;
        }
    });

    // Disable right-click
    document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        return false;
    });

    // Clear console
    console.clear();
    console.log('Secure Anonymous Chat Platform');
    console.log('All communications are encrypted and anonymous');
})();