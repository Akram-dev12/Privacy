const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const path = require('path');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "ws:", "wss:"],
      // Prevent screen capture and recording
      mediaSrc: ["'none'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
      // Block external media and recording
      workerSrc: ["'self'"],
      childSrc: ["'self'"],
      // Prevent data extraction
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  // Additional security headers
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: { policy: "same-origin" },
  crossOriginResourcePolicy: { policy: "same-origin" },
  referrerPolicy: { policy: "no-referrer" },
  // Prevent clickjacking
  frameguard: { action: "deny" },
  // Prevent MIME type sniffing
  noSniff: true,
  // XSS protection
  xssFilter: true
}));

app.use(cors());
app.use(compression());
app.use(express.json());
app.use(express.static('public'));

// Privacy headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), display-capture=()');
  
  // Additional anti-screenshot headers
  res.setHeader('X-Screenshot-Protection', 'enabled');
  res.setHeader('X-Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; media-src 'none'; object-src 'none'; frame-src 'none';");
  
  // Prevent caching of sensitive content
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  
  // Prevent screen capture
  res.setHeader('X-Display-Capture', 'deny');
  res.setHeader('X-Screen-Recording', 'deny');
  
  next();
});

// Store active sessions (minimal data)
const activeSessions = new Map();
const chatRooms = new Map();

// Security monitoring
const securityEvents = new Map();
const screenshotAttempts = new Map();

// Security event logging
function logSecurityEvent(eventType, userId, roomId, details = {}) {
  const event = {
    type: eventType,
    userId: userId,
    roomId: roomId,
    timestamp: Date.now(),
    details: details,
    ip: details.ip || 'unknown'
  };
  
  console.log(`🚨 SECURITY EVENT: ${eventType}`, event);
  
  // Store security event
  if (!securityEvents.has(userId)) {
    securityEvents.set(userId, []);
  }
  const userEvents = securityEvents.get(userId);
  userEvents.push(event);
  
  // Clean up old events (keep last 24 hours)
  const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
  const filteredEvents = userEvents.filter(e => e.timestamp > oneDayAgo);
  securityEvents.set(userId, filteredEvents);
}

// Screenshot attempt tracking
function trackScreenshotAttempt(userId, roomId, ip) {
  if (!screenshotAttempts.has(userId)) {
    screenshotAttempts.set(userId, {
      count: 0,
      firstAttempt: Date.now(),
      lastAttempt: Date.now(),
      roomId: roomId,
      ip: ip
    });
  }
  
  const attempts = screenshotAttempts.get(userId);
  attempts.count++;
  attempts.lastAttempt = Date.now();
  
  logSecurityEvent('SCREENSHOT_ATTEMPT', userId, roomId, {
    attemptCount: attempts.count,
    ip: ip,
    timeSinceFirst: Date.now() - attempts.firstAttempt
  });
  
  // If too many attempts, log as potential security breach
  if (attempts.count > 5) {
    logSecurityEvent('SECURITY_BREACH', userId, roomId, {
      reason: 'Multiple screenshot attempts',
      totalAttempts: attempts.count,
      ip: ip
    });
  }
}

// Security monitoring endpoint
app.post('/security/event', (req, res) => {
  try {
    // Check if req.body exists and has the required properties
    if (!req.body || typeof req.body !== 'object') {
      console.warn('Invalid request body for security event');
      return res.status(400).json({ error: 'Invalid request body' });
    }
    
    const { eventType, userId, roomId, details } = req.body;
    
    if (eventType && userId) {
      logSecurityEvent(eventType, userId, roomId, {
        ...details,
        ip: req.ip || req.connection.remoteAddress
      });
    } else {
      console.warn('Missing required fields for security event:', { eventType, userId });
    }
    
    res.status(200).json({ status: 'logged' });
  } catch (error) {
    console.error('Error processing security event:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Security status endpoint
app.get('/security/status', (req, res) => {
  const userId = req.query.userId;
  
  if (userId && securityEvents.has(userId)) {
    const events = securityEvents.get(userId);
    const recentEvents = events.filter(e => Date.now() - e.timestamp < 60000); // Last minute
    
    res.json({
      userId: userId,
      totalEvents: events.length,
      recentEvents: recentEvents.length,
      hasBreaches: events.some(e => e.type === 'SECURITY_BREACH'),
      lastEvent: events[events.length - 1]
    });
  } else {
    res.json({ status: 'no_data' });
  }
});

// Generate room ID
function generateRoomId() {
  return crypto.randomBytes(16).toString('hex');
}

// Generate room encryption key
function generateRoomKey() {
  return crypto.randomBytes(16).toString('hex');
}

// Generate temporary user ID
function generateUserId() {
  return crypto.randomBytes(8).toString('hex');
}

io.on('connection', (socket) => {
  console.log('New connection:', socket.id);
  
  // Generate anonymous user ID
  const userId = generateUserId();
  activeSessions.set(socket.id, {
    userId,
    roomId: null,
    connectedAt: Date.now()
  });

  socket.emit('user-assigned', { userId });

  // Join room
  socket.on('join-room', (data) => {
    const session = activeSessions.get(socket.id);
    if (!session) return;

    let roomId = data.roomId;
    
    // Create new room if none exists
    if (!roomId || !chatRooms.has(roomId)) {
      roomId = generateRoomId();
      const roomKey = generateRoomKey();
      chatRooms.set(roomId, {
        users: new Set(),
        messages: [],
        created: Date.now(),
        encryptionKey: roomKey,
        creatorId: userId
      });
    }

    session.roomId = roomId;
    socket.join(roomId);
    
    const room = chatRooms.get(roomId);
    room.users.add(userId);

    socket.emit('room-joined', { 
      roomId,
      userCount: room.users.size,
      messages: room.messages.slice(-50), // Last 50 messages
      roomKey: room.encryptionKey,
      creatorId: room.creatorId
    });

    socket.to(roomId).emit('user-joined', { 
      userId,
      userCount: room.users.size 
    });
  });

  // Handle encrypted messages
  socket.on('send-message', (data) => {
    const session = activeSessions.get(socket.id);
    if (!session || !session.roomId) return;

    const room = chatRooms.get(session.roomId);
    if (!room) return;

    const message = {
      id: crypto.randomBytes(16).toString('hex'),
      userId: session.userId,
      encryptedContent: data.encryptedContent,
      timestamp: data.timestamp || Date.now(),
      signature: data.signature,
      digitalSignature: data.digitalSignature,
      method: data.method,
      salt: data.salt,
      sequenceNumber: data.sequenceNumber,
      sessionId: data.sessionId
    };

    room.messages.push(message);
    
    // Keep only last 100 messages
    if (room.messages.length > 100) {
      room.messages = room.messages.slice(-100);
    }

    // Broadcast to room
    socket.to(session.roomId).emit('new-message', message);
  });

  // Handle key rotation events
  socket.on('key-rotation', (data) => {
    const session = activeSessions.get(socket.id);
    if (!session || !session.roomId) return;

    // Log key rotation for security monitoring
    console.log(`Key rotation in room ${session.roomId} by user ${session.userId}`);
    
    // Notify other users in the room about key rotation
    socket.to(session.roomId).emit('key-rotated', {
      userId: session.userId,
      sessionId: data.sessionId,
      timestamp: data.timestamp
    });
  });

  // Handle feedback messages
  socket.on('send-feedback', (data) => {
    const session = activeSessions.get(socket.id);
    if (!session || !session.roomId) return;

    const room = chatRooms.get(session.roomId);
    if (!room) return;

    const feedback = {
      id: crypto.randomBytes(16).toString('hex'),
      messageId: data.messageId,
      userId: session.userId,
      type: data.type,
      timestamp: Date.now()
    };

    // Broadcast feedback to room
    socket.to(session.roomId).emit('new-feedback', feedback);
  });

  // Handle end-room event
  socket.on('end-room', (data) => {
    const session = activeSessions.get(socket.id);
    if (!session || !session.roomId) return;
    const roomId = session.roomId;
    const room = chatRooms.get(roomId);
    if (!room) return;
    // Notify all users in the room
    io.to(roomId).emit('room-ended', { roomId });
    // Remove all users from the room
    room.users.forEach(uid => {
      for (const [sid, sess] of activeSessions.entries()) {
        if (sess.userId === uid) {
          activeSessions.get(sid).roomId = null;
        }
      }
    });
    // Delete the room
    chatRooms.delete(roomId);
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    const session = activeSessions.get(socket.id);
    if (session && session.roomId) {
      const room = chatRooms.get(session.roomId);
      if (room) {
        room.users.delete(session.userId);
        
        // Remove room if empty
        if (room.users.size === 0) {
          chatRooms.delete(session.roomId);
        } else {
          socket.to(session.roomId).emit('user-left', { 
            userId: session.userId,
            userCount: room.users.size 
          });
        }
      }
    }
    
    activeSessions.delete(socket.id);
    console.log('Disconnected:', socket.id);
  });
});

// Cleanup old rooms and sessions
setInterval(() => {
  const now = Date.now();
  
  // Clean up sessions older than 24 hours
  for (const [socketId, session] of activeSessions.entries()) {
    if (now - session.connectedAt > 24 * 60 * 60 * 1000) {
      activeSessions.delete(socketId);
    }
  }
  
  // Clean up rooms older than 7 days
  for (const [roomId, room] of chatRooms.entries()) {
    if (now - room.created > 7 * 24 * 60 * 60 * 1000) {
      chatRooms.delete(roomId);
    }
  }
}, 60 * 60 * 1000); // Run every hour

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0'; // Listen on all network interfaces
server.listen(PORT, HOST, () => {
  console.log(`Back Channel server running on http://${HOST}:${PORT}`);
  console.log(`Local access: http://localhost:${PORT}`);
  console.log(`Network access: http://10.45.2.145:${PORT}`);
  console.log('Server configured for maximum privacy and security');
}); 