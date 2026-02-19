# SOMETHING

A highly secure, anonymous communication platform designed for privacy-conscious users. This application provides end-to-end encryption, anonymous user sessions, and a minimalist interface optimized for security.

## Features

### Security & Privacy
- **End-to-End Encryption**: All messages are encrypted using AES-256
- **Anonymous Users**: No persistent user accounts or personal information required
- **No Logging**: Server does not store message content or user data
- **Temporary Sessions**: User IDs and room data are automatically cleaned up
- **Privacy Headers**: Comprehensive security headers to prevent tracking
- **No Analytics**: Zero tracking or analytics code

### Interface
- **Minimalist Design**: Black background with white text for low visibility
- **Horizontal Layout**: Optimized for wide screens
- **Monospace Font**: Courier New for consistent text rendering
- **No Images**: Text-only interface to minimize data transfer

### Communication
- **Real-time Messaging**: WebSocket-based communication
- **Room-based Chat**: Join existing rooms or create new ones
- **Anonymous Rooms**: Room IDs are randomly generated
- **User Count**: See how many users are in each room
- **System Messages**: Automatic notifications for user events

## Installation

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Start the Server**
   ```bash
   npm start
   ```

3. **Access the Application**
   Open your browser and navigate to `http://localhost:3000`

## Security Features

### Encryption
- AES-256 encryption for all messages
- Unique encryption keys generated per session
- HMAC signatures for message integrity
- Client-side encryption/decryption

### Anonymity
- Random user IDs generated for each session
- No persistent user data stored
- Automatic cleanup of old sessions and rooms
- No IP address logging

### Network Security
- WebSocket connections with fallback to polling
- HTTPS-ready configuration
- Security headers (HSTS, CSP, XSS Protection)
- CORS configuration for cross-origin requests

### Privacy Protection
- No referrer information sent
- Disabled geolocation, microphone, and camera access
- No third-party scripts or tracking
- Minimal data collection

## Usage

### Joining a Chat Room
1. Enter a room ID in the input field (or leave empty for a new room)
2. Click "Join Room" or "New Room"
3. Wait for connection confirmation

### Sending Messages
1. Type your message in the text area
2. Press Enter or click "Send"
3. Messages are automatically encrypted before transmission

### Security Indicators
- **Connection Status**: Shows current connection state
- **User ID**: Your anonymous identifier for this session
- **Room Info**: Current room ID and user count
- **Security Info**: Encryption status and privacy settings

## Technical Details

### Server Architecture
- Node.js with Express.js
- Socket.IO for real-time communication
- Helmet.js for security headers
- Automatic cleanup of old data

### Client Architecture
- Vanilla JavaScript (no frameworks)
- CryptoJS for encryption
- WebSocket for real-time updates
- Minimal DOM manipulation

### Data Storage
- In-memory storage only
- No database required
- Automatic cleanup every hour
- Sessions expire after 24 hours
- Rooms expire after 7 days

## Security Considerations

### For Users
- Use a VPN or Tor for additional anonymity
- Clear browser data after each session
- Don't share sensitive information
- Be aware that metadata may still be visible to ISPs

### For Administrators
- Deploy behind a reverse proxy with HTTPS
- Use a secure hosting provider
- Monitor server logs for unusual activity
- Regularly update dependencies

## Deployment

### Production Setup
1. Set environment variables:
   ```bash
   export PORT=3000
   export NODE_ENV=production
   ```

2. Use a process manager like PM2:
   ```bash
   npm install -g pm2
   pm2 start server.js --name "something"
   ```

3. Configure reverse proxy (nginx example):
   ```nginx
   server {
       listen 443 ssl;
       server_name your-domain.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       
       location / {
           proxy_pass http://localhost:3000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_cache_bypass $http_upgrade;
       }
   }
   ```

## Limitations

- Messages are not persistent (lost when room is deleted)
- No file sharing capabilities
- No user authentication or verification
- Limited to text-based communication
- Requires JavaScript enabled

## Contributing

This is a security-focused application. Please ensure all contributions maintain the privacy and security standards.

## License

MIT License - See LICENSE file for details.

## Disclaimer

This software is provided for educational and legitimate privacy purposes only. Users are responsible for complying with applicable laws and regulations in their jurisdiction. 