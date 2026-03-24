require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const compression = require('compression');
const http = require('http');
const https = require('https');
const TelegramBot = require('node-telegram-bot-api');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');
const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: false });

const app = express();
app.use(compression()); // Reduces bandwidth usage

// Force IPv4 for all axios requests to prevent ECONNRESET with Telegram
axios.defaults.httpsAgent = new https.Agent({ family: 4 });


// ── Firebase Admin ────────────────────────────────────────────────────────────
let adminDb = null;
let fcmMessaging = null;

try {
    const admin = require('firebase-admin');

    // Use FIREBASE_SERVICE_ACCOUNT env var (JSON string)
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            projectId: 'z-chat-144'
        });
        adminDb = admin.firestore();
        fcmMessaging = admin.messaging();
        console.log('[FCM] Firebase Admin initialised');
    } else {
        console.warn('[FCM] FIREBASE_SERVICE_ACCOUNT not found — push notifications disabled');
    }
} catch (e) {
    console.warn('[FCM] firebase-admin failed to load:', e.message);
}


// ── CORS ──────────────────────────────────────────────────────────────────────
app.use(cors({
    origin: (origin, callback) => {
        // Allow all zchat subdomains on duckdns and render
        if (!origin || /zchat|onrender\.com|duckdns\.org|localhost/.test(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    optionsSuccessStatus: 200
}));

app.use(express.json());

// ── Email Transporter ────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

transporter.verify((error) => {
    if (error) console.warn('[Email] SMTP Transporter failed:', error.message);
    else console.log('[Email] SMTP Server is ready');
});

// ── Region label (set via Render env var REGION, e.g. "singapore") ─────────────
const REGION = process.env.REGION || 'unknown';

// ── Root – simple response for uptime monitors ─────────────────────────────
app.get('/', (req, res) => {
    res.status(200).send(`Z-CDN-Node [${REGION}] is Active`);
});

// ── Ping – latency probe used by the CDN router in Z Chat ────────────────────
app.get('/ping', (req, res) => {
    res.json({ status: 'ok', region: REGION, timestamp: Date.now() });
});

// ── 2FA Endpoints ─────────────────────────────────────────────────────────────
app.post('/auth/2fa/send-code', async (req, res) => {
    const { email, uid } = req.body;
    
    if (!adminDb) return res.status(503).json({ error: 'Firebase Admin not initialized on server. Check FIREBASE_SERVICE_ACCOUNT variable.' });
    if (!email || !uid) return res.status(400).json({ error: 'Email and UID are required' });

    try {
        // Generate 6-digit code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60000); // 10 minutes from now

        // Save to Firestore
        await adminDb.collection('twoFactorCodes').doc(uid).set({
            code,
            expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
            email
        });

        // Send Email
        const mailOptions = {
            from: `"Z Chat Security" <${process.env.SMTP_USER}>`,
            to: email,
            subject: 'Your Z Chat Verification Code',
            html: `
                <div style="font-family: sans-serif; max-width: 500px; margin: auto; padding: 20px; border: 1px solid #777; border-radius: 10px; background: #000; color: #fff;">
                    <h2 style="color: #ff3040; text-align: center;">Z Chat Security</h2>
                    <p>Hello,</p>
                    <p>Your verification code is:</p>
                    <div style="font-size: 32px; font-weight: bold; text-align: center; letter-spacing: 5px; margin: 20px 0; color: #fff; background: #1a1a1a; padding: 20px; border-radius: 8px; border: 1px solid #333;">
                        ${code}
                    </div>
                    <p style="font-size: 13px; color: #aaa; text-align: center;">This code will expire in 10 minutes. If you did not request this code, please ignore this email.</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log(`[2FA] Code sent to ${email}`);
        res.json({ success: true });
    } catch (err) {
        console.error('[2FA] Send error:', err);
        res.status(500).json({ error: 'Failed to send verification code' });
    }
});

app.post('/auth/2fa/verify-code', async (req, res) => {
    const { uid, code } = req.body;

    if (!adminDb) return res.status(503).json({ error: 'Firebase Admin not initialized on server. Check FIREBASE_SERVICE_ACCOUNT variable.' });
    if (!uid || !code) return res.status(400).json({ error: 'UID and code are required' });

    try {
        const docRef = adminDb.collection('twoFactorCodes').doc(uid);
        const docSnap = await docRef.get();

        if (!docSnap.exists) return res.status(404).json({ error: 'No code found for this user' });

        const data = docSnap.data();
        const now = admin.firestore.Timestamp.now();

        if (data.code !== code) {
            return res.status(400).json({ error: 'Invalid verification code' });
        }

        if (now.toMillis() > data.expiresAt.toMillis()) {
            return res.status(400).json({ error: 'Verification code expired' });
        }

        // Success - clean up the code
        await docRef.delete();
        res.json({ success: true });
    } catch (err) {
        console.error('[2FA] Verify error:', err);
        res.status(500).json({ error: 'Verification failed' });
    }
});

// ── Push Notification ────────────────────────────────────────────────────────
app.post('/push', async (req, res) => {
    if (!fcmMessaging || !adminDb) {
        return res.status(503).json({ error: 'FCM not configured on this node' });
    }

    const { recipientId, title, body, data = {} } = req.body;
    if (!recipientId || !title) {
        return res.status(400).json({ error: 'recipientId and title are required' });
    }

    try {
        const userDoc = await adminDb.collection('users').doc(recipientId).get();
        if (!userDoc.exists) return res.json({ sent: 0, reason: 'user not found' });

        const userData = userDoc.data();
        const tokens = [
            ...(userData.fcmTokens || []),
            ...(userData.fcmToken ? [userData.fcmToken] : [])
        ].filter(Boolean);

        const uniqueTokens = [...new Set(tokens)];
        if (uniqueTokens.length === 0) return res.json({ sent: 0, reason: 'no tokens' });

        const message = {
            notification: { title, body: body || '' },
            data: Object.fromEntries(
                Object.entries(data).map(([k, v]) => [k, String(v)])
            ),
            tokens: uniqueTokens,
            android: {
                priority: 'high',
                notification: { sound: 'default', channelId: 'zchat_messages' }
            },
            apns: {
                payload: { aps: { sound: 'default', badge: 1 } }
            },
            webpush: {
                headers: { Urgency: 'high' }
            }
        };

        const response = await fcmMessaging.sendEachForMulticast(message);
        console.log(`[FCM] Sent to ${response.successCount}/${uniqueTokens.length} tokens`);

        // Clean up stale tokens
        const staleTokens = [];
        response.responses.forEach((r, i) => {
            if (!r.success && (r.error?.code === 'messaging/registration-token-not-registered' ||
                r.error?.code === 'messaging/invalid-registration-token')) {
                staleTokens.push(uniqueTokens[i]);
            }
        });
        if (staleTokens.length > 0) {
            await adminDb.collection('users').doc(recipientId).update({
                fcmTokens: (userData.fcmTokens || []).filter(t => !staleTokens.includes(t))
            });
        }

        res.json({ sent: response.successCount, failed: response.failureCount });
    } catch (err) {
        console.error('[FCM] Push error:', err);
        res.status(500).json({ error: err.message });
    }
});


// ── OCI Proxy – stream Oracle Cloud Object Storage media ─────────────────────
// Restricts to OCI hostnames only to prevent open-proxy abuse
const ALLOWED_DOMAIN = 'objectstorage';

const axiosInstance = axios.create({
    httpAgent: new http.Agent({ keepAlive: true }),
    httpsAgent: new https.Agent({ keepAlive: true }),
    timeout: 30000
});

app.get('/proxy', async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).send('Missing url parameter');

    try {
        const parsedUrl = new URL(url);
        if (!parsedUrl.hostname.includes(ALLOWED_DOMAIN)) {
            return res.status(403).send('Proxy restriction: unauthorized domain');
        }

        const response = await axiosInstance({
            method: 'GET',
            url,
            responseType: 'stream'
        });

        res.set('Content-Type', response.headers['content-type']);
        if (response.headers['content-length']) {
            res.set('Content-Length', response.headers['content-length']);
        }
        // Cache at edge and browser for 30 days (media is immutable)
        res.set('Cache-Control', 'public, max-age=2592000, immutable');
        res.set('Access-Control-Allow-Origin', '*');

        response.data.pipe(res);
    } catch (error) {
        console.error('Proxy error:', error.message);
        res.status(error.response?.status || 500).send('CDN Edge Error');
    }
});

// ── Telegram Cleanup ────────────────────────────────────────────────────────
// Trigger a cleanup cycle for media older than 15 days
app.post('/cleanup/telegram', async (req, res) => {
    const { key } = req.body;
    if (key !== process.env.Z_CDN_KEY) return res.status(401).send('Unauthorized');

    try {
        const { spawn } = require('child_process');
        const cleanupProcess = spawn('node', ['scripts/cleanupTelegram.js'], {
            detached: true,
            stdio: 'ignore'
        });
        cleanupProcess.unref();

        res.json({ status: 'Cleanup triggered successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ── Telegram Proxy ──────────────────────────────────────────────────────────
// Proxy media from Telegram servers to bypass CORS and provide a cleaner URL
app.get('/tg-proxy', async (req, res) => {
    const { fileId } = req.query;
    if (!fileId) return res.status(400).send('Missing fileId');

    try {
        const file = await bot.getFile(fileId);
        const fileUrl = `https://api.telegram.org/file/bot${process.env.TELEGRAM_BOT_TOKEN}/${file.file_path}`;

        const response = await axios({
            method: 'GET',
            url: fileUrl,
            responseType: 'stream'
        });

        res.set('Content-Type', response.headers['content-type']);
        res.set('Cache-Control', 'public, max-age=2592000, immutable');
        response.data.pipe(res);
    } catch (error) {
        console.error('Telegram proxy error:', error.message);
        res.status(500).send('Telegram Proxy Error');
    }
});

// ── Telegram Upload ─────────────────────────────────────────────────────────
// Allow local CDN nodes to upload to the Z-Chat Telegram storage
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });

app.post('/upload/telegram', upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).send('No file uploaded');

    try {
        const result = await bot.sendDocument(process.env.TELEGRAM_CHAT_ID, req.file.buffer, {
            contentType: req.file.mimetype,
            filename: req.file.originalname
        });

        const fileId = result.document ? result.document.file_id : result.photo[result.photo.length - 1].file_id;
        res.json({
            url: `tg://${fileId}`,
            fileId: fileId,
            messageId: result.message_id,
            provider: 'telegram'
        });

    } catch (error) {
        console.error('Telegram upload error:', error.message);
        res.status(500).send('Telegram Upload Error');
    }
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, region: REGION }));

// ── Socket.io Signaling ──────────────────────────────────────────────────────
const { Server } = require('socket.io');
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] },
    transports: ['websocket', 'polling']
});

const onlineUsers = new Map();

io.on('connection', (socket) => {
    socket.on('user-online', (uid) => {
        if (!uid) return;
        onlineUsers.set(uid, socket.id);
        socket.data.uid = uid;
        socket.join(`user:${uid}`);
        socket.broadcast.emit('user-status', { uid, online: true });
    });

    socket.on('join-room', (roomId) => {
        socket.join(roomId);
        socket.to(roomId).emit('user-joined', { socketId: socket.id });
    });

    socket.on('call-offer', (data) => {
        const targetSocket = onlineUsers.get(data.targetUid);
        if (targetSocket) io.to(targetSocket).emit('call-offer', { ...data, callerUid: socket.data.uid });
    });

    socket.on('call-answer', (data) => {
        const targetSocket = onlineUsers.get(data.targetUid);
        if (targetSocket) io.to(targetSocket).emit('call-answer', data);
    });

    socket.on('ice-candidate', (data) => {
        const targetSocket = onlineUsers.get(data.targetUid);
        if (targetSocket) io.to(targetSocket).emit('ice-candidate', data);
    });

    socket.on('call-end', (data) => {
        const targetSocket = onlineUsers.get(data.targetUid);
        if (targetSocket) io.to(targetSocket).emit('call-end', data);
    });

    socket.on('disconnect', () => {
        const uid = socket.data.uid;
        if (uid) {
            onlineUsers.delete(uid);
            socket.broadcast.emit('user-status', { uid, online: false });
        }
    });
});

// ── Self-Pinging (Keep-Alive) ────────────────────────────────────────────────
const SELF_SERVICE_URL = process.env.SELF_SERVICE_URL;
if (SELF_SERVICE_URL) {
    const PING_INTERVAL = 13 * 60 * 1000; // 13 minutes
    setInterval(async () => {
        try {
            await axios.get(SELF_SERVICE_URL);
            console.log(`[Keep-Alive] Self-ping successful: ${SELF_SERVICE_URL}`);
        } catch (err) {
            console.warn(`[Keep-Alive] Self-ping failed: ${err.message}`);
        }
    }, PING_INTERVAL);
    console.log(`[Keep-Alive] Self-pinging ${SELF_SERVICE_URL} every 13 minutes`);
}

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`Z-CDN-Node [${REGION}] with Signaling running on port ${PORT}`));
