require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const compression = require('compression');
const http = require('http');
const https = require('https');
const TelegramBot = require('node-telegram-bot-api');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const multer = require('multer');

const app = express();
const server = http.createServer(app);

// ── Security Headers ──────────────────────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "img-src": ["'self'", "data:", "https:", "blob:"],
            "media-src": ["'self'", "https:", "blob:"],
            "connect-src": ["'self'", "https:", "wss:"],
        },
    },
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(compression());
app.use(express.json({ limit: '1mb' }));

// ── Strict CORS ───────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
    'https://zchatweb.duckdns.org',
    'https://z-chateueast.duckdns.org',
    'https://zchatcentral.duckdns.org',
    'https://z-chat-asia.duckdns.org',
    'https://zchatohio.duckdns.org',
    'https://zchat-signal.duckdns.org',
    'http://localhost:5173',
    'http://localhost:3001',
    'http://localhost:3000'
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(origin) || origin.endsWith('.onrender.com')) {
            callback(null, true);
        } else {
            console.warn(`[CORS] Security Warning: Blocked origin ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// ── Socket.io Setup ───────────────────────────────────────────────────────────
const io = require('socket.io')(server, {
    cors: { 
        origin: (origin, callback) => {
            if (!origin || ALLOWED_ORIGINS.includes(origin) || origin.endsWith('.onrender.com')) {
                callback(null, true);
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        },
        methods: ['GET', 'POST'] 
    },
    transports: ['websocket', 'polling']
});

// Force IPv4 for all axios requests to prevent ECONNRESET with Telegram
axios.defaults.httpsAgent = new https.Agent({ family: 4 });

// ── Firebase Admin (STRICT: ENV ONLY) ──────────────────────────────────────────
let adminDb = null;
let fcmMessaging = null;

try {
    let credential;
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        let rawData = process.env.FIREBASE_SERVICE_ACCOUNT.trim();
        if (rawData.startsWith("'") && rawData.endsWith("'")) rawData = rawData.slice(1, -1);
        if (rawData.startsWith('"') && rawData.endsWith('"')) rawData = rawData.slice(1, -1);

        try {
            if (rawData.length > 100 && !rawData.trim().startsWith('{')) {
                rawData = Buffer.from(rawData, 'base64').toString('utf-8');
            }
            const serviceAccount = JSON.parse(rawData);
            if (serviceAccount.private_key && typeof serviceAccount.private_key === 'string') {
                serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
            }
            credential = admin.credential.cert(serviceAccount);
        } catch (parseError) {
            console.error('[FCM] CRITICAL: FIREBASE_SERVICE_ACCOUNT is invalid JSON.');
        }
    }

    if (credential) {
        admin.initializeApp({
            credential,
            projectId: 'z-chat-144',
            databaseURL: process.env.DATABASE_URL || "https://z-chat-144-default-rtdb.asia-southeast1.firebasedatabase.app"
        });
        adminDb = admin.firestore();
        fcmMessaging = admin.messaging();
        console.log('[FCM] Firebase Admin initialised via Environment Variable');
    } else {
        console.error('[FCM] CRITICAL: No Firebase credentials found.');
    }
} catch (e) {
    console.error('[FCM] Firebase Admin failed to load:', e.message);
}

// ── Telegram Bot Setup ────────────────────────────────────────────────────────
const bot = process.env.TELEGRAM_BOT_TOKEN ? new TelegramBot(process.env.TELEGRAM_BOT_TOKEN) : null;

// ── Email Transporter ────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

const REGION = process.env.REGION || 'unknown';
const PEER_NODES = [
    'https://z-chateueast.duckdns.org',
    'https://zchatcentral.duckdns.org',
    'https://z-chat-asia.duckdns.org',
    'https://zchatohio.duckdns.org',
    'https://your-node-name.onrender.com'
].filter(url => !url.includes(process.env.SELF_DOMAIN || 'localhost') && !url.includes('your-node-name'));

// ── Rate Limiting ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: 'Too many authentication requests, try again later' }
});

const twoFaLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 4,
    message: { error: 'Too many OTP requests from this IP, please try again after a minute' },
    standardHeaders: true, 
    legacyHeaders: false,
});

// ── 2FA Endpoints ─────────────────────────────────────────────────────────────
app.post('/auth/2fa/send-code', twoFaLimiter, async (req, res) => {
    const { email, uid, resend = false } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    if (!adminDb) return res.status(503).json({ error: 'Firebase Admin not initialized' });
    if (!email || !uid) return res.status(400).json({ error: 'Email and UID are required' });

    try {
        const docRef = adminDb.collection('twoFactorCodes').doc(uid);
        const docSnap = await docRef.get();
        let code;
        let isNew = false;

        if (docSnap.exists) {
            const data = docSnap.data();
            const now = admin.firestore.Timestamp.now();
            if (data.expiresAt.toMillis() > now.toMillis()) {
                code = data.code;
            }
        }

        if (!code) {
            code = Math.floor(100000 + Math.random() * 900000).toString();
            const expiresAt = new Date(Date.now() + 5 * 60000);
            isNew = true;
            await docRef.set({
                code,
                expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
                email,
                ip: ip || 'unknown'
            });
        }

        if (!isNew && !resend) {
            return res.json({ success: true, reused: true, silent: true });
        }

        const mailOptions = {
            from: `"Z Chat Security" <${process.env.SMTP_USER}>`,
            to: email,
            subject: 'Your Z Chat Verification Code',
            html: `<div style="font-family: sans-serif; max-width: 500px; margin: auto; padding: 20px; border: 1px solid #777; border-radius: 10px; background: #000; color: #fff;">
                    <h2 style="color: #ff3040; text-align: center;">Z Chat Security</h2>
                    <p>Your verification code is: <b style="font-size: 24px;">${code}</b></p>
                    <p style="font-size: 13px; color: #aaa;">Expires in 5 minutes.</p>
                </div>`
        };

        if (process.env.SMTP_USER) {
            await transporter.sendMail(mailOptions);
        }
        res.json({ success: true, reused: !isNew });
    } catch (err) {
        res.status(500).json({ error: 'Verification error' });
    }
});

app.post('/auth/2fa/verify-code', async (req, res) => {
    const { uid, code } = req.body;
    if (!adminDb) return res.status(503).json({ error: 'Auth Unavailable' });
    try {
        const userDoc = await adminDb.collection('users').doc(uid).get();
        const userData = userDoc.data();

        if (userData?.twoFactorType === 'authenticator' && userData?.totpSecret) {
            if (authenticator.check(code, userData.totpSecret)) return res.json({ success: true });
            return res.status(400).json({ error: 'Invalid authenticator code' });
        }

        const docRef = adminDb.collection('twoFactorCodes').doc(uid);
        const docSnap = await docRef.get();
        if (docSnap.exists) {
            const data = docSnap.data();
            if (data.code === code && data.expiresAt.toMillis() > Date.now()) {
                await docRef.delete();
                return res.json({ success: true });
            }
        }
        return res.status(400).json({ error: 'Invalid or expired code' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to verify' });
    }
});

app.post('/auth/2fa/totp/setup', async (req, res) => {
    const { email, uid } = req.body;
    if (!adminDb) return res.status(503).json({ error: 'Firebase Admin not initialized' });
    try {
        const secret = authenticator.generateSecret();
        const otpauth = authenticator.keyuri(email, 'Z Chat', secret);
        const qrCodeUrl = await QRCode.toDataURL(otpauth);
        await adminDb.collection('tempTotpSecrets').doc(uid).set({ secret, createdAt: admin.firestore.Timestamp.now() });
        res.json({ secret, qrCodeUrl });
    } catch (err) {
        res.status(500).json({ error: 'Failed to generate TOTP' });
    }
});

app.post('/auth/2fa/totp/enable', async (req, res) => {
    const { uid, code } = req.body;
    if (!adminDb) return res.status(503).json({ error: 'Firebase Admin not initialized' });
    try {
        const tempSnap = await adminDb.collection('tempTotpSecrets').doc(uid).get();
        if (!tempSnap.exists) return res.status(404).json({ error: 'Setup session expired' });
        const { secret } = tempSnap.data();
        if (authenticator.check(code, secret)) {
            await adminDb.collection('users').doc(uid).update({ twoFactorEnabled: true, twoFactorType: 'authenticator', totpSecret: secret });
            await adminDb.collection('tempTotpSecrets').doc(uid).delete();
            return res.json({ success: true });
        }
        res.status(400).json({ error: 'Invalid code' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to enable TOTP' });
    }
});

app.post('/auth/verify-login-code', authLimiter, async (req, res) => {
    const { code } = req.body;
    if (!adminDb) return res.status(503).json({ error: 'Auth server unavailable' });
    try {
        const docRef = adminDb.collection('login_codes').doc(code);
        const docSnap = await docRef.get();
        if (!docSnap.exists || docSnap.data().expiresAt.toMillis() < Date.now()) {
            if (docSnap.exists) await docRef.delete();
            return res.status(401).json({ error: 'Invalid or expired code' });
        }
        const customToken = await admin.auth().createCustomToken(docSnap.data().uid);
        await docRef.delete();
        res.json({ token: customToken });
    } catch (err) {
        res.status(500).json({ error: 'Internal Auth Error' });
    }
});

// ── Media Upload & Storage ───────────────────────────────────────────────────
const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/svg+xml', 'image/heic', 'image/heif', 'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime', 'video/x-msvideo', 'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm', 'audio/aac', 'audio/mp4', 'application/pdf']);
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (ALLOWED_MIME_TYPES.has(file.mimetype)) cb(null, true);
        else cb(new Error(`File type '${file.mimetype}' is not allowed.`), false);
    }
});

app.post('/upload/telegram', upload.single('file'), async (req, res) => {
    if (!req.file || !bot) return res.status(400).json({ error: 'Upload failed' });
    try {
        const result = await bot.sendDocument(process.env.TELEGRAM_CHAT_ID, req.file.buffer, { contentType: req.file.mimetype, filename: req.file.originalname });
        const fileId = result.document ? result.document.file_id : (result.photo ? result.photo[result.photo.length - 1].file_id : null);
        
        const userUid = req.body.userUid || req.query.userUid;
        if (userUid) backupFileToCloud(userUid, req.file.buffer, req.file.originalname, req.file.mimetype).catch(e => console.error('[Backup] Failed:', e.message));

        res.json({ url: `tg://${fileId}`, fileId, provider: 'telegram' });
    } catch (error) {
        res.status(500).json({ error: 'Telegram Upload Error' });
    }
});

// ── Cloud Backup Helpers ──────────────────────────────────────────────────────
async function backupFileToCloud(userUid, buffer, filename, mimetype) {
    if (!adminDb) return;
    const userSnap = await adminDb.collection('users').doc(userUid).get();
    if (!userSnap.exists) return;
    const { backupSettings } = userSnap.data();
    if (!backupSettings) return;

    const isImage = mimetype.startsWith('image/');
    const isVideo = mimetype.startsWith('video/');
    const isOther = !isImage && !isVideo;

    // Google Drive
    if (backupSettings.google?.connected && backupSettings.google?.enabled !== false) {
        const canBackup = (isImage && backupSettings.google.backupImages) || (isVideo && backupSettings.google.backupVideos) || (isOther && backupSettings.google.backupOthers);
        if (canBackup) uploadToGoogleDrive(userUid, backupSettings.google, buffer, filename, mimetype).catch(e => console.error('[Backup] GDrive Error:', e.message));
    }

    // OneDrive
    if (backupSettings.onedrive?.connected && backupSettings.onedrive?.enabled !== false) {
        const canBackup = (isImage && backupSettings.onedrive.backupImages) || (isVideo && backupSettings.onedrive.backupVideos) || (isOther && backupSettings.onedrive.backupOthers);
        if (canBackup) uploadToOneDrive(userUid, backupSettings.onedrive, buffer, filename, mimetype).catch(e => console.error('[Backup] OneDrive Error:', e.message));
    }
}

async function uploadToGoogleDrive(userUid, googleSettings, buffer, filename, mimetype) {
    let accessToken = await refreshGoogleToken(userUid, googleSettings.refreshToken);
    const metadata = { name: `ZChat_${Date.now()}_${filename}`, parents: googleSettings.folderId ? [googleSettings.folderId] : [] };
    const boundary = '-------314159265358979323846';
    const delimiter = "\r\n--" + boundary + "\r\n";
    const close_delim = "\r\n--" + boundary + "--";
    const multipartBody = delimiter + 'Content-Type: application/json; charset=UTF-8\r\n\r\n' + JSON.stringify(metadata) + delimiter + 'Content-Type: ' + mimetype + '\r\n\r\n' + buffer.toString('base64') + close_delim;

    await axios.post('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', Buffer.from(multipartBody, 'utf8'), {
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': `multipart/related; boundary=${boundary}`, 'Content-Transfer-Encoding': 'base64' }
    });
}

async function uploadToOneDrive(userUid, onedriveSettings, buffer, filename, mimetype) {
    let accessToken = await refreshOneDriveToken(userUid, onedriveSettings.refreshToken);
    const sanitizedName = `ZChat_${Date.now()}_${filename.replace(/[^a-zA-Z0-9.]/g, '_')}`;
    await axios.put(`https://graph.microsoft.com/v1.0/me/drive/root:/ZChat_Media/${sanitizedName}:/content`, buffer, {
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': mimetype }
    });
}

async function refreshGoogleToken(userUid, refreshToken) {
    const res = await axios.post('https://oauth2.googleapis.com/token', {
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: 'refresh_token'
    });
    return res.data.access_token;
}

async function refreshOneDriveToken(userUid, refreshToken) {
    const res = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', new URLSearchParams({
        client_id: process.env.MS_CLIENT_ID,
        client_secret: process.env.MS_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: 'Files.ReadWrite offline_access'
    }));
    return res.data.access_token;
}

// ── OAuth Initialization ─────────────────────────────────────────────────────
app.get('/auth/google/init', (req, res) => {
    const url = `https://accounts.google.com/o/oauth2/v2/auth?` + new URLSearchParams({ client_id: process.env.GOOGLE_CLIENT_ID, redirect_uri: `${process.env.CDN_URL}/auth/google/callback`, response_type: 'code', scope: 'https://www.googleapis.com/auth/drive.file', access_type: 'offline', prompt: 'consent', state: req.query.uid }).toString();
    res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
    const { code, state: uid } = req.query;
    try {
        const tr = await axios.post('https://oauth2.googleapis.com/token', { code, client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET, redirect_uri: `${process.env.CDN_URL}/auth/google/callback`, grant_type: 'authorization_code' });
        await adminDb.collection('users').doc(uid).update({ 'backupSettings.google': { connected: true, refreshToken: tr.data.refresh_token, backupImages: true, backupVideos: true, backupOthers: true } });
        res.send('<html><body><script>window.close();</script>Google Drive linked!</body></html>');
    } catch (e) { res.status(500).send('Auth Error'); }
});

app.get('/auth/onedrive/init', (req, res) => {
    const url = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?` + new URLSearchParams({ client_id: process.env.MS_CLIENT_ID, redirect_uri: `${process.env.CDN_URL}/auth/onedrive/callback`, response_type: 'code', scope: 'Files.ReadWrite offline_access', state: req.query.uid }).toString();
    res.redirect(url);
});

app.get('/auth/onedrive/callback', async (req, res) => {
    const { code, state: uid } = req.query;
    try {
        const tr = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', new URLSearchParams({ code, client_id: process.env.MS_CLIENT_ID, client_secret: process.env.MS_CLIENT_SECRET, redirect_uri: `${process.env.CDN_URL}/auth/onedrive/callback`, grant_type: 'authorization_code' }));
        await adminDb.collection('users').doc(uid).update({ 'backupSettings.onedrive': { connected: true, refreshToken: tr.data.refresh_token, backupImages: true, backupVideos: true, backupOthers: true } });
        res.send('<html><body><script>window.close();</script>OneDrive linked!</body></html>');
    } catch (e) { res.status(500).send('Auth Error'); }
});

// ── Signaling & Health ────────────────────────────────────────────────────────
app.get('/ping', (req, res) => res.json({ status: 'ok', region: REGION, timestamp: Date.now() }));
app.get('/health', (req, res) => res.json({ ok: true, region: REGION }));

const onlineUsers = new Map();
async function relaySignal(event, data, excludeNode = null) {
    if (data._relayed) return;
    const relayData = { ...data, _relayed: true };
    const promises = PEER_NODES.map(async nodeUrl => {
        if (nodeUrl === excludeNode) return;
        try { await axios.post(`${nodeUrl}/api/relay/signal`, { event, data: relayData }, { timeout: 2000 }); } catch (err) {}
    });
    await Promise.all(promises);
}

app.post('/api/relay/signal', (req, res) => {
    const { event, data } = req.body;
    const targetSocket = onlineUsers.get(data?.targetUid);
    if (targetSocket) io.to(targetSocket).emit(event, data);
    res.sendStatus(200);
});

io.on('connection', (socket) => {
    socket.on('user-online', (uid) => { if (uid) { onlineUsers.set(uid, socket.id); socket.data.uid = uid; socket.join(`user:${uid}`); socket.broadcast.emit('user-status', { uid, online: true }); } });
    socket.on('join-room', (roomId) => { socket.join(roomId); socket.to(roomId).emit('user-joined', { socketId: socket.id }); });
    socket.on('call-offer', (data) => { const ts = onlineUsers.get(data.targetUid); if (ts) io.to(ts).emit('call-offer', { ...data, callerUid: socket.data.uid }); else relaySignal('call-offer', { ...data, callerUid: socket.data.uid }); });
    socket.on('call-answer', (data) => { const ts = onlineUsers.get(data.targetUid); if (ts) io.to(ts).emit('call-answer', data); else relaySignal('call-answer', data); });
    socket.on('ice-candidate', (data) => { const ts = onlineUsers.get(data.targetUid); if (ts) io.to(ts).emit('ice-candidate', data); else relaySignal('ice-candidate', data); });
    socket.on('call-end', (data) => { const ts = onlineUsers.get(data.targetUid); if (ts) io.to(ts).emit('call-end', data); else relaySignal('call-end', data); });
    socket.on('disconnect', () => { const uid = socket.data.uid; if (uid) { onlineUsers.delete(uid); socket.broadcast.emit('user-status', { uid, online: false }); } });
});

setInterval(async () => {
    const promises = PEER_NODES.map(async url => { try { await axios.get(`${url}/ping`); } catch (err) {} });
    await Promise.all(promises);
}, 13 * 60 * 1000);

app.get('*', (req, res) => {
    const ext = path.extname(req.url);
    if (ext && ext !== '.html') return res.status(404).send('Not Found');
    const indexPath = path.join(__dirname, '../dist', 'index.html');
    if (fs.existsSync(indexPath)) res.sendFile(indexPath);
    else res.status(200).send(`Z-CDN-Node [${REGION}] Active`);
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`Z-CDN-Node [${REGION}] SECURED running on port ${PORT}`));
