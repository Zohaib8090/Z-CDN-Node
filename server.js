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
// Note: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, MS_CLIENT_ID, MS_CLIENT_SECRET, and CDN_URL must be set in .env

const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: false });

const app = express();
const distPath = path.join(__dirname, '../dist');
app.use(express.static(distPath));
app.use(compression()); // Reduces bandwidth usage

const server = http.createServer(app);
const io = require('socket.io')(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] },
    transports: ['websocket', 'polling']
});

// Force IPv4 for all axios requests to prevent ECONNRESET with Telegram
axios.defaults.httpsAgent = new https.Agent({ family: 4 });


// ── Firebase Admin ────────────────────────────────────────────────────────────
let adminDb = null;
let fcmMessaging = null;

try {
    let credential;

    // Prioritize local file if it exists (requested for private repo)
    if (fs.existsSync(path.resolve(__dirname, 'serviceAccountKey.json'))) {
        const serviceAccount = require('./serviceAccountKey.json');
        credential = admin.credential.cert(serviceAccount);
        console.log('[FCM] Using local serviceAccountKey.json');
    } 
    // Fallback to environment variable
    else if (process.env.FIREBASE_SERVICE_ACCOUNT && process.env.FIREBASE_SERVICE_ACCOUNT !== 'PASTE_SINGLE_LINE_JSON_HERE') {
        try {
            // Production: use env var (JSON string or Base64)
            let rawData = process.env.FIREBASE_SERVICE_ACCOUNT.trim();
            
            // Auto-fix common escaping issues
            if (rawData.startsWith("'") && rawData.endsWith("'")) rawData = rawData.slice(1, -1);
            if (rawData.startsWith('"') && rawData.endsWith('"')) rawData = rawData.slice(1, -1);

            // Handle Base64 encoding if the string doesn't look like JSON
            if (rawData.length > 500 && !rawData.trim().startsWith('{')) {
                try {
                    console.log('[FCM] Detected Base64 encoded service account, decoding...');
                    rawData = Buffer.from(rawData, 'base64').toString('utf-8');
                } catch (b64Error) {
                    console.warn('[FCM] Failed to decode as Base64, trying as raw string');
                }
            }

            const serviceAccount = JSON.parse(rawData);
            
            // Fix double-escaped newlines in private key if they exist
            if (serviceAccount.private_key && typeof serviceAccount.private_key === 'string') {
                serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
            }

            credential = admin.credential.cert(serviceAccount);
        } catch (parseError) {
            console.error('[FCM] CRITICAL: FIREBASE_SERVICE_ACCOUNT is set but contains INVALID JSON:', parseError.message);
        }
    }

    if (credential) {
        try {
            admin.initializeApp({
                credential,
                projectId: 'z-chat-144',
                databaseURL: process.env.DATABASE_URL || "https://z-chat-144-default-rtdb.asia-southeast1.firebasedatabase.app"
            });
            adminDb = admin.firestore();
            fcmMessaging = admin.messaging();
            console.log('[FCM] Firebase Admin initialised successfully');
        } catch (initError) {
            console.error('[FCM] CRITICAL: Firebase app initialization failed:', initError.message);
        }
    } else {
        console.warn('[FCM] No Firebase credentials found — 2FA and push notifications disabled.');
        console.warn('  → Local key missing at:', path.resolve(__dirname, 'serviceAccountKey.json'));
        console.warn('  → Env var FIREBASE_SERVICE_ACCOUNT is:', process.env.FIREBASE_SERVICE_ACCOUNT ? 'SET (but possibly failed parse)' : 'NOT SET');
    }
} catch (e) {
    console.warn('[FCM] firebase-admin failed to load:', e.message);
}


// ── CORS ────────────────────────────────────────────────────────────────
// Explicit CORS allowlist — no regex wildcards that could allow unexpected domains.
// Add allowed origins to the ALLOWED_ORIGINS env var (comma-separated) in production.
const DEFAULT_CORS_ORIGINS = [
    'https://zchatweb.duckdns.org',
    'https://z-chateueast.duckdns.org',
    'https://zchatcentral.duckdns.org',
    'https://z-chat-asia.duckdns.org',
    'https://zchatohio.duckdns.org',
    'https://zchat-signal.duckdns.org',
    'https://z-chat-mini-cdn-oregon.onrender.com',
    'https://zchat-cdn-sg.onrender.com',
    'https://zchat-cdn-ohio.onrender.com',
    'https://zchat-cdn-fra.onrender.com',
    'https://zchat-cdn-oregon.onrender.com',
    'http://localhost:5173',
    'http://localhost:3001',
    'http://localhost:3000',
];
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : DEFAULT_CORS_ORIGINS;

app.use(cors({
    origin: (origin, callback) => {
        // Allow same-origin requests (no origin header) and Electron
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`[CORS] Blocked request from unauthorized origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '1mb' }));

// ── Security Headers ───────────────────────────────────────────────────────────
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=self, microphone=self, geolocation=(), payment=(), usb=()');
    if (req.headers['x-forwarded-proto'] === 'https' || req.secure) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }
    next();
});

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

// ── Peer Nodes for Signaling Relay ───────────────────────────────────────────
const PEER_NODES = [
    'https://z-chateueast.duckdns.org',
    'https://zchatcentral.duckdns.org',
    'https://z-chat-asia.duckdns.org',
    'https://zchatohio.duckdns.org'
].filter(url => !url.includes(process.env.SELF_DOMAIN || 'localhost')); // Don't relay to self

// ── Root – serve the React app UI ───────────────────────────────────────────
app.get('/', (req, res) => {
    const indexPath = path.join(distPath, 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.status(200).send(`Z-CDN-Node [${REGION}] is Active (UI not built)`);
    }
});

// ── Ping – latency probe used by the CDN router in Z Chat ────────────────────
app.get('/ping', (req, res) => {
    res.json({ status: 'ok', region: REGION, timestamp: Date.now() });
});

// ── Rate Limiting ─────────────────────────────────────────────────────────────
const twoFaLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute window
    max: 4, // Limit each IP to 4 requests per windowMs
    message: { error: 'Too many OTP requests from this IP, please try again after a minute' },
    standardHeaders: true, 
    legacyHeaders: false,
});

// ── 2FA Endpoints ─────────────────────────────────────────────────────────────
app.post('/auth/2fa/send-code', twoFaLimiter, async (req, res) => {
    const { email, uid, resend = false } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    if (!adminDb) return res.status(503).json({ error: 'Firebase Admin not initialized on server. Check FIREBASE_SERVICE_ACCOUNT variable.' });
    if (!email || !uid) return res.status(400).json({ error: 'Email and UID are required' });

    try {
        const docRef = adminDb.collection('twoFactorCodes').doc(uid);
        const docSnap = await docRef.get();
        let code;
        let expiresAt;
        let isNew = false;

        // Reuse existing code if it's still valid (within its 10-minute expiry)
        if (docSnap.exists) {
            const data = docSnap.data();
            const now = admin.firestore.Timestamp.now();
            
            if (data.expiresAt.toMillis() > now.toMillis()) {
                code = data.code;
                expiresAt = data.expiresAt.toDate();
                console.log(`[2FA] Reusing existing code for ${email} (IP: ${ip})`);
            }
        }

        // Generate new code only if none exists or it has expired
        if (!code) {
            code = Math.floor(100000 + Math.random() * 900000).toString();
            expiresAt = new Date(Date.now() + 5 * 60000); // 5 minutes from now
            isNew = true;

            // Save to Firestore
            await docRef.set({
                code,
                expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
                email,
                ip: ip || 'unknown'
            });
            console.log(`[2FA] Generated NEW code for ${email} (IP: ${ip})`);
        } else {
            // Update IP on resend if it changed
            await docRef.update({ ip: ip || 'unknown' });
        }

        // SILENT SUCCESS: If code is reused and NOT a manual resend, skip the email
        if (!isNew && !resend) {
            console.log(`[2FA] Silent success for ${email} (No email sent on reload)`);
            return res.json({ success: true, reused: true, silent: true });
        }

        // Send Email (New code OR manual resend)
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
                    <p style="font-size: 13px; color: #aaa; text-align: center;">This code will expire in 5 minutes. If you did not request this code, please ignore this email.</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log(`[2FA] Email sent to ${email} (${isNew ? 'New' : 'Manual Resend'})`);
        res.json({ success: true, reused: !isNew });
    } catch (err) {
        console.error('[2FA] Send error:', err);
        res.status(500).json({ error: 'Failed to send verification code' });
    }
});

// ── TOTP (Authenticator) Setup ──────────────────────────────────────────────
app.post('/auth/2fa/totp/setup', async (req, res) => {
    const { email, uid } = req.body;
    if (!adminDb) return res.status(503).json({ error: 'Firebase Admin not initialized on server. Check FIREBASE_SERVICE_ACCOUNT variable.' });
    if (!uid || !email) return res.status(400).json({ error: 'UID and email are required' });

    try {
        const secret = authenticator.generateSecret();
        const otpauth = authenticator.keyuri(email, 'Z Chat', secret);
        const qrCodeUrl = await QRCode.toDataURL(otpauth);

        // Temporarily store secret (unconfirmed)
        await adminDb.collection('tempTotpSecrets').doc(uid).set({
            secret,
            createdAt: admin.firestore.Timestamp.now()
        });

        res.json({ secret, qrCodeUrl });
    } catch (err) {
        console.error('[TOTP] Setup error:', err);
        res.status(500).json({ error: 'Failed to generate TOTP secret' });
    }
});

app.post('/auth/2fa/totp/enable', async (req, res) => {
    const { uid, code } = req.body;
    if (!adminDb) return res.status(503).json({ error: 'Firebase Admin not initialized on server. Check FIREBASE_SERVICE_ACCOUNT variable.' });
    if (!uid || !code) return res.status(400).json({ error: 'UID and code are required' });

    try {
        const tempSnap = await adminDb.collection('tempTotpSecrets').doc(uid).get();
        if (!tempSnap.exists) return res.status(404).json({ error: 'Setup session expired. Try again.' });

        const { secret } = tempSnap.data();
        const isValid = authenticator.check(code, secret);

        if (!isValid) return res.status(400).json({ error: 'Invalid authenticator code' });

        // Enable TOTP for user
        await adminDb.collection('users').doc(uid).update({
            twoFactorEnabled: true,
            twoFactorType: 'authenticator',
            totpSecret: secret
        });

        // Clean up temp secret
        await adminDb.collection('tempTotpSecrets').doc(uid).delete();

        res.json({ success: true });
    } catch (err) {
        console.error('[TOTP] Enable error:', err);
        res.status(500).json({ error: 'Failed to enable TOTP' });
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

        // 1. Check if user has TOTP enabled
        const userDoc = await adminDb.collection('users').doc(uid).get();
        const userData = userDoc.data();

        let totpValid = false;
        if (userData?.totpSecret) {
            totpValid = authenticator.check(code, userData.totpSecret);
            if (totpValid) {
                console.log(`[2FA] Authenticator code verified for ${uid}`);
                res.json({ success: true });
                return;
            }
        }

        // 2. Check Email Code as Backup
        if (docSnap.exists) {
            const emailData = docSnap.data();
            const now = admin.firestore.Timestamp.now();

            if (emailData.code === code) {
                if (now.toMillis() > emailData.expiresAt.toMillis()) {
                    return res.status(400).json({ error: 'Verification code expired' });
                }
                
                console.log(`[2FA] Email code verified for ${uid}`);
                // Success - clean up the code
                await docRef.delete();
                res.json({ success: true });
                return;
            }
        }

        // If we get here, neither matched
        return res.status(400).json({ error: 'Invalid verification code' });
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

// Security: Allowlist of safe MIME types — no executables, scripts, or archives
const ALLOWED_MIME_TYPES = new Set([
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp',
    'image/svg+xml', 'image/heic', 'image/heif',
    'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime', 'video/x-msvideo',
    'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm', 'audio/aac', 'audio/mp4',
    'application/pdf',
]);
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: MAX_FILE_SIZE },
    fileFilter: (req, file, cb) => {
        if (ALLOWED_MIME_TYPES.has(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error(`File type '${file.mimetype}' is not allowed.`), false);
        }
    }
});

app.post('/upload/telegram', (req, res, next) => {
    upload.single('file')(req, res, (err) => {
        if (err instanceof multer.MulterError) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(413).json({ error: 'File too large. Maximum size is 50MB.' });
            }
            return res.status(400).json({ error: err.message });
        } else if (err) {
            return res.status(400).json({ error: err.message });
        }
        next();
    });
}, async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    // Double-check: verify MIME type is still in the allowlist after multer
    if (!ALLOWED_MIME_TYPES.has(req.file.mimetype)) {
        return res.status(400).json({ error: 'File type not allowed' });
    }

    try {
        const result = await bot.sendDocument(process.env.TELEGRAM_CHAT_ID, req.file.buffer, {
            contentType: req.file.mimetype,
            filename: req.file.originalname
        });

        const fileId = result.document ? result.document.file_id : result.photo[result.photo.length - 1].file_id;
        const tgUrl = `tg://${fileId}`;

        // ── Backup to Cloud (Async) ───────────────────────────────────────────
        const userUid = req.body.userUid || req.query.userUid;
        if (userUid) {
            backupFileToCloud(userUid, req.file.buffer, req.file.originalname, req.file.mimetype)
                .catch(err => console.error('[Backup] Failed:', err.message));
        }

        res.json({
            url: tgUrl,
            fileId: fileId,
            messageId: result.message_id,
            provider: 'telegram'
        });

    } catch (error) {
        console.error('Telegram upload error:', error.message);
        res.status(500).json({ error: 'Telegram Upload Error' });
    }
});

// ── Backup Logic Helpers ──────────────────────────────────────────────────────
async function backupFileToCloud(userUid, buffer, filename, mimetype) {
    if (!adminDb) return;
    const userSnap = await adminDb.collection('users').doc(userUid).get();
    if (!userSnap.exists) return;
    
    const { backupSettings } = userSnap.data();
    if (!backupSettings) return;

    // Google Drive Backup
    if (backupSettings.google?.connected && backupSettings.google?.enabled !== false) {
        try {
            await uploadToGoogleDrive(userUid, backupSettings.google, buffer, filename, mimetype);
        } catch (err) {
            console.error('[Backup] Google Drive error:', err.message);
        }
    }

    // OneDrive Backup
    if (backupSettings.onedrive?.connected && backupSettings.onedrive?.enabled !== false) {
        try {
            await uploadToOneDrive(userUid, backupSettings.onedrive, buffer, filename, mimetype);
        } catch (err) {
            console.error('[Backup] OneDrive error:', err.message);
        }
    }
}

async function uploadToGoogleDrive(userUid, googleSettings, buffer, filename, mimetype) {
    let accessToken = await refreshGoogleToken(userUid, googleSettings.refreshToken);
    
    // 1. Create Metadata
    const metadata = {
        name: `ZChat_${Date.now()}_${filename}`,
        parents: googleSettings.folderId ? [googleSettings.folderId] : []
    };

    // 2. Simple upload (for files < 5MB, which is most chat media)
    const form = new URLSearchParams();
    // This is a simplified version, usually we'd use a multipart upload for reliability
    // For now, let's use the simplest possible REST call
    const boundary = '-------314159265358979323846';
    const delimiter = "\r\n--" + boundary + "\r\n";
    const close_delim = "\r\n--" + boundary + "--";

    const multipartBody = 
        delimiter + 'Content-Type: application/json; charset=UTF-8\r\n\r\n' + JSON.stringify(metadata) +
        delimiter + 'Content-Type: ' + mimetype + '\r\n\r\n' + buffer.toString('base64') +
        close_delim;

    await axios.post('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', 
        Buffer.from(multipartBody, 'utf8'), {
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': `multipart/related; boundary=${boundary}`,
            'Content-Transfer-Encoding': 'base64'
        }
    });
}

async function uploadToOneDrive(userUid, onedriveSettings, buffer, filename, mimetype) {
    let accessToken = await refreshOneDriveToken(userUid, onedriveSettings.refreshToken);
    const sanitizedName = `ZChat_${Date.now()}_${filename.replace(/[^a-zA-Z0-9.]/g, '_')}`;
    
    // OneDrive PUT upload (up to 4MB, for larger we'd need uploadSession)
    await axios.put(`https://graph.microsoft.com/v1.0/me/drive/root:/ZChat_Media/${sanitizedName}:/content`, buffer, {
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': mimetype
        }
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

// ── OAuth Routes ─────────────────────────────────────────────────────────────
app.get('/auth/google/init', (req, res) => {
    const { uid } = req.query;
    const url = `https://accounts.google.com/o/oauth2/v2/auth?` + 
        new URLSearchParams({
            client_id: process.env.GOOGLE_CLIENT_ID,
            redirect_uri: `${process.env.CDN_URL}/auth/google/callback`,
            response_type: 'code',
            scope: 'https://www.googleapis.com/auth/drive.file',
            access_type: 'offline',
            prompt: 'consent',
            state: uid
        }).toString();
    res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
    const { code, state: uid } = req.query;
    try {
        const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: `${process.env.CDN_URL}/auth/google/callback`,
            grant_type: 'authorization_code'
        });

        const { access_token, refresh_token } = tokenRes.data;
        
        await adminDb.collection('users').doc(uid).update({
            'backupSettings.google': {
                connected: true,
                refreshToken: refresh_token,
                backupImages: true,
                backupVideos: true,
                backupOthers: true,
                email: 'Connected' // Optional: fetch user info from Google
            }
        });

        res.send('<html><body><script>window.close();</script>Successfully linked Google Drive. You can close this window.</body></html>');
    } catch (err) {
        res.status(500).send('Google Auth Error: ' + err.message);
    }
});

app.get('/auth/onedrive/init', (req, res) => {
    const { uid } = req.query;
    const url = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?` + 
        new URLSearchParams({
            client_id: process.env.MS_CLIENT_ID,
            redirect_uri: `${process.env.CDN_URL}/auth/onedrive/callback`,
            response_type: 'code',
            scope: 'Files.ReadWrite offline_access',
            state: uid
        }).toString();
    res.redirect(url);
});

app.get('/auth/onedrive/callback', async (req, res) => {
    const { code, state: uid } = req.query;
    try {
        const tokenRes = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', new URLSearchParams({
            code,
            client_id: process.env.MS_CLIENT_ID,
            client_secret: process.env.MS_CLIENT_SECRET,
            redirect_uri: `${process.env.CDN_URL}/auth/onedrive/callback`,
            grant_type: 'authorization_code'
        }));

        const { access_token, refresh_token } = tokenRes.data;
        
        await adminDb.collection('users').doc(uid).update({
            'backupSettings.onedrive': {
                connected: true,
                refreshToken: refresh_token,
                backupImages: true,
                backupVideos: true,
                backupOthers: true
            }
        });

        res.send('<html><body><script>window.close();</script>Successfully linked OneDrive. You can close this window.</body></html>');
    } catch (err) {
        res.status(500).send('OneDrive Auth Error: ' + err.message);
    }
});


// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, region: REGION }));

const onlineUsers = new Map();

// Relay a signal to other nodes if user is not found locally
async function relaySignal(event, data, excludeNode = null) {
    // Prevent infinite loops by flagging relayed messages
    if (data._relayed) return;
    
    const relayData = { ...data, _relayed: true };
    const promises = PEER_NODES.map(async (nodeUrl) => {
        if (nodeUrl === excludeNode) return;
        try {
            await axios.post(`${nodeUrl}/api/relay/signal`, { event, data: relayData }, { timeout: 2000 });
        } catch (err) {
            // Silently fail if peer node is down
        }
    });
    await Promise.all(promises);
}

// Specialized endpoint for cross-node signaling
app.post('/api/relay/signal', (req, res) => {
    const { event, data } = req.body;
    if (!event || !data || !data.targetUid) return res.status(400).send('Invalid relay data');

    const targetSocket = onlineUsers.get(data.targetUid);
    if (targetSocket) {
        io.to(targetSocket).emit(event, data);
        console.log(`[Relay] Delivered ${event} to ${data.targetUid} on this node`);
    }
    
    res.sendStatus(200);
});

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
        if (targetSocket) {
            io.to(targetSocket).emit('call-offer', { ...data, callerUid: socket.data.uid });
        } else {
            relaySignal('call-offer', { ...data, callerUid: socket.data.uid });
        }
    });

    socket.on('call-answer', (data) => {
        const targetSocket = onlineUsers.get(data.targetUid);
        if (targetSocket) {
            io.to(targetSocket).emit('call-answer', data);
        } else {
            relaySignal('call-answer', data);
        }
    });

    socket.on('ice-candidate', (data) => {
        const targetSocket = onlineUsers.get(data.targetUid);
        if (targetSocket) {
            io.to(targetSocket).emit('ice-candidate', data);
        } else {
            relaySignal('ice-candidate', data);
        }
    });

    socket.on('call-end', (data) => {
        const targetSocket = onlineUsers.get(data.targetUid);
        if (targetSocket) {
            io.to(targetSocket).emit('call-end', data);
        } else {
            relaySignal('call-end', data);
        }
    });

    socket.on('disconnect', () => {
        const uid = socket.data.uid;
        if (uid) {
            onlineUsers.delete(uid);
            socket.broadcast.emit('user-status', { uid, online: false });
        }
    });
});

// ── Peer-to-Peer Keep-Alive (Mesh Pinging) ──────────────────────────────────
// Automatically pings all peer nodes every 13 minutes to prevent sleeping.
const PING_INTERVAL = 13 * 60 * 1000; // 13 minutes
setInterval(async () => {
    console.log(`[Keep-Alive] Starting Mesh Ping cycle...`);
    const promises = PEER_NODES.map(async (nodeUrl) => {
        try {
            await axios.get(`${nodeUrl}/ping`);
            console.log(`[Keep-Alive] Ping successful: ${nodeUrl}`);
        } catch (err) {
            console.warn(`[Keep-Alive] Ping failed for ${nodeUrl}: ${err.message}`);
        }
    });
    await Promise.all(promises);
}, PING_INTERVAL);
console.log(`[Keep-Alive] Automated Mesh Pinging active for ${PEER_NODES.length} peers.`);

// ── Error Handling ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
    console.error(`[Server Error] ${err.message}`);
    if (req.path.startsWith('/auth') || req.path.startsWith('/upload') || req.path.startsWith('/proxy')) {
        return res.status(500).json({ error: err.message || 'Internal Server Error' });
    }
    next(err);
});

// Catch-all route for Single Page Application
app.get('*', (req, res) => {
    // Only serve index.html for navigation requests (no file extension)
    // Avoid serving index.html for missing assets like .js, .css, .png, etc.
    const ext = path.extname(req.url);
    if (ext && ext !== '.html') {
        return res.status(404).send('Not Found');
    }

    const indexPath = path.join(distPath, 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.status(404).send('Z-CDN: index.html not found. Ensure you have run "npm run build".');
    }
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`Z-CDN-Node [${REGION}] with Signaling running on port ${PORT}`));
