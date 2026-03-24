# Z-CDN-Node

Z Chat CDN edge node - deploy one per Render region.

## Endpoints
- `/ping` - latency probe
- `/proxy?url=...` - streams OCI media
- `/health` - uptime

## Deploy to Render
1. Connect repo to Render Web Service
2. Build: `npm install` | Start: `node server.js`
3. Env vars: `REGION=singapore` and `RENDER_EXTERNAL_URL=https://your-cdn.onrender.com`
