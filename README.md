# Rebel Ink — Web Service only (no database)

This version runs as a plain **Render Web Service**.  
No PostgreSQL. No Blueprint. No extra environment variables required.

## Deploy

1. Push this folder to GitHub (`server.js`, `package.json`, `public/` at repo root).
2. Render → **New → Web Service**
3. Connect the repo
4. Settings:
   - Runtime: **Node**
   - Build Command: `npm install`
   - Start Command: `npm start`
   - Plan: **Free**
5. (Optional but recommended) Environment variables:
   - `JWT_SECRET` = long random string (32+ chars)
   - `ADMIN_SETUP_TOKEN` = long random string (24+ chars)  
   If you skip them the app generates temporary ones (they change on every restart).
6. Deploy.

## First admin

Open the **Logs**. You will see:

```
FIRST ADMIN SETUP REQUIRED. Open /admin-setup?token=...
```

Copy that URL, open it, choose your admin email/password.

## Critical limitation

On free Render the Web Service **sleeps after ~15 minutes** of no traffic.  
When it wakes up (or when you redeploy), **all members and appointments are wiped**.

This is normal for in-memory storage. If you need data to survive, you must use the Postgres version instead.

## Health check

`GET /api/health`
