Triabo License Server - Final Package (with Server Started notification)
-----------------------------------------------------------------------

Files included:
- server.js
- package.json
- public/admin.html
- triabo_extension_auth.js
- license_tool.js
- send_telegram_test.js
- Dockerfile
- docker-compose.yml
- .env.example

What's new:
- On server startup the server will call `notifyAdmin(...)` to send a "Server started" message to Telegram (if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set).

How to deploy to Render manually (fast):
1. Create a new GitHub repo and push these files (do NOT push private.pem).
2. On Render, create a new Web Service -> Connect to GitHub -> Select repo -> Set build command `npm install` and start command `node server.js`.
3. Add environment variables on Render's dashboard (set ADMIN_TOKEN and others).
4. Ensure you upload private.pem and public.pem to the server via Render's files or use Secrets/Files feature.
5. Render will provide HTTPS automatically (required for WebAuthn).

If you want me to deploy to Render for you I need one of the following:
A) A GitHub repo URL where I can push these files (add me as collaborator) — or
B) You upload this zip as a repo/archive in your Render dashboard and connect it, then grant me access or tell me the repo name so I can finish setup, or
C) A temporary Render API key with permissions to create a service (NOT recommended to paste in chat).

Tell me which method you prefer and I'll proceed. If you want full automated deploy now, provide the GitHub repo URL and add me as a collaborator (tell me the GitHub username to invite) or upload the zip and give me a link.
