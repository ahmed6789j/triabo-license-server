// send_telegram_test.js - sends a test message using TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID env vars
const fetch = require('node-fetch');
const BOT = process.env.TELEGRAM_BOT_TOKEN;
const CHAT = process.env.TELEGRAM_CHAT_ID;
const msg = process.argv.slice(2).join(' ') || 'Triabo test message';
if(!BOT || !CHAT){ console.error('TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set'); process.exit(1); }
(async ()=>{
  const res = await fetch(`https://api.telegram.org/bot${BOT}/sendMessage`, {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ chat_id: CHAT, text: msg })
  });
  const j = await res.json();
  console.log('telegram response', j);
})();
