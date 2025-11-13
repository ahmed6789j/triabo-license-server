#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const PRIVATE_KEY_PATH = path.join(__dirname, 'private.pem');
if(!fs.existsSync(PRIVATE_KEY_PATH)){
  console.error('Missing private.pem - generate keys first (see README).');
  process.exit(1);
}
const PRIVATE_KEY = fs.readFileSync(PRIVATE_KEY_PATH);
function genKey(prefix='TRIABO', len=12){
  const rnd = crypto.randomBytes(16).toString('hex').slice(0,len).toUpperCase();
  return `${prefix}-${rnd}`;
}
const args = process.argv.slice(2);
if(args[0] === 'create'){
  const key = genKey();
  const payload = { license_key: key, created_at: Date.now(), type: 'full' };
  const token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  console.log('LICENSE_KEY:', key);
  console.log('SIGNED_TOKEN:', token);
} else {
  console.log('Usage: node license_tool.js create');
}
