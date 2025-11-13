// triabo_extension_auth.js (with activation)
async function generateHWID(){
  const parts = [];
  parts.push(navigator.userAgent || '');
  parts.push(navigator.platform || '');
  parts.push(navigator.language || '');
  parts.push(screen.width + 'x' + screen.height);
  parts.push(navigator.hardwareConcurrency || '');
  parts.push(navigator.deviceMemory || '');
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = "14px 'Arial'";
    ctx.fillText('TriaboFingerprint', 2, 2);
    const data = canvas.toDataURL();
    parts.push(data.slice(0,50));
  } catch(e){}
  let iid = localStorage.getItem('triabo_installer_id');
  if(!iid){
    iid = crypto.getRandomValues(new Uint32Array(4)).join('-');
    localStorage.setItem('triabo_installer_id', iid);
  }
  parts.push(iid);
  const encoder = new TextEncoder();
  const msg = parts.join('||');
  const buf = encoder.encode(msg);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buf);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2,'0')).join('');
}

async function activateLicense(license_key){
  const hwid = await generateHWID();
  const resp = await fetch('https://YOUR_LICENSE_SERVER_DOMAIN/api/activate', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ license_key, hwid, client_info: { ua: navigator.userAgent } })
  });
  const j = await resp.json();
  if(!j.ok) throw new Error(j.error || 'activation failed');
  const token = j.token;
  localStorage.setItem('triabo_license_token', token);
  return true;
}
