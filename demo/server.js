// A small server that uses the same encrypted scheme as the bundled profile
// to test CrypticBurp without pointing it at a real app.
//
//   npm start      (or just: node server.js)
//
// Endpoints:
//   GET  /api?<ciphertext>   encrypted query string, Tab (0x09) padding
//   POST /api/message        encrypted JSON body, PKCS7 padding
//
// Responses are encrypted too, so the Decrypted tab is useful on both sides.
// Every request is logged in plaintext and ciphertext so you can check the
// extension against it.

const http = require('http');
const crypto = require('crypto');

// The server reads the same test profile you load into Burp.
// Change the key in one place and both sides follow. This is a copy of
// profiles/template.json, kept here so this folder works on its own.
const profile = require('./template.json');

const BLOCK = 16;
const TAB = 0x09;
const ALGORITHM = 'aes-128-cbc';
const PORT = Number(process.env.DEMO_PORT || 3000);

const KEY = Buffer.from(profile.key, 'utf8');
const IV = profile.ivSameAsKey ? KEY : Buffer.from(profile.iv, 'utf8');

if (KEY.length !== BLOCK) {
  throw new Error(`AES-128 needs a 16 byte key, got ${KEY.length}`);
}

// Pad length is always 1..16, so a block-aligned input still gets a full block
// of tabs. Removal just strips tabs off the right.
function padTab(buf) {
  const padLen = BLOCK - (buf.length % BLOCK) || BLOCK;
  return Buffer.concat([buf, Buffer.alloc(padLen, TAB)]);
}

function unpadTab(buf) {
  let end = buf.length;
  while (end > 0 && buf[end - 1] === TAB) end--;
  return buf.subarray(0, end);
}

function encryptTab(text) {
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, IV);
  cipher.setAutoPadding(false);
  const padded = padTab(Buffer.from(text, 'utf8'));
  return Buffer.concat([cipher.update(padded), cipher.final()]).toString('base64');
}

function decryptTab(b64) {
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, IV);
  decipher.setAutoPadding(false);
  const out = Buffer.concat([
    decipher.update(Buffer.from(b64, 'base64')),
    decipher.final(),
  ]);
  return unpadTab(out).toString('utf8');
}

function encryptPkcs7(text) {
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, IV);
  return Buffer.concat([
    cipher.update(Buffer.from(text, 'utf8')),
    cipher.final(),
  ]).toString('base64');
}

function decryptPkcs7(b64) {
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, IV);
  return Buffer.concat([
    decipher.update(Buffer.from(b64, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

// Base64 uses + and /, which do not survive every trip through a URL. Accept
// the percent encoded spelling too, and turn a space back into the + it was
// before something form decoded it.
function normalizeBase64(text) {
  let out = text;
  try {
    out = decodeURIComponent(out);
  } catch (e) {
    // Not valid percent encoding, so take it as it came in.
  }
  return out.replace(/ /g, '+');
}

function parseQuery(text) {
  const out = {};
  for (const pair of text.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    if (eq === -1) out[pair] = '';
    else out[pair.slice(0, eq)] = pair.slice(eq + 1);
  }
  return out;
}

function log(label, plaintext, ciphertext) {
  console.log('\n' + '-'.repeat(60));
  console.log(`[demo] ${label}`);
  console.log(`  plaintext : ${plaintext}`);
  console.log(`  ciphertext: ${ciphertext}`);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => resolve(data.trim()));
    req.on('error', reject);
  });
}

function sendPlain(res, code, text) {
  res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(text);
}

function sendEncrypted(res, code, payload) {
  const plaintext = JSON.stringify(payload);
  const ciphertext = encryptPkcs7(plaintext);
  log('response', plaintext, ciphertext);
  res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(ciphertext);
}

const server = http.createServer(async (req, res) => {
  // A request line can carry the full URL instead of just the path, which is
  // easy to end up with when you paste a URL into Repeater. Drop the scheme and
  // host before matching so either form works.
  const rawUrl = req.url.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '');
  const qMark = rawUrl.indexOf('?');
  const path = qMark === -1 ? rawUrl : rawUrl.slice(0, qMark);
  const rawQuery = qMark === -1 ? '' : rawUrl.slice(qMark + 1);

  try {
    if (req.method === 'GET' && path === '/') {
      return sendPlain(res, 200, [
        'CrypticBurp demo server',
        '',
        '  GET  /api?<ciphertext>   encrypted query, Tab (0x09) padding',
        '  POST /api/message        encrypted JSON body, PKCS7 padding',
        '',
        'Load template.json in the CrypticBurp tab, then see README.md',
        'for five ready made requests.',
      ].join('\n'));
    }

    if (req.method === 'GET' && path === '/health') {
      return sendPlain(res, 200, 'ok');
    }

    if (req.method === 'GET' && path === '/api') {
      if (!rawQuery) {
        return sendEncrypted(res, 400, { status: 'error', error: 'no encrypted query' });
      }
      const ciphertext = normalizeBase64(rawQuery);
      const decrypted = decryptTab(ciphertext);
      log('GET /api (encrypted query)', decrypted, ciphertext);
      return sendEncrypted(res, 200, {
        status: 'ok',
        endpoint: '/api',
        received: parseQuery(decrypted),
      });
    }

    if (req.method === 'POST' && path === '/api/message') {
      const body = await readBody(req);
      if (!body) {
        return sendEncrypted(res, 400, { status: 'error', error: 'no encrypted body' });
      }
      const decrypted = decryptPkcs7(body);
      log('POST /api/message (encrypted body)', decrypted, body);
      let received;
      try {
        received = JSON.parse(decrypted);
      } catch (e) {
        received = decrypted;
      }
      return sendEncrypted(res, 200, {
        status: 'ok',
        endpoint: '/api/message',
        received,
      });
    }

    return sendPlain(res, 404, 'not found');
  } catch (e) {
    // Almost always a wrong key or the wrong padding for the endpoint.
    console.log(`\n[demo] could not decrypt: ${e.message}`);
    return sendEncrypted(res, 400, { status: 'error', error: 'decrypt failed' });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`CrypticBurp demo server on http://127.0.0.1:${PORT}`);
  console.log('Load demo/template.json in the CrypticBurp tab to follow along.');
});
