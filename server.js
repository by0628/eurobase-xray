// Eurobase front for xray: serves the health endpoint on $PORT and proxies
// WebSocket upgrades on /ray to a loopback xray process.
// xray is downloaded from the official XTLS release at boot and its
// SHA-256 is verified against the pinned value from the release .dgst file.
const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const zlib = require('zlib');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PORT = parseInt(process.env.PORT || '3000', 10);
const XRAY_PORT = 10000;
const UUID = process.env.XRAY_UUID || '';
const XRAY_VER = 'v26.11.9';
const XRAY_URL = `https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip`;
const XRAY_SHA256 = 'b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82';
const WORK = path.join(os.tmpdir(), 'xray-bin');
const BIN = path.join(WORK, 'xray');

function download(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? require('https') : http;
    lib.get(url, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        resolve(download(res.headers.location));
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error('download status ' + res.statusCode));
        return;
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }).on('error', reject);
  });
}

function extractFile(zipBuf, name) {
  // Locate End Of Central Directory record.
  let eocd = -1;
  for (let i = zipBuf.length - 22; i >= Math.max(0, zipBuf.length - 22 - 65536); i--) {
    if (zipBuf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('EOCD not found');
  const count = zipBuf.readUInt16LE(eocd + 10);
  let off = zipBuf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (zipBuf.readUInt32LE(off) !== 0x02014b50) throw new Error('bad central dir');
    const method = zipBuf.readUInt16LE(off + 10);
    const compSize = zipBuf.readUInt32LE(off + 20);
    const nameLen = zipBuf.readUInt16LE(off + 28);
    const extraLen = zipBuf.readUInt16LE(off + 30);
    const commentLen = zipBuf.readUInt16LE(off + 32);
    const localOff = zipBuf.readUInt32LE(off + 42);
    const fname = zipBuf.toString('utf8', off + 46, off + 46 + nameLen);
    if (fname === name) {
      const lNameLen = zipBuf.readUInt16LE(localOff + 26);
      const lExtraLen = zipBuf.readUInt16LE(localOff + 28);
      const dataStart = localOff + 30 + lNameLen + lExtraLen;
      const comp = zipBuf.subarray(dataStart, dataStart + compSize);
      if (method === 0) return Buffer.from(comp);
      if (method === 8) return zlib.inflateRawSync(comp);
      throw new Error('unsupported zip method ' + method);
    }
    off += 46 + nameLen + extraLen + commentLen;
  }
  throw new Error('file not in zip: ' + name);
}

async function ensureXray() {
  if (fs.existsSync(BIN)) return;
  fs.mkdirSync(WORK, { recursive: true });
  console.log('downloading xray ' + XRAY_VER);
  const zip = await download(XRAY_URL);
  const digest = crypto.createHash('sha256').update(zip).digest('hex');
  if (digest !== XRAY_SHA256) throw new Error('sha256 mismatch: ' + digest);
  const bin = extractFile(zip, 'xray');
  fs.writeFileSync(BIN, bin, { mode: 0o755 });
  console.log('xray ready, ' + bin.length + ' bytes');
}

function startXray() {
  if (!UUID) {
    console.error('XRAY_UUID env not set; xray not started');
    return;
  }
  const cfg = {
    log: { loglevel: 'warning' },
    inbounds: [{
      listen: '127.0.0.1',
      port: XRAY_PORT,
      protocol: 'vless',
      settings: { clients: [{ id: UUID }], decryption: 'none' },
      streamSettings: { network: 'ws', wsSettings: { path: '/ray' } },
      sniffing: { enabled: true, destOverride: ['http', 'tls'] }
    }],
    outbounds: [{ protocol: 'freedom' }]
  };
  const cfgPath = path.join(WORK, 'config.json');
  fs.writeFileSync(cfgPath, JSON.stringify(cfg));
  const proc = spawn(BIN, ['run', '-c', cfgPath], { stdio: 'inherit' });
  proc.on('exit', code => {
    console.error('xray exited with ' + code + '; restarting in 2s');
    setTimeout(startXray, 2000);
  });
}

const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  } else {
    res.writeHead(404);
    res.end();
  }
});

server.on('upgrade', (req, socket, head) => {
  if (!req.url || !req.url.startsWith('/ray')) {
    socket.destroy();
    return;
  }
  const upstream = net.connect(XRAY_PORT, '127.0.0.1', () => {
    const lines = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
    }
    upstream.write(lines.join('\r\n') + '\r\n\r\n');
    if (head && head.length) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => upstream.destroy());
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('front listening on ' + PORT);
});

ensureXray().then(startXray).catch(err => {
  console.error('failed to prepare xray:', err.message);
});
