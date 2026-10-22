#!/usr/bin/env node
'use strict';
/*
 * deob_server.js: web UI + API for deob_unified.js, made for Render (works locally too).
 *
 * Environment variables
 *   PORT            set by Render; the server then binds 0.0.0.0 (otherwise 127.0.0.1:8787)
 *   ACCESS_TOKEN    required when bound publicly; clients send it as the x-access-token header
 *   ALLOW_OPEN=1    start publicly without a token (not recommended)
 *   MAX_UPLOAD_MB   max input size, default 20
 *   MAX_QUEUE       max waiting + running jobs, default 3 (extra requests get HTTP 429)
 *   MAX_TIMEOUT     upper bound in seconds for the timeout/budget options, default 300
 */
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { deobfuscate } = require('./deob_unified');

const ON_RENDER = !!process.env.PORT;
const PORT = parseInt(process.env.PORT || process.argv[2] || '8787', 10);
const HOST = process.env.HOST || (ON_RENDER ? '0.0.0.0' : '127.0.0.1');
const TOKEN = process.env.ACCESS_TOKEN || '';
const MAX_BYTES = (parseInt(process.env.MAX_UPLOAD_MB || '20', 10) || 20) * 1024 * 1024;
const MAX_QUEUE = parseInt(process.env.MAX_QUEUE || '3', 10) || 3;
const MAX_TIMEOUT = parseInt(process.env.MAX_TIMEOUT || '300', 10) || 300;
// UI lives in public/ (file name matched case-insensitively: deob_ui.html / DEOB_UI.HTML)
const PUBLIC_DIR = path.join(__dirname, 'public');
const findUI = () => {
  try {
    const f = fs.readdirSync(PUBLIC_DIR).find(n => n.toLowerCase() === 'deob_ui.html');
    return f ? path.join(PUBLIC_DIR, f) : null;
  } catch { return null; }
};

if (HOST !== '127.0.0.1' && !TOKEN && process.env.ALLOW_OPEN !== '1') {
  console.error('Refusing to start on a public interface without ACCESS_TOKEN (set ALLOW_OPEN=1 to override).');
  process.exit(1);
}

let queue = Promise.resolve();          // one job at a time (stderr capture + CPU/RAM heavy)
let pending = 0;

const DEFAULTS = {
  inputs: [], output: null, detect: false, plugin: null, noDevirt: false, noHooks: false, noFold: false,
  debug: false, strings: false, keepHarness: false, keepPreamble: false, timeout: 90, budget: 30,
  maxRuns: 12, devirtRounds: 200, executor: 'Wave', inputText: null,
};

function authorized(req) {
  if (!TOKEN) return true;
  const got = Buffer.from(String(req.headers['x-access-token'] || ''));
  const want = Buffer.from(TOKEN);
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const bufs = []; let n = 0;
    req.on('data', b => {
      n += b.length;
      if (n > limit) { reject(new Error('payload too large')); req.destroy(); } else bufs.push(b);
    });
    req.on('end', () => resolve(Buffer.concat(bufs)));
    req.on('error', reject);
  });
}

async function runJob(payload, send) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deob_web_'));
  const input = path.join(dir, 'input.lua');
  const output = path.join(dir, 'result.lua');
  fs.writeFileSync(input, Buffer.from(payload.data_b64 || '', 'base64'));

  const o = payload.options || {};
  const num = (v, d, lo, hi) => { v = Number(v); return Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : d; };
  const args = Object.assign({}, DEFAULTS, {
    output, inputs: [input],
    detect: !!payload.detectOnly,
    noDevirt: !!o.noDevirt, noHooks: !!o.noHooks, noFold: !!o.noFold, strings: !!o.strings,
    timeout: num(o.timeout, 90, 5, MAX_TIMEOUT), budget: num(o.budget, 30, 5, MAX_TIMEOUT),
    maxRuns: num(o.maxRuns, 12, 1, 20), devirtRounds: num(o.devirtRounds, 200, 1, 500),
    executor: ['Wave', 'Synapse', 'Xeno', 'Solara'].includes(o.executor) ? o.executor : 'Wave',
    plugin: o.plugin === 'luraph_v15' ? 'luraph_v15' : null,
  });

  // forward the pipeline's progress output to the client
  const realErr = process.stderr.write.bind(process.stderr);
  const realLog = console.log;
  process.stderr.write = (chunk, ...rest) => {
    String(chunk).split('\n').filter(Boolean).forEach(l => send({ log: l }));
    return realErr(chunk, ...rest);
  };
  console.log = (...a) => { send({ log: a.join(' ') }); };
  try {
    const res = await deobfuscate(input, args);
    if (args.detect) send({ done: true, detectOnly: true });
    else if (res && fs.existsSync(res)) send({ done: true, result: fs.readFileSync(res, 'utf8') });
    else send({ done: true, error: 'no result produced' });
  } catch (e) {
    send({ done: true, error: String((e && e.message) || e).slice(0, 2000) });
  } finally {
    process.stderr.write = realErr;
    console.log = realLog;
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  }
}

const server = http.createServer(async (req, res) => {
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'content-type, x-access-token',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  };
  const json = (code, obj) => { res.writeHead(code, Object.assign({ 'Content-Type': 'application/json' }, cors)); res.end(JSON.stringify(obj)); };
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }

  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    const ui = findUI();
    if (!ui) { res.writeHead(500, cors); return res.end('public/deob_ui.html not found'); }
    res.writeHead(200, Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, cors));
    return res.end(fs.readFileSync(ui));
  }
  if (req.method === 'GET' && req.url === '/api/health') return json(200, { ok: true, auth: !!TOKEN, maxUploadMb: MAX_BYTES / 1048576 });

  if (req.method === 'POST' && req.url === '/api/deobfuscate') {
    if (!authorized(req)) return json(401, { error: 'invalid or missing access token' });
    if (pending >= MAX_QUEUE) return json(429, { error: 'server is busy, try again shortly' });

    let payload;
    try { payload = JSON.parse((await readBody(req, Math.ceil(MAX_BYTES * 1.4))).toString('utf8')); }
    catch (e) { return json(400, { error: 'bad request: ' + e.message }); }

    res.writeHead(200, Object.assign({
      'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no',
    }, cors));
    const send = (obj) => { try { res.write(JSON.stringify(obj) + '\n'); } catch {} };
    let aborted = false;
    res.on('close', () => { aborted = true; });
    const hb = setInterval(() => send({ hb: 1 }), 15000);   // keeps the proxy connection open
    pending++;
    send({ log: pending > 1 ? '[web] queued behind another job' : '[web] started' });
    queue = queue
      .then(() => (aborted ? null : runJob(payload, send)))
      .catch(() => {})
      .then(() => { pending--; clearInterval(hb); res.end(); });
    return;
  }
  json(404, { error: 'not found' });
});

server.requestTimeout = 0;           // long-running streamed responses
server.headersTimeout = 65000;
server.listen(PORT, HOST, () => console.log(`deob web UI listening on ${HOST}:${PORT}${TOKEN ? ' (token required)' : ''}`));
