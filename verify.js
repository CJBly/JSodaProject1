#!/usr/bin/env node
// ============================================================
//  verify.js  -  checks your work
//
//  Usage:  node verify.js 1        (or 2, 3, 4, or "all")
//
//  Every check boots the real app on a spare port and pokes it
//  over HTTP. It does not care how you organise your files -
//  only that the app still behaves.
// ============================================================

const { spawn } = require('node:child_process');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = __dirname;
const ENTRY = 'server.js';

// ---------- tiny output helpers ----------
const C = {
  reset: '\x1b[0m', red: '\x1b[31m', green: '\x1b[32m',
  yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m'
};
const pass = (m) => console.log(`  ${C.green}PASS${C.reset}  ${m}`);
const fail = (m) => console.log(`  ${C.red}FAIL${C.reset}  ${m}`);
const note = (m) => console.log(`        ${C.dim}${m}${C.reset}`);

class CheckFailed extends Error {}
function must(condition, message, detail) {
  if (condition) { pass(message); return; }
  fail(message);
  if (detail) note(detail);
  throw new CheckFailed(message);
}

// ---------- .env ----------
function readEnvFile() {
  const p = path.join(ROOT, '.env');
  if (!fs.existsSync(p)) return {};
  const out = {};
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const eq = t.indexOf('=');
    if (eq === -1) continue;
    out[t.slice(0, eq).trim()] = t.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
  }
  return out;
}
const ENV_FILE = readEnvFile();

// ---------- server control ----------
function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function startServer({ withKey = true } = {}) {
  const port = await freePort();

  const env = { ...process.env, PORT: String(port) };
  delete env.WEATHER_API_KEY;
  if (withKey) {
    for (const [k, v] of Object.entries(ENV_FILE)) env[k] = v;
  } else {
    for (const k of Object.keys(ENV_FILE)) delete env[k];
  }

  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', ENTRY], {
    cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe']
  });

  let stderr = '';
  child.stderr.on('data', (d) => { stderr += d; });
  child.stdout.on('data', () => {});

  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 10000;
  for (;;) {
    if (child.exitCode !== null) {
      throw new CheckFailed(
        `the app exited on startup\n${C.dim}${stderr.trim().split('\n').slice(0, 8).join('\n')}${C.reset}`
      );
    }
    try {
      await fetch(`${base}/api/items`, { signal: AbortSignal.timeout(800) });
      break;
    } catch {
      if (Date.now() > deadline) {
        child.kill('SIGKILL');
        throw new CheckFailed(
          `the app never started listening on PORT=${port}.\n` +
          `        Make sure ${ENTRY} still reads process.env.PORT.\n` +
          (stderr ? `${C.dim}${stderr.trim().split('\n').slice(0, 8).join('\n')}${C.reset}` : '')
        );
      }
      await new Promise((r) => setTimeout(r, 120));
    }
  }

  return { base, stop: () => child.kill('SIGKILL') };
}

async function withServer(opts, fn) {
  const s = await startServer(opts);
  try { return await fn(s.base); } finally { s.stop(); }
}

async function post(base, route, body) {
  const r = await fetch(base + route, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  let data = {};
  try { data = await r.json(); } catch {}
  return { status: r.status, data };
}

// ---------- source scanning (used only by challenge 1) ----------
const SKIP_DIRS = new Set(['.git', 'node_modules', '.devcontainer']);
const SKIP_FILES = new Set(['.env', 'verify.js', 'README.md']);

function sourceFiles(dir = ROOT, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      sourceFiles(path.join(dir, e.name), acc);
    } else {
      if (SKIP_FILES.has(e.name)) continue;
      acc.push(path.join(dir, e.name));
    }
  }
  return acc;
}

function filesContaining(needle) {
  const hits = [];
  for (const f of sourceFiles()) {
    let text;
    try { text = fs.readFileSync(f, 'utf8'); } catch { continue; }
    if (text.includes(needle)) hits.push(path.relative(ROOT, f));
  }
  return hits;
}

// ============================================================
//  CHALLENGE 1 - the API key
// ============================================================
async function challenge1() {
  const secret = ENV_FILE.WEATHER_API_KEY;
  must(Boolean(secret), '.env defines WEATHER_API_KEY',
       'Your .env file should still contain the key. Do not delete it.');

  const hits = filesContaining(secret);
  must(hits.length === 0, 'the key is not written into any source file',
       hits.length ? `still found in: ${hits.join(', ')}` : '');

  await withServer({ withKey: true }, async (base) => {
    const r = await fetch(base + '/api/weather');
    must(r.status === 200, 'the weather widget works when the key is supplied',
         `got HTTP ${r.status} instead of 200`);
    const w = await r.json();
    must(typeof w.tempF === 'number', 'the weather response still returns a temperature');
  });

  await withServer({ withKey: false }, async (base) => {
    const r = await fetch(base + '/api/weather');
    must(r.status === 401, 'the weather widget fails when the key is absent',
         `got HTTP ${r.status}. The key is probably still hardcoded somewhere, ` +
         `or the check that validates it was removed.`);
  });
}

// ============================================================
//  CHALLENGE 2 - SQL injection
// ============================================================
const PAYLOADS = [
  { username: "' OR '1'='1' --", password: 'anything' },
  { username: "admin' --", password: 'anything' },
  { username: "' OR 1=1 --", password: '' },
  { username: 'admin', password: "' OR '1'='1" }
];

async function challenge2() {
  await withServer({ withKey: true }, async (base) => {
    const good = await post(base, '/api/login', { username: 'admin', password: 'hunter2' });
    must(good.data.ok === true, 'a correct username and password still signs in',
         'Login is broken. The fix should stop injection, not stop logging in.');

    const bad = await post(base, '/api/login', { username: 'admin', password: 'nope' });
    must(bad.data.ok !== true, 'a wrong password is still rejected');

    for (const p of PAYLOADS) {
      const r = await post(base, '/api/login', p);
      must(
        r.data.ok !== true,
        `login injection rejected: ${JSON.stringify(p.username)}`,
        `Signed in as "${r.data.username}" (${r.data.role}) using ` +
        `username ${JSON.stringify(p.username)} and password ${JSON.stringify(p.password)}.\n` +
        `        Check whether the query uses placeholders, or whether it only ` +
        `filters characters.`
      );
    }

    // The inventory list is injectable too, through ?after=. This one lives in a
    // NUMBER position, so escaping quotes does nothing - only real placeholders
    // close it. A UNION payload here leaks every user's password.
    const clean = await (await fetch(base + '/api/items?after=0')).json();
    must(Array.isArray(clean) && clean.length > 0, 'the inventory list still loads');

    const leak = '0 UNION SELECT id, username, password, role FROM users';
    const res = await fetch(base + '/api/items?after=' + encodeURIComponent(leak));
    let rows = [];
    try { rows = await res.json(); } catch {}
    const secrets = ['hunter2', 'soccer99', 'letmein2024'];
    const leaked = Array.isArray(rows) &&
      rows.some((r) => r && typeof r === 'object' &&
        Object.values(r).some((v) => secrets.includes(v)));
    must(!leaked, 'the inventory list resists a UNION injection',
         `A crafted ?after= value returned user passwords in the item list.\n` +
         `        Escaping quotes will not fix this one - the value goes into a ` +
         `number position. Use a placeholder here too.`);
  });
}

// ============================================================
//  CHALLENGE 3 - split the file up
// ============================================================
async function challenge3() {
  await withServer({ withKey: true }, async (base) => {
    const r = await fetch(base + '/');
    must(r.status === 200, 'the app still serves a page at /', `got HTTP ${r.status}`);
    const html = await r.text();
    must(/<html[\s>]/i.test(html), 'the page is still HTML');

    const inlineStyle = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)]
      .filter((m) => m[1].trim().length > 0);
    must(inlineStyle.length === 0, 'no CSS left inline in the page',
         `found ${inlineStyle.length} <style> block(s) with rules in them`);

    const inlineScript = [...html.matchAll(/<script\b((?![^>]*\bsrc=)[^>])*>([\s\S]*?)<\/script>/gi)]
      .filter((m) => m[2].trim().length > 0);
    must(inlineScript.length === 0, 'no JavaScript left inline in the page',
         `found ${inlineScript.length} <script> block(s) with code in them`);

    const jsRefs = [...html.matchAll(/<script[^>]*\bsrc=["']([^"']+)["']/gi)].map((m) => m[1]);
    const cssRefs = [...html.matchAll(/<link[^>]*>/gi)]
      .filter((t) => /stylesheet/i.test(t[0]))
      .map((t) => (t[0].match(/href=["']([^"']+)["']/i) || [])[1])
      .filter(Boolean);

    must(jsRefs.length > 0, 'the page loads its JavaScript from a separate file');
    must(cssRefs.length > 0, 'the page loads its CSS from a separate file');

    for (const ref of [...jsRefs, ...cssRefs]) {
      if (/^https?:/i.test(ref)) continue;
      const url = new URL(ref, base).href;
      let res;
      try {
        res = await fetch(url);
      } catch {
        must(false, `the app serves ${ref}`, 'the request failed outright');
        continue;
      }
      const body = await res.text();
      must(res.status === 200 && body.trim().length > 0,
           `the app serves ${ref}`,
           `got HTTP ${res.status}, ${body.length} bytes. The file may exist on disk ` +
           `but the server is not sending it.`);
    }
  });
}

// ============================================================
//  CHALLENGE 4 - add delete, break nothing
// ============================================================
async function challenge4() {
  await withServer({ withKey: true }, async (base) => {
    const before = await (await fetch(base + '/api/items')).json();
    must(Array.isArray(before) && before.length > 0, 'the inventory still lists items');

    const victim = before[before.length - 1];
    const del = await fetch(`${base}/api/items/${victim.id}`, { method: 'DELETE' });
    must(del.status < 400, `DELETE /api/items/${victim.id} is accepted`,
         `got HTTP ${del.status}. The route may not exist yet.`);

    const after = await (await fetch(base + '/api/items')).json();
    must(!after.some((i) => i.id === victim.id),
         `"${victim.name}" is gone from the inventory afterwards`,
         'The route responded, but the item is still there.');
    must(after.length === before.length - 1, 'exactly one item was removed',
         `went from ${before.length} items to ${after.length}`);
  });

  console.log(`\n  ${C.dim}now re-checking the earlier challenges…${C.reset}`);
  await challenge1();
  await challenge2();
  await challenge3();
}

// ============================================================
//  runner
// ============================================================
const CHALLENGES = {
  1: ['Challenge 1 - the API key', challenge1],
  2: ['Challenge 2 - SQL injection', challenge2],
  3: ['Challenge 3 - split the file up', challenge3],
  4: ['Challenge 4 - add delete, break nothing', challenge4]
};

async function main() {
  const arg = (process.argv[2] || '').toLowerCase();
  const which = arg === 'all' ? ['1', '2', '3', '4'] : [arg];

  if (!which.every((n) => CHALLENGES[n])) {
    console.log('Usage: node verify.js 1|2|3|4|all');
    process.exit(2);
  }

  let allGood = true;
  for (const n of which) {
    const [title, fn] = CHALLENGES[n];
    console.log(`\n${C.bold}${title}${C.reset}`);
    try {
      await fn();
      console.log(`  ${C.green}${C.bold}✓ challenge ${n} complete${C.reset}`);
    } catch (err) {
      allGood = false;
      if (!(err instanceof CheckFailed)) {
        fail('the check could not run');
        note(err.message);
      }
      console.log(`  ${C.yellow}✗ challenge ${n} not done yet${C.reset}`);
      if (arg !== 'all') break;
    }
  }
  console.log('');
  process.exit(allGood ? 0 : 1);
}

main();
