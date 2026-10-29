'use strict';

// whyismycomputeronfuckingfire.com.au backend
// Made by Sami9889 - https://sami-s.dev
//
// One file, no npm packages, Node 18+.  Run:  node server.js
//
// What it does
//   - Serves index.html (and summit.yaml if you have one)
//   - Guestbook: every submission is a GitHub issue labelled "thermal-incident".
//     Close an issue on GitHub to take it off the wall.
//   - Fund bar: reads the money raised from GitHub Sponsors, converts USD -> AUD
//   - Visitor counter: stored in the body of one issue labelled "counter"
//
// Environment
//   PAT              your GitHub Personal Access Token (store it as a secret named PAT).
//                    Use a CLASSIC token with the scopes: public_repo (or repo, if the repo
//                    is private) and read:user. That one token does the guestbook, the
//                    counter and the Sponsors fund bar.
//                    Read in this order: PAT, GITHUB_PAT, GITHUB_TOKEN. PAT wins on purpose:
//                    Codespaces and Actions pre-set GITHUB_TOKEN to a limited token.
//   SPONSORS_TOKEN   optional separate token for Sponsors data. Falls back to PAT.
//   GITHUB_API_URL   default https://api.github.com (only change this for testing)
//   GITHUB_REPO      default Sami9889/whyismycomputeronfuckingfire
//   SPONSOR_LOGIN    GitHub account that receives sponsorships, default = repo owner
//   PORT             default 3000
//   ALLOWED_ORIGIN   default *   = only the page this server serves may post. If the page
//                    lives elsewhere, set it to its URL, e.g. https://whyismycomputeronfuckingfire.com.au
//   SECRET           any long random string; signs the anti-bot challenges (random per start if unset)
//   POW_BITS         anti-bot difficulty, default 18 (each +1 doubles the work)
//   TRUST_PROXY      set to 1 when behind a proxy/host that sets X-Forwarded-For
//   USD_TO_AUD       fallback exchange rate if the live rate can't be fetched (default 1.5)
//
// Optional summit.yaml next to this file:
//   fund_goal_aud: 500
//   sponsor_url: https://github.com/sponsors/Sami9889
//   raised_aud: 0          # only used if GitHub Sponsors can't be read

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------- config ----------

const PORT = Number(process.env.PORT) || 3000;
const REPO = process.env.GITHUB_REPO || 'Sami9889/whyismycomputeronfuckingfire';
const SPONSOR_LOGIN = process.env.SPONSOR_LOGIN || REPO.split('/')[0];
const TOKEN_NAME = ['PAT', 'GITHUB_PAT', 'GITHUB_TOKEN'].filter(function (n) { return (process.env[n] || '').trim(); })[0] || '';
const TOKEN = TOKEN_NAME ? process.env[TOKEN_NAME].trim() : '';
const SPONSORS_TOKEN = (process.env.SPONSORS_TOKEN || '').trim() || TOKEN;
const GITHUB_URL = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/+$/, '');
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
// On by default on hosts that put a proxy in front of the app.
const TRUST_PROXY = !!(process.env.TRUST_PROXY || process.env.CODESPACES || process.env.RENDER ||
                       process.env.FLY_APP_NAME || process.env.RAILWAY_ENVIRONMENT);
const FALLBACK_FX = Number(process.env.USD_TO_AUD) || 1.5;

const API = GITHUB_URL + '/repos/' + REPO;
const INCIDENT_LABEL = 'thermal-incident';
const COUNTER_LABEL = 'counter';
const TEMPS = ['95C', '120C', '500C', '9000C'];

const HTTP_TIMEOUT = 8000;
const MAX_BODY_BYTES = 4096;
const PER_IP_LIMIT = 1;               // guestbook posts per IP...
const PER_IP_WINDOW = 60 * 60e3;      // ...per hour
const GLOBAL_LIMIT = 30;              // guestbook posts per hour, whole site
const GLOBAL_WINDOW = 60 * 60e3;
const HIT_WINDOW = 60 * 60e3;         // a visitor counts once per hour
const DUPLICATE_WINDOW = 24 * 60 * 60e3;

// Anti-spam: posting needs a signed, single-use challenge plus a small proof-of-work.
const ALLOWED_LIST = ALLOWED_ORIGIN.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
// Stable across restarts (the free host sleeps a lot): set SECRET, or it is derived from the PAT.
const SECRET = process.env.SECRET ||
  (TOKEN ? crypto.createHash('sha256').update('fire-guestbook:' + TOKEN).digest('hex') : crypto.randomBytes(32).toString('hex'));
const MARKER = /<!--\s*t:([a-f0-9]{12})\s+n:([a-f0-9]{24})\s*-->/;
const POW_BITS = Number(process.env.POW_BITS) || 18;   // ~260k hashes: a few seconds in a browser
const CHALLENGE_MIN_AGE = 3000;                        // humans take longer than 3s
const CHALLENGE_MAX_AGE = 10 * 60e3;

function log() {
  console.log.apply(console, [new Date().toISOString()].concat([].slice.call(arguments)));
}

// ---------- helpers ----------

// Cache a value for ttl ms. Shares one in-flight request, and serves the last good
// value if a refresh fails.
function cache(ttl, loader) {
  let value, at = 0, pending = null;
  return {
    get: function () {
      if (value !== undefined && Date.now() - at < ttl) return Promise.resolve(value);
      if (pending) return pending;
      pending = loader().then(function (v) {
        value = v; at = Date.now(); return v;
      }).catch(function (e) {
        if (value !== undefined) { log('Refresh failed, serving stale:', e.message); return value; }
        throw e;
      }).finally(function () { pending = null; });
      return pending;
    },
    bust: function () { at = 0; }
  };
}

function ghHeaders(token, extra) {
  const h = {
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'why-is-my-computer-on-fire',
    'X-GitHub-Api-Version': '2022-11-28'
  };
  if (token) h['Authorization'] = 'Bearer ' + token;
  return Object.assign(h, extra || {});
}

async function failFrom(res) {
  const text = await res.text();
  const err = new Error('GitHub ' + res.status + ': ' + text.slice(0, 200));
  err.status = res.status;
  return err;
}

// GETs use ETags: an unchanged answer (304) does not count against the rate limit.
const etags = new Map();

async function gh(method, urlPath, body) {
  const headers = ghHeaders(TOKEN, body ? { 'Content-Type': 'application/json' } : null);
  const prev = method === 'GET' ? etags.get(urlPath) : null;
  if (prev) headers['If-None-Match'] = prev.etag;

  const res = await fetch(API + urlPath, {
    method: method,
    headers: headers,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(HTTP_TIMEOUT)
  });
  if (res.status === 304 && prev) return prev.data;
  if (!res.ok) throw await failFrom(res);
  const data = await res.json();
  const tag = res.headers.get('etag');
  if (method === 'GET' && tag) etags.set(urlPath, { etag: tag, data: data });
  return data;
}

async function graphql(query, variables) {
  const res = await fetch(GITHUB_URL + '/graphql', {
    method: 'POST',
    headers: ghHeaders(SPONSORS_TOKEN, { 'Content-Type': 'application/json' }),
    body: JSON.stringify({ query: query, variables: variables }),
    signal: AbortSignal.timeout(HTTP_TIMEOUT)
  });
  if (!res.ok) throw await failFrom(res);
  const json = await res.json();
  if (json.errors && json.errors.length) throw new Error('GraphQL: ' + json.errors[0].message);
  return json.data;
}

function readConfigFile() {
  const out = {};
  try {
    fs.readFileSync(path.join(__dirname, 'summit.yaml'), 'utf8').split(/\r?\n/).forEach(function (line) {
      const m = line.match(/^\s*([A-Za-z0-9_]+)\s*:\s*(.*?)\s*$/);
      if (m && m[1].charAt(0) !== '#') out[m[1]] = m[2].replace(/^["']|["']$/g, '').replace(/\s+#.*$/, '');
    });
  } catch (e) { /* file is optional */ }
  return out;
}

// ---------- abuse protection ----------

const limiters = [];
// Sliding-window limiter: returns true when `key` has gone over `max` hits in `windowMs`.
function makeLimiter(max, windowMs) {
  const store = new Map();
  limiters.push({ store: store, windowMs: windowMs });
  return function (key) {
    const now = Date.now();
    const hits = (store.get(key) || []).filter(function (t) { return now - t < windowMs; });
    hits.push(now);
    store.set(key, hits);
    return hits.length > max;
  };
}

const apiLimit = makeLimiter(60, 60e3);       // any API call: 60 / minute / IP
const challengeLimit = makeLimiter(10, 60e3); // challenges: 10 / minute / IP

const usedChallenges = new Map(); // nonce -> expiry

function ipTag(ip) {
  return crypto.createHash('sha256').update(String(ip)).digest('hex').slice(0, 16);
}

function sign(payload) {
  return crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
}

function issueChallenge(ip) {
  const payload = Buffer.from(JSON.stringify({
    n: crypto.randomBytes(12).toString('hex'),
    t: Date.now(),
    ip: ipTag(ip),
    b: POW_BITS
  })).toString('base64url');
  return { token: payload + '.' + sign(payload), bits: POW_BITS };
}

function hasZeroBits(buf, bits) {
  let i = 0;
  while (bits >= 8) { if (buf[i] !== 0) return false; i++; bits -= 8; }
  return bits === 0 || (buf[i] >> (8 - bits)) === 0;
}

// Returns { nonce } if the challenge is valid (and burns it), otherwise an error message string.
function verifyChallenge(ip, token, solution) {
  const BAD = 'Bad anti-bot token. Reload the page and try again.';
  if (typeof token !== 'string' || token.length > 400) return BAD;
  const parts = token.split('.');
  if (parts.length !== 2) return BAD;

  const given = Buffer.from(parts[1]);
  const wanted = Buffer.from(sign(parts[0]));
  if (given.length !== wanted.length || !crypto.timingSafeEqual(given, wanted)) return BAD;

  let p;
  try { p = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); } catch (e) { return BAD; }

  if (p.ip !== ipTag(ip)) return 'That token was issued to a different address.';
  const age = Date.now() - p.t;
  if (age < CHALLENGE_MIN_AGE) return 'Too fast. Humans take a few seconds.';
  if (age > CHALLENGE_MAX_AGE) return 'Anti-bot token expired. Reload and try again.';
  if (usedChallenges.has(p.n)) return 'That token was already used.';

  const sol = String(solution == null ? '' : solution);
  if (!/^[0-9a-z]{1,16}$/.test(sol)) return BAD;
  const hash = crypto.createHash('sha256').update(token + ':' + sol).digest();
  if (!hasZeroBits(hash, p.b)) return 'Anti-bot check failed.';

  usedChallenges.set(p.n, Date.now() + CHALLENGE_MAX_AGE);
  return { nonce: p.n };
}

// Hourly rotating tag: lets us rate-limit by IP using only the issues, without keeping an
// address anywhere. It cannot be turned back into the IP and changes every hour.
function rateTag(ip, bucket) {
  return crypto.createHmac('sha256', SECRET).update('rl:' + ip + ':' + bucket).digest('hex').slice(0, 12);
}

// Browsers always send Origin on a POST. Only our own page (or ALLOWED_ORIGIN) may post.
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  if (ALLOWED_ORIGIN !== '*') return ALLOWED_LIST.indexOf(origin) !== -1;
  try {
    const host = new URL(origin).host;
    if (host === req.headers.host) return true;
    // Behind a proxy (Codespaces, Render, Fly...) the public host arrives in X-Forwarded-Host.
    if (TRUST_PROXY && req.headers['x-forwarded-host']) {
      return String(req.headers['x-forwarded-host']).split(',')[0].trim() === host;
    }
    return false;
  } catch (e) { return false; }
}

// ---------- guestbook (GitHub issues) ----------

function clean(s, max) {
  return String(s == null ? '' : s)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[<>`*_\[\]#|~\\]/g, '')
    .replace(/@/g, 'at ')
    .replace(/https?:\/\//gi, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

// Open issues only: close an issue on GitHub to hide an entry.
const incidents = cache(30e3, async function () {
  const issues = await gh('GET', '/issues?labels=' + INCIDENT_LABEL + '&state=open&per_page=30');
  return issues
    .filter(function (i) { return !i.pull_request; })
    .map(function (i) {
      const b = i.body || '';
      const n = b.match(/\*\*Handle:\*\* ([^\n]+)/);
      const t = b.match(/\*\*Temperature:\*\* ([^\n]+)/);
      const m = b.match(/\*\*Emergency Method:\*\* ([^\n]+)/);
      return {
        name: n ? n[1].trim() : '(unknown)',
        temp: t ? t[1].trim() : '?',
        method: m ? m[1].trim() : '',
        date: i.created_at
      };
    });
});

const ipPosts = new Map();       // ip -> [timestamps]
let globalPosts = [];
const recentEntries = new Map(); // fingerprint -> timestamp

// Returns 0 if the post is allowed, otherwise seconds to wait.
function postWait(ip) {
  const now = Date.now();
  globalPosts = globalPosts.filter(function (t) { return now - t < GLOBAL_WINDOW; });
  const mine = (ipPosts.get(ip) || []).filter(function (t) { return now - t < PER_IP_WINDOW; });
  ipPosts.set(ip, mine);
  if (mine.length >= PER_IP_LIMIT) return Math.ceil((PER_IP_WINDOW - (now - mine[0])) / 1000);
  if (globalPosts.length >= GLOBAL_LIMIT) return Math.ceil((GLOBAL_WINDOW - (now - globalPosts[0])) / 1000);
  return 0;
}

function recordPost(ip, fingerprint) {
  const now = Date.now();
  ipPosts.get(ip).push(now);
  globalPosts.push(now);
  recentEntries.set(fingerprint, now);
}

async function createIncident(ip, input) {
  const name = clean(input.name, 40);
  const method = clean(input.method, 120);
  const temp = String(input.temp || '');
  if (!name || !method) return { status: 400, body: { error: 'Please fill in your name and what you tried.' } };
  if (TEMPS.indexOf(temp) === -1) return { status: 400, body: { error: 'Pick a temperature from the list.' } };
  if (!/[a-z0-9]/i.test(name) || !/[a-z0-9]/i.test(method)) {
    return { status: 400, body: { error: 'Use some actual words, mate.' } };
  }
  if (!TOKEN) return { status: 503, body: { error: 'Guestbook is offline (server has no GitHub token).' } };

  const v = verifyChallenge(ip, input.challenge, input.solution);
  if (typeof v === 'string') return { status: 403, body: { error: v } };

  const fingerprint = (name + '|' + temp + '|' + method).toLowerCase();
  const seen = recentEntries.get(fingerprint);
  if (seen && Date.now() - seen < DUPLICATE_WINDOW) {
    return { status: 409, body: { error: 'That one is already on the wall.' } };
  }

  const wait = postWait(ip);
  if (wait) {
    return { status: 429, retryAfter: wait, body: { error: 'One entry per person, mate. Try again in ' + Math.ceil(wait / 60) + ' min.' } };
  }

  // The same limits again, read back from the issues, so they still hold after a restart.
  const recent = await gh('GET', '/issues?labels=' + INCIDENT_LABEL + '&state=all&per_page=30');
  const now = Date.now();
  const bucket = Math.floor(now / 3600e3);
  const myTags = [rateTag(ip, bucket), rateTag(ip, bucket - 1)];
  let inLastHour = 0;
  for (let k = 0; k < recent.length; k++) {
    const i = recent[k];
    if (i.pull_request) continue;
    const age = now - Date.parse(i.created_at);
    const mark = (i.body || '').match(MARKER);
    if (mark && mark[2] === v.nonce) return { status: 403, body: { error: 'That token was already used.' } };
    if (age < PER_IP_WINDOW) {
      inLastHour++;
      if (mark && myTags.indexOf(mark[1]) !== -1) {
        return { status: 429, retryAfter: 3600, body: { error: 'One entry per person, mate. Try again in an hour.' } };
      }
    }
    if (age < DUPLICATE_WINDOW) {
      const b = i.body || '';
      const n = b.match(/\*\*Handle:\*\* ([^\n]+)/), t = b.match(/\*\*Temperature:\*\* ([^\n]+)/), m = b.match(/\*\*Emergency Method:\*\* ([^\n]+)/);
      if (n && t && m && (n[1].trim() + '|' + t[1].trim() + '|' + m[1].trim()).toLowerCase() === fingerprint) {
        return { status: 409, body: { error: 'That one is already on the wall.' } };
      }
    }
  }
  if (inLastHour >= GLOBAL_LIMIT) {
    return { status: 429, retryAfter: 3600, body: { error: 'The wall is full for now. Try again later.' } };
  }

  await gh('POST', '/issues', {
    title: 'THERMAL INCIDENT: ' + name + ' (' + temp + ')',
    body: '**Handle:** ' + name + '\n\n**Temperature:** ' + temp + '\n\n**Emergency Method:** ' + method +
          '\n\nSubmitted via whyismycomputeronfuckingfire.com.au\n\n<!-- t:' + myTags[0] + ' n:' + v.nonce + ' -->',
    labels: [INCIDENT_LABEL]
  });
  recordPost(ip, fingerprint);
  incidents.bust();
  return { status: 201, body: { ok: true } };
}

// ---------- fund bar (GitHub Sponsors) ----------

const SPONSORS_QUERY =
  'query($login:String!,$after:String){ user(login:$login){' +
  ' monthlyEstimatedSponsorsIncomeInCents' +
  ' lifetimeReceivedSponsorshipValues(first:100, after:$after){' +
  '  totalCount pageInfo{ hasNextPage endCursor } nodes{ amountInCents } } } }';

// Everything ever received through GitHub Sponsors, in USD cents.
async function fetchSponsorsUsd() {
  if (!SPONSORS_TOKEN) throw new Error('no token for Sponsors');
  let totalCents = 0, supporters = 0, monthlyCents = 0, after = null;
  for (let page = 0; page < 10; page++) {
    const data = await graphql(SPONSORS_QUERY, { login: SPONSOR_LOGIN, after: after });
    if (!data.user) throw new Error('GitHub user not found: ' + SPONSOR_LOGIN);
    const conn = data.user.lifetimeReceivedSponsorshipValues;
    monthlyCents = data.user.monthlyEstimatedSponsorsIncomeInCents || 0;
    supporters = conn.totalCount || 0;
    conn.nodes.forEach(function (n) { totalCents += n.amountInCents || 0; });
    if (!conn.pageInfo.hasNextPage) break;
    after = conn.pageInfo.endCursor;
  }
  return { usd: totalCents / 100, monthlyUsd: monthlyCents / 100, supporters: supporters };
}

const sponsors = cache(5 * 60e3, fetchSponsorsUsd);

const usdToAud = cache(12 * 60 * 60e3, async function () {
  const res = await fetch('https://api.frankfurter.app/latest?from=USD&to=AUD', { signal: AbortSignal.timeout(HTTP_TIMEOUT) });
  if (!res.ok) throw new Error('FX ' + res.status);
  const j = await res.json();
  if (!j.rates || !j.rates.AUD) throw new Error('FX bad response');
  return j.rates.AUD;
});

const round2 = function (n) { return Math.round(n * 100) / 100; };

async function fundStatus() {
  const cfg = readConfigFile();
  const goal = Number(cfg.fund_goal_aud) || 500;
  const out = {
    goal_aud: goal,
    raised_aud: 0,
    percent: 0,
    supporters: 0,
    monthly_aud: 0,
    source: 'none',
    sponsor_url: cfg.sponsor_url || 'https://github.com/sponsors/' + SPONSOR_LOGIN
  };

  try {
    const s = await sponsors.get();
    let fx = FALLBACK_FX;
    try { fx = await usdToAud.get(); } catch (e) { log('FX fallback:', e.message); }
    out.raised_aud = round2(s.usd * fx);
    out.monthly_aud = round2(s.monthlyUsd * fx);
    out.supporters = s.supporters;
    out.source = 'github-sponsors';
  } catch (e) {
    log('Sponsors unavailable:', e.message);
    if (cfg.raised_aud) { out.raised_aud = Number(cfg.raised_aud) || 0; out.source = 'summit.yaml'; }
  }
  out.percent = Math.max(0, Math.min(100, Math.round(out.raised_aud / goal * 100)));
  return out;
}

// ---------- visitor counter (stored in an issue body) ----------

let count = 0;
let counterIssue = null;
let dirty = false;
const hitSeen = new Map(); // ip -> timestamp

let githubState = TOKEN ? 'unchecked' : 'no token';

// Run once at startup so a bad PAT shows up in the log straight away, with the reason.
async function checkToken() {
  if (!TOKEN) return;
  try {
    const res = await fetch(GITHUB_URL + '/user', { headers: ghHeaders(TOKEN), signal: AbortSignal.timeout(HTTP_TIMEOUT) });
    if (res.status === 401) {
      githubState = 'token rejected';
      log('GitHub REJECTED the token from ' + TOKEN_NAME + ' (401). It is wrong, expired or revoked. Make a new one and update the secret.');
      return;
    }
    if (!res.ok) throw new Error('GitHub ' + res.status);
    const who = await res.json();
    const scopes = res.headers.get('x-oauth-scopes');
    if (scopes === null) {
      log('GitHub token OK (' + TOKEN_NAME + ', fine-grained) as ' + who.login + '. Needs Issues: read and write on this repo. Sponsors data needs a classic token.');
    } else {
      const list = scopes.split(',').map(function (s) { return s.trim(); });
      log('GitHub token OK (' + TOKEN_NAME + ', classic) as ' + who.login + ' | scopes: ' + (scopes || 'none'));
      if (list.indexOf('repo') === -1 && list.indexOf('public_repo') === -1) log('WARNING: the token has no public_repo scope, so the guestbook cannot post.');
      if (list.indexOf('read:user') === -1 && list.indexOf('user') === -1) log('WARNING: the token has no read:user scope, so the fund bar cannot read Sponsors.');
    }
    const repo = await fetch(API, { headers: ghHeaders(TOKEN), signal: AbortSignal.timeout(HTTP_TIMEOUT) });
    if (repo.status === 404) {
      githubState = 'repo not found';
      log('WARNING: GitHub says repo ' + REPO + ' does not exist, or the token cannot see it. Check GITHUB_REPO and the token\'s access.');
      return;
    }
    githubState = 'ok';
  } catch (e) {
    githubState = 'unreachable';
    log('Could not check the GitHub token:', e.message);
  }
}

async function initCounter() {
  if (!TOKEN) { log('No PAT set: counter is in-memory only and the guestbook is read-only.'); return; }
  const found = await gh('GET', '/issues?labels=' + COUNTER_LABEL + '&state=open&per_page=1');
  if (found.length) {
    counterIssue = found[0].number;
    count = parseInt(found[0].body, 10) || 0;
  } else {
    const made = await gh('POST', '/issues', { title: 'Visitor counter (do not edit)', body: '0', labels: [COUNTER_LABEL] });
    counterIssue = made.number;
  }
  log('Counter at', count, '(issue #' + counterIssue + ')');
}

async function saveCounter() {
  if (!TOKEN || !counterIssue || !dirty) return;
  dirty = false;
  try {
    await gh('PATCH', '/issues/' + counterIssue, { body: String(count) });
  } catch (e) {
    dirty = true;
    log('Could not save counter:', e.message);
  }
}

function registerHit(ip) {
  const now = Date.now();
  const last = hitSeen.get(ip);
  if (!last || now - last > HIT_WINDOW) {
    hitSeen.set(ip, now);
    count++;
    dirty = true;
  }
  return count;
}

// ---------- housekeeping ----------

setInterval(saveCounter, 60e3).unref();

setInterval(function () {
  const now = Date.now();
  ipPosts.forEach(function (v, k) {
    const keep = v.filter(function (t) { return now - t < PER_IP_WINDOW; });
    if (keep.length) ipPosts.set(k, keep); else ipPosts.delete(k);
  });
  hitSeen.forEach(function (t, k) { if (now - t > HIT_WINDOW) hitSeen.delete(k); });
  usedChallenges.forEach(function (exp, k) { if (exp < now) usedChallenges.delete(k); });
  limiters.forEach(function (l) {
    l.store.forEach(function (hits, k) {
      if (!hits.length || now - hits[hits.length - 1] > l.windowMs) l.store.delete(k);
    });
  });
  recentEntries.forEach(function (t, k) { if (now - t > DUPLICATE_WINDOW) recentEntries.delete(k); });
}, 5 * 60e3).unref();

// ---------- http ----------

const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/summit.yaml': ['summit.yaml', 'text/plain; charset=utf-8'],
  '/security.txt': ['security.txt', 'text/plain; charset=utf-8'],
  '/.well-known/security.txt': ['security.txt', 'text/plain; charset=utf-8']
};

function baseHeaders(req, res) {
  if (ALLOWED_ORIGIN !== '*') {
    const origin = req.headers.origin;
    if (origin && ALLOWED_LIST.indexOf(origin) !== -1) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    }
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
}

function send(res, status, obj, extra) {
  const headers = Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, extra || {});
  res.writeHead(status, headers);
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise(function (resolve, reject) {
    let size = 0;
    const chunks = [];
    req.on('data', function (c) {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('Too big'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', function () { resolve(Buffer.concat(chunks).toString('utf8')); });
    req.on('error', reject);
  });
}

const server = http.createServer(async function (req, res) {
  try {
    baseHeaders(req, res);
    const url = new URL(req.url, 'http://localhost');

    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

    const ip = (TRUST_PROXY && req.headers['x-forwarded-for'])
      ? String(req.headers['x-forwarded-for']).split(',')[0].trim()
      : req.socket.remoteAddress;

    if (url.pathname.indexOf('/api/') === 0 && apiLimit(ip)) {
      return send(res, 429, { error: 'Too many requests. Calm down.' }, { 'Retry-After': '60' });
    }

    if (url.pathname === '/api/challenge' && req.method === 'GET') {
      if (challengeLimit(ip)) return send(res, 429, { error: 'Too many requests. Calm down.' }, { 'Retry-After': '60' });
      const c = issueChallenge(ip);
      return send(res, 200, { token: c.token, bits: c.bits, min_wait_ms: CHALLENGE_MIN_AGE });
    }

    if (url.pathname === '/api/health' && req.method === 'GET') {
      return send(res, 200, { ok: true, counter: count, guestbook: !!TOKEN, github: githubState });
    }

    if (url.pathname === '/api/incidents' && req.method === 'GET') {
      return send(res, 200, await incidents.get(), { 'Cache-Control': 'public, max-age=15' });
    }

    if (url.pathname === '/api/incidents' && req.method === 'POST') {
      if (!originAllowed(req)) return send(res, 403, { error: 'Not allowed from here.' });
      if ((req.headers['content-type'] || '').indexOf('application/json') !== 0) {
        return send(res, 415, { error: 'Bad request.' });
      }
      let input;
      try { input = JSON.parse(await readBody(req)); } catch (e) {
        return send(res, e.status || 400, { error: 'Bad request.' });
      }
      if (!input || typeof input !== 'object') return send(res, 400, { error: 'Bad request.' });
      const out = await createIncident(ip, input);
      return send(res, out.status, out.body, out.retryAfter ? { 'Retry-After': String(out.retryAfter) } : null);
    }

    if (url.pathname === '/api/fund' && req.method === 'GET') {
      return send(res, 200, await fundStatus(), { 'Cache-Control': 'public, max-age=60' });
    }

    if (url.pathname === '/api/hit' && req.method === 'GET') {
      // The page sends ?peek=1 when the visitor already has the cookie, so it only reads the number.
      return send(res, 200, { value: url.searchParams.get('peek') ? count : registerHit(ip) });
    }

    if (req.method === 'GET' && STATIC[url.pathname]) {
      const entry = STATIC[url.pathname];
      return fs.readFile(path.join(__dirname, entry[0]), function (err, data) {
        if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
        res.writeHead(200, { 'Content-Type': entry[1], 'Cache-Control': 'no-cache' });
        res.end(data);
      });
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  } catch (e) {
    log('Error on', req.method, req.url, '-', e.message);
    if (!res.headersSent) send(res, 502, { error: 'The server had a bit of a meltdown. Try again later.' });
  }
});

server.requestTimeout = 15e3;
server.headersTimeout = 10e3;

checkToken().then(initCounter).catch(function (e) { log('Counter init failed:', e.message); });

server.listen(PORT, function () {
  log('Listening on port ' + PORT + ' | repo ' + REPO + ' | sponsors for ' + SPONSOR_LOGIN);
  log(TOKEN ? 'Using the token from ' + TOKEN_NAME : 'WARNING: no PAT set. Add a secret/env var named PAT with your GitHub personal access token.');
  if (!TRUST_PROXY) log('Note: TRUST_PROXY is off. Behind a proxy, every visitor will look like one IP; set TRUST_PROXY=1.');
});

let stopping = false;
function shutdown() {
  if (stopping) return;
  stopping = true;
  log('Shutting down...');
  server.close();
  saveCounter().finally(function () { process.exit(0); });
  setTimeout(function () { process.exit(0); }, 5000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('unhandledRejection', function (e) { log('Unhandled rejection:', e && e.message); });
