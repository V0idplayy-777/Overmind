/*!
 * overAuth 1.0 — "Sign in with Overmind" for any website.
 * https://v0idplayy-777.github.io/Overmind/overauth.html
 *
 * Drop-in:
 *   <script src="https://v0idplayy-777.github.io/Overmind/overauth.js"
 *           data-key="oav1_..." data-container="#login" data-theme="dark"></script>
 *
 * Manual:
 *   OvermindAuth.init({ key: 'oav1_...' })
 *   const res = await OvermindAuth.signIn(username, password)
 *   if (res.ok) { ... res.user.username ... }
 *
 * Zero dependencies. Works in the browser and in Node 18+.
 */
(function (global, factory) {
  var api = factory(global);
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    global.OvermindAuth = api;
    global.overAuth = api; // friendly alias
  }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (global) {
  'use strict';

  var VERSION = '1.0.0';
  var KEY_PREFIX = 'oav1_';

  // Public Supabase project for Overmind (same anon key the Overmind web app ships with).
  var SUPABASE_URL = 'https://llmsljlcjugdpkhfklph.supabase.co';
  var SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxsbXNsamxjanVnZHBraGZrbHBoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI2MjA4ODgsImV4cCI6MjA5ODE5Njg4OH0.weH2fYFj4qxEeyIUdQtn1hz7H2iyHeab6OPdJONXzmo';

  // Signing secret for the self-describing part of a key. It is *public* (it has to be —
  // this is a static site with no server), so the signature only proves "issued by the
  // Overmind console / not tampered with". Real enforcement (revocation, origin checks,
  // sessions) happens in the Supabase functions installed by supabase/overauth.sql.
  var KEY_SIGNING_SECRET = SUPABASE_ANON_KEY;

  var REASONS = {
    invalid_key: 'That overAuth key is malformed or was not issued by Overmind.',
    invalid_credentials: 'Incorrect username or password.',
    missing_credentials: 'A username and password are required.',
    key_revoked: 'That overAuth key has been revoked by its owner.',
    key_expired: 'That overAuth key has expired.',
    origin_not_allowed: 'This website is not on the key\'s allowed-origin list.',
    account_banned: 'That Overmind account has been banned.',
    invalid_session: 'That session is no longer valid.',
    backend_error: 'The overAuth service returned an error.',
    network_error: 'Could not reach the overAuth service.',
    not_initialized: 'Call OvermindAuth.init({ key }) first.'
  };

  /* =====================================================================
   * 1. Crypto — small, dependency-free SHA-256 + HMAC-SHA256.
   *    Implemented in JS (not crypto.subtle) so overAuth also works on
   *    plain http:// pages and inside Node without a secure context.
   * ===================================================================== */

  var SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

  /** SHA-256 over a Uint8Array, returned as bytes. */
  function sha256Raw(bytes) {
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var len = bytes.length;
    var total = (((len + 8) >> 6) + 1) * 64;
    var buf = new Uint8Array(total);
    buf.set(bytes);
    buf[len] = 0x80;
    var view = new DataView(buf.buffer);
    // 64-bit big-endian bit length (JS numbers are fine up to 2^53 bytes)
    view.setUint32(total - 8, Math.floor(len / 536870912), false);
    view.setUint32(total - 4, (len << 3) >>> 0, false);

    var w = new Uint32Array(64);
    for (var off = 0; off < total; off += 64) {
      for (var i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4, false);
      for (i = 16; i < 64; i++) {
        var x = w[i - 15], y = w[i - 2];
        var s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
        var s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    var out = new Uint8Array(32);
    var ov = new DataView(out.buffer);
    for (i = 0; i < 8; i++) ov.setUint32(i * 4, h[i], false);
    return out;
  }

  function toHex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return s;
  }

  function utf8Bytes(str) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
    return new Uint8Array(Buffer.from(String(str), 'utf8')); // Node fallback
  }

  function bytesToUtf8(bytes) {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder().decode(bytes);
    return Buffer.from(bytes).toString('utf8');
  }

  /** SHA-256 hex digest of a string — identical to Overmind's password hashing. */
  function sha256Hex(str) { return toHex(sha256Raw(utf8Bytes(String(str)))); }

  /** HMAC-SHA256 (bytes) */
  function hmacSha256Raw(keyBytes, msgBytes) {
    var block = 64;
    if (keyBytes.length > block) keyBytes = sha256Raw(keyBytes);
    var ipad = new Uint8Array(block), opad = new Uint8Array(block);
    for (var i = 0; i < block; i++) {
      var k = i < keyBytes.length ? keyBytes[i] : 0;
      ipad[i] = k ^ 0x36;
      opad[i] = k ^ 0x5c;
    }
    var inner = new Uint8Array(block + msgBytes.length);
    inner.set(ipad); inner.set(msgBytes, block);
    var innerHash = sha256Raw(inner);
    var outer = new Uint8Array(block + innerHash.length);
    outer.set(opad); outer.set(innerHash, block);
    return sha256Raw(outer);
  }

  function hmacSha256Hex(secret, message) {
    return toHex(hmacSha256Raw(utf8Bytes(secret), utf8Bytes(message)));
  }

  /* ---------------- base64url ---------------- */

  var B64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  function b64urlFromBytes(bytes) {
    var out = '';
    var i = 0;
    for (; i + 2 < bytes.length; i += 3) {
      var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += B64URL_CHARS[(n >> 18) & 63] + B64URL_CHARS[(n >> 12) & 63] + B64URL_CHARS[(n >> 6) & 63] + B64URL_CHARS[n & 63];
    }
    var rem = bytes.length - i;
    if (rem === 1) {
      var n1 = bytes[i] << 16;
      out += B64URL_CHARS[(n1 >> 18) & 63] + B64URL_CHARS[(n1 >> 12) & 63];
    } else if (rem === 2) {
      var n2 = (bytes[i] << 16) | (bytes[i + 1] << 8);
      out += B64URL_CHARS[(n2 >> 18) & 63] + B64URL_CHARS[(n2 >> 12) & 63] + B64URL_CHARS[(n2 >> 6) & 63];
    }
    return out;
  }

  function bytesFromB64url(str) {
    str = String(str).replace(/=+$/, '');
    var bytes = [];
    var buffer = 0, bits = 0;
    for (var i = 0; i < str.length; i++) {
      var v = B64URL_CHARS.indexOf(str.charAt(i));
      if (v < 0) throw new Error('invalid base64url character: ' + str.charAt(i));
      buffer = (buffer << 6) | v;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        bytes.push((buffer >> bits) & 0xff);
      }
    }
    return new Uint8Array(bytes);
  }

  function b64urlEncode(str) { return b64urlFromBytes(utf8Bytes(str)); }
  function b64urlDecode(str) { return bytesToUtf8(bytesFromB64url(str)); }

  function randomHex(byteLength) {
    var bytes = new Uint8Array(byteLength || 16);
    var c = global.crypto || global.msCrypto;
    if (c && c.getRandomValues) c.getRandomValues(bytes);
    else for (var i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
    return toHex(bytes);
  }

  function safeEqual(a, b) {
    a = String(a); b = String(b);
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  /* =====================================================================
   * 2. Keys
   * ===================================================================== */

  /**
   * Build an overAuth 1.0 key.
   * Format: oav1_<base64url(payload JSON)>.<base64url(HMAC-SHA256(payload, secret)[0:16])>
   */
  function buildKey(options) {
    options = options || {};
    var now = Math.floor(Date.now() / 1000);
    var payload = {
      v: 1,
      kid: options.keyId || ('oak_' + randomHex(8)),
      sub: options.owner || 'unknown',
      org: options.origins || ['*'],
      scp: options.scopes || ['profile', 'sessions'],
      iat: now
    };
    if (options.mode) payload.m = options.mode;          // 'db' (default) or 'local'
    if (options.expiresAt) payload.exp = Math.floor(new Date(options.expiresAt).getTime() / 1000);
    if (options.name) payload.n = String(options.name).slice(0, 60);

    var body = b64urlEncode(JSON.stringify(payload));
    var sig = b64urlFromBytes(hmacSha256Raw(utf8Bytes(KEY_SIGNING_SECRET), utf8Bytes(body)).slice(0, 16));
    return {
      key: KEY_PREFIX + body + '.' + sig,
      keyId: payload.kid,
      keyHash: sha256Hex(KEY_PREFIX + body + '.' + sig),
      payload: payload
    };
  }

  /** Parse + signature-check a key without contacting the network. */
  function parseKey(key) {
    if (typeof key !== 'string') return { valid: false, reason: 'invalid_key' };
    var match = /^oav1_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(key.trim());
    if (!match) return { valid: false, reason: 'invalid_key' };
    var payload;
    try { payload = JSON.parse(b64urlDecode(match[1])); } catch (e) { return { valid: false, reason: 'invalid_key' }; }
    if (!payload || payload.v !== 1 || !payload.kid) return { valid: false, reason: 'invalid_key' };
    var expected = b64urlFromBytes(hmacSha256Raw(utf8Bytes(KEY_SIGNING_SECRET), utf8Bytes(match[1])).slice(0, 16));
    var signatureValid = safeEqual(expected, match[2]);
    var expired = !!(payload.exp && payload.exp * 1000 < Date.now());
    return {
      valid: signatureValid && !expired,
      signatureValid: signatureValid,
      expired: expired,
      reason: !signatureValid ? 'invalid_key' : (expired ? 'key_expired' : null),
      raw: key.trim(),
      keyId: payload.kid,
      payload: payload,
      owner: payload.sub,
      origins: payload.org || [],
      scopes: payload.scp || [],
      name: payload.n || null,
      mode: payload.m || 'db',
      issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
      expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null
    };
  }

  /* =====================================================================
   * 3. Transport
   * ===================================================================== */

  function currentOrigin() {
    try {
      if (typeof global.location !== 'undefined' && global.location.origin && global.location.origin !== 'null') {
        return global.location.origin;
      }
      if (typeof global.location !== 'undefined' && global.location.protocol === 'file:') return 'file://';
    } catch (e) { /* node */ }
    return 'unknown';
  }

  function fetchJson(url, options) {
    var f = global.fetch;
    if (typeof f !== 'function') {
      return Promise.reject(new Error('fetch is not available in this environment'));
    }
    return f(url, options).then(function (response) {
      return response.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
        return { status: response.status, ok: response.ok, data: data };
      });
    }).catch(function (err) {
      return { status: 0, ok: false, data: null, networkError: String(err && err.message || err) };
    });
  }

  function rpcHeaders() {
    return {
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': 'Bearer ' + SUPABASE_ANON_KEY,
      'Content-Type': 'application/json'
    };
  }

  /** Call a Supabase SQL function (RPC). Resolves to { status, data, error, missing }. */
  function rpc(fn, params) {
    return fetchJson(SUPABASE_URL + '/rest/v1/rpc/' + fn, {
      method: 'POST',
      headers: rpcHeaders(),
      body: JSON.stringify(params || {})
    }).then(function (res) {
      if (res.networkError) return { status: 0, data: null, error: { message: res.networkError, code: 'NETWORK' }, missing: false };
      var isMissing = res.status === 404 && res.data && (res.data.code === 'PGRST202' || /could not find the function/i.test(res.data.message || ''));
      return { status: res.status, data: res.ok ? res.data : null, error: res.ok ? null : res.data, missing: !!isMissing };
    });
  }

  /** Raw PostgREST GET (used by the no-SQL "local" fallback). */
  function restSelect(table, query) {
    return fetchJson(SUPABASE_URL + '/rest/v1/' + table + '?' + query, {
      method: 'GET',
      headers: Object.assign({ 'Accept': 'application/json' }, rpcHeaders())
    });
  }

  /* =====================================================================
   * 4. Origin matching (mirrors public.overauth_origin_allowed in SQL)
   * ===================================================================== */

  function originAllowed(allowed, origin) {
    if (!allowed || !allowed.length) return false;
    var o = String(origin || '').toLowerCase().replace(/\/+$/, '');
    for (var i = 0; i < allowed.length; i++) {
      var pattern = String(allowed[i] || '').trim().toLowerCase().replace(/\/+$/, '');
      if (!pattern) continue;
      if (pattern === '*') return true;
      if (pattern === o) return true;
      if (pattern.indexOf('*') !== -1) {
        var rx = new RegExp('^' + pattern.split('*').map(escapeRegExp).join('[^/]*') + '$');
        if (rx.test(o)) return true;
      }
    }
    return false;
  }

  function escapeRegExp(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  /* =====================================================================
   * 5. State + public API
   * ===================================================================== */

  var state = {
    initialized: false,
    key: null,
    parsed: null,
    mode: 'auto',        // 'auto' | 'db' | 'local'
    backend: 'unknown',  // 'ready' | 'missing' | 'unknown' | 'error'
    origin: null,
    storage: true,
    remember: true,
    user: null,
    sessionToken: null,
    sessionExpiresAt: null,
    sessionCheckedAt: 0,
    listeners: [],
    widgets: []
  };

  function fail(reason, extra) {
    var out = { ok: false, reason: reason, message: REASONS[reason] || reason };
    if (extra) for (var k in extra) if (Object.prototype.hasOwnProperty.call(extra, k)) out[k] = extra[k];
    return out;
  }

  function emit(event) {
    for (var i = 0; i < state.listeners.length; i++) {
      try { state.listeners[i](event); } catch (e) { /* listener errors must not break auth */ }
    }
  }

  function storageKey() { return 'overauth.session.' + (state.parsed ? state.parsed.keyId : 'default'); }

  function storeAvailable() {
    try {
      if (!state.storage) return null;
      if (typeof global.localStorage === 'undefined') return null;
      var probe = '__overauth_probe__';
      global.localStorage.setItem(probe, '1');
      global.localStorage.removeItem(probe);
      return global.localStorage;
    } catch (e) { return null; }
  }

  function saveSession(result) {
    var store = storeAvailable();
    if (!store || !result || !result.ok) return;
    try {
      store.setItem(storageKey(), JSON.stringify({
        v: 1,
        user: result.user,
        session_token: result.session_token || null,
        expires_at: result.session_expires_at || null,
        mode: result.mode,
        saved_at: new Date().toISOString()
      }));
    } catch (e) { /* private mode / quota */ }
  }

  function readStoredSession() {
    var store = storeAvailable();
    if (!store) return null;
    try {
      var raw = store.getItem(storageKey());
      return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
  }

  function clearStoredSession() {
    var store = storeAvailable();
    if (!store) return;
    try { store.removeItem(storageKey()); } catch (e) { /* ignore */ }
  }

  /** Is the overAuth SQL backend installed on the Supabase project? */
  function backendStatus(force) {
    if (!force && (state.backend === 'ready' || state.backend === 'missing')) {
      return Promise.resolve(state.backend);
    }
    return rpc('overauth_health', {}).then(function (res) {
      if (res.missing) state.backend = 'missing';
      else if (res.error) state.backend = 'error';
      else if (res.data && res.data.ok) state.backend = 'ready';
      else state.backend = 'error';
      return state.backend;
    });
  }

  function init(options) {
    options = options || {};
    if (typeof options === 'string') options = { key: options };
    if (!options.key) return Promise.resolve(fail('invalid_key', { message: 'No overAuth key supplied.' }));

    var parsed = parseKey(options.key);
    if (!parsed.signatureValid) return Promise.resolve(fail('invalid_key'));
    if (parsed.expired) return Promise.resolve(fail('key_expired'));

    state.key = parsed.raw;
    state.parsed = parsed;
    state.mode = options.mode || 'auto';
    state.origin = options.origin || currentOrigin();
    state.storage = options.storage !== false;
    state.remember = options.remember !== false;
    if (options.onAuthChange) onAuthChange(options.onAuthChange);
    state.initialized = true;

    // Re-initialising (possibly with a different key) starts from a clean slate;
    // any session belonging to *this* key is restored from storage below.
    state.user = null;
    state.sessionToken = null;
    state.sessionExpiresAt = null;
    state.sessionCheckedAt = 0;

    var stored = readStoredSession();
    if (stored && stored.user) {
      state.user = stored.user;
      state.sessionToken = stored.session_token || null;
      state.sessionExpiresAt = stored.expires_at || null;
    }

    return backendStatus().then(function (backend) {
      var mode = state.mode === 'auto' ? (backend === 'ready' ? 'db' : 'local') : state.mode;
      var info = {
        ok: true,
        version: VERSION,
        backend: backend,
        mode: mode,
        keyId: parsed.keyId,
        owner: parsed.owner,
        keyName: parsed.name,
        origins: parsed.origins,
        scopes: parsed.scopes,
        expiresAt: parsed.expiresAt,
        origin: state.origin,
        originAllowed: originAllowed(parsed.origins, state.origin),
        session: state.user ? { user: state.user, session_token: state.sessionToken } : null
      };
      if (state.user) emit({ type: 'SESSION_RESTORED', user: state.user });
      if (state.widgets.length) renderAllWidgets();
      return info;
    });
  }

  function requireInit() {
    if (!state.initialized || !state.parsed) return fail('not_initialized');
    if (!state.parsed.signatureValid) return fail('invalid_key');
    if (state.parsed.expired) return fail('key_expired');
    return null;
  }

  /**
   * Verify a username + password against Overmind.
   * Does NOT create a local session — use signIn() for that.
   */
  function checkCredentials(username, password, options) {
    options = options || {};
    var guard = requireInit();
    if (guard) return Promise.resolve(guard);
    username = String(username == null ? '' : username).trim();
    password = String(password == null ? '' : password);
    if (!username || !password) return Promise.resolve(fail('missing_credentials'));

    var passwordHash = sha256Hex(password);
    var origin = options.origin || state.origin;
    var remember = typeof options.remember === 'boolean' ? options.remember : state.remember;
    var mode = state.mode === 'auto' ? null : state.mode;

    function runLocal() {
      var parsed = state.parsed;
      if (!parsed.signatureValid) return Promise.resolve(fail('invalid_key'));
      if (parsed.expired) return Promise.resolve(fail('key_expired'));
      if (!originAllowed(parsed.origins, origin)) {
        return Promise.resolve(fail('origin_not_allowed', { origin: origin, allowed_origins: parsed.origins }));
      }
      var q = 'select=username,is_admin,is_banned,created_at' +
        '&username=eq.' + encodeURIComponent(username) +
        '&password_hash=eq.' + encodeURIComponent(passwordHash) +
        '&limit=1';
      return restSelect('users', q).then(function (res) {
        if (res.networkError) return fail('network_error', { detail: res.networkError });
        if (!res.ok) return fail('backend_error', { detail: res.data });
        var rows = Array.isArray(res.data) ? res.data : [];
        if (!rows.length) return fail('invalid_credentials');
        var row = rows[0];
        if (row.is_banned) return fail('account_banned');
        var user = { username: row.username };
        if (hasScope(parsed.scopes, 'profile')) user.created_at = row.created_at || null;
        if (hasScope(parsed.scopes, 'admin_flag')) user.is_admin = !!row.is_admin;
        var result = {
          ok: true,
          mode: 'local',
          user: user,
          key: { key_id: parsed.keyId, name: parsed.name },
          session_token: null,
          session_expires_at: null
        };
        if (remember) {
          // No server-side sessions in local mode: mint a browser-only token.
          result.session_token = 'local_' + hmacSha256Hex(parsed.keyId + '|' + user.username, String(Date.now())).slice(0, 32);
          result.session_expires_at = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
        }
        return result;
      });
    }

    function runDb() {
      return rpc('overauth_verify', {
        p_key_id: state.parsed.keyId,
        p_key_hash: sha256Hex(state.key),
        p_username: username,
        p_password_hash: passwordHash,
        p_origin: origin,
        p_remember: remember
      }).then(function (res) {
        if (res.missing) {
          state.backend = 'missing';
          return runLocal();
        }
        if (res.status === 0) return fail('network_error', { detail: res.error && res.error.message });
        if (res.error) return fail('backend_error', { detail: res.error.message || res.error, code: res.error.code });
        var data = res.data || {};
        data.mode = 'db';
        return data;
      });
    }

    return (mode === 'local' ? runLocal() : runDb()).then(function (result) {
      result = normalize(result);
      if (result && result.ok) state.backend = result.mode === 'db' ? 'ready' : state.backend;
      return result;
    });
  }

  /** Server responses carry a machine `reason`; make sure there is always a
   *  human-readable `message` a site can show the visitor. */
  function normalize(result) {
    if (!result || typeof result !== 'object') return fail('backend_error');
    if (result.ok !== true && !result.message) {
      result.message = REASONS[result.reason] || (result.reason ? String(result.reason) : 'Sign in failed.');
    }
    return result;
  }

  function hasScope(scopes, name) {
    if (!scopes || !scopes.length) return false;
    if (scopes.indexOf('*') !== -1) return true;
    return scopes.indexOf(name) !== -1;
  }

  /** Verify credentials AND keep the user signed in on this site. */
  function signIn(username, password, options) {
    return checkCredentials(username, password, options).then(function (result) {
      if (result && result.ok) {
        state.user = result.user;
        state.sessionToken = result.session_token || null;
        state.sessionExpiresAt = result.session_expires_at || null;
        state.sessionCheckedAt = Date.now();
        saveSession(result);
        emit({ type: 'SIGNED_IN', user: result.user, result: result });
        renderAllWidgets();
      } else {
        emit({ type: 'ERROR', result: result });
      }
      return result;
    });
  }

  /** Restore / revalidate the stored session. Resolves to a result object or null. */
  function getSession(options) {
    options = options || {};
    var guard = requireInit();
    if (guard) return Promise.resolve(null);

    var stored = readStoredSession();
    if (!state.user && stored && stored.user) {
      state.user = stored.user;
      state.sessionToken = stored.session_token || null;
      state.sessionExpiresAt = stored.expires_at || null;
    }
    if (!state.user) return Promise.resolve(null);

    var fresh = Date.now() - state.sessionCheckedAt < (options.maxAge || 12 * 3600 * 1000);
    if (fresh && !options.force) {
      return Promise.resolve({ ok: true, mode: stored ? stored.mode : 'db', user: state.user, session_token: state.sessionToken, session_expires_at: state.sessionExpiresAt, cached: true });
    }

    if (!state.sessionToken || String(state.sessionToken).indexOf('local_') === 0) {
      // Local-mode sessions cannot be revalidated server-side.
      state.sessionCheckedAt = Date.now();
      return Promise.resolve({ ok: true, mode: 'local', user: state.user, session_token: state.sessionToken, session_expires_at: state.sessionExpiresAt });
    }

    return rpc('overauth_session', { p_token: state.sessionToken }).then(function (res) {
      state.sessionCheckedAt = Date.now();
      if (res.missing) return { ok: true, mode: 'local', user: state.user, session_token: state.sessionToken };
      if (res.error || !res.data || !res.data.ok) {
        var reason = (res.data && res.data.reason) || 'invalid_session';
        signOut({ silentRemote: true });
        return fail(reason);
      }
      state.user = res.data.user || state.user;
      var out = { ok: true, mode: 'db', user: state.user, session_token: state.sessionToken, session_expires_at: res.data.expires_at || state.sessionExpiresAt };
      saveSession(out);
      return out;
    });
  }

  /** Sign the current visitor out of this site. */
  function signOut(options) {
    options = options || {};
    var token = state.sessionToken;
    state.user = null;
    state.sessionToken = null;
    state.sessionExpiresAt = null;
    state.sessionCheckedAt = 0;
    clearStoredSession();
    renderAllWidgets();
    emit({ type: 'SIGNED_OUT' });
    if (token && String(token).indexOf('local_') !== 0 && !options.silentRemote) {
      return rpc('overauth_end_session', { p_token: token }).then(function () { return { ok: true }; });
    }
    return Promise.resolve({ ok: true });
  }

  function currentUser() { return state.user; }

  function onAuthChange(cb) {
    if (typeof cb !== 'function') return function () {};
    state.listeners.push(cb);
    return function () {
      var i = state.listeners.indexOf(cb);
      if (i !== -1) state.listeners.splice(i, 1);
    };
  }

  /* =====================================================================
   * 6. Drop-in UI widget
   * ===================================================================== */

  var WIDGET_CSS = [
    '.omauth-root{--omauth-accent:#22c55e;--omauth-bg:#131417;--omauth-card:#1a1b1e;--omauth-border:#2a2b30;',
    '--omauth-text:#e6e8ec;--omauth-muted:#9aa0aa;--omauth-input:#0f1012;--omauth-error:#f87171;--omauth-error-bg:rgba(248,113,113,.12);',
    'font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}',
    '.omauth-root[data-theme="light"]{--omauth-bg:#f6f7f9;--omauth-card:#ffffff;--omauth-border:#e3e5ea;--omauth-text:#14161a;',
    '--omauth-muted:#61676f;--omauth-input:#f4f5f7;--omauth-error:#b91c1c;--omauth-error-bg:rgba(185,28,28,.08);}',
    '.omauth-card{background:var(--omauth-card);color:var(--omauth-text);border:1px solid var(--omauth-border);',
    'border-radius:16px;padding:22px;max-width:380px;box-sizing:border-box;box-shadow:0 18px 45px rgba(0,0,0,.28);}',
    '.omauth-head{display:flex;align-items:center;gap:10px;margin-bottom:14px;}',
    '.omauth-mark{width:30px;height:30px;border-radius:9px;background:var(--omauth-accent);display:flex;align-items:center;',
    'justify-content:center;font-weight:800;color:#05130a;font-size:16px;flex:0 0 auto;}',
    '.omauth-brand{font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;color:var(--omauth-muted);}',
    '.omauth-title{font-size:1.12rem;font-weight:700;line-height:1.25;margin:2px 0 0;}',
    '.omauth-desc{font-size:.85rem;color:var(--omauth-muted);margin:0 0 16px;line-height:1.5;}',
    '.omauth-field{margin-bottom:12px;}',
    '.omauth-label{display:block;font-size:.75rem;color:var(--omauth-muted);margin-bottom:6px;letter-spacing:.02em;}',
    '.omauth-input{width:100%;box-sizing:border-box;background:var(--omauth-input);border:1px solid var(--omauth-border);',
    'color:var(--omauth-text);border-radius:10px;padding:11px 12px;font-size:.95rem;outline:none;transition:border-color .15s ease;}',
    '.omauth-input:focus{border-color:var(--omauth-accent);}',
    '.omauth-btn{width:100%;background:var(--omauth-accent);color:#05130a;border:0;border-radius:10px;padding:12px 14px;',
    'font-size:.95rem;font-weight:700;cursor:pointer;transition:filter .15s ease,transform .05s ease;}',
    '.omauth-btn:hover{filter:brightness(1.07);}.omauth-btn:active{transform:translateY(1px);}',
    '.omauth-btn[disabled]{opacity:.6;cursor:progress;}',
    '.omauth-btn-ghost{width:100%;background:transparent;color:var(--omauth-text);border:1px solid var(--omauth-border);',
    'border-radius:10px;padding:11px 14px;font-size:.92rem;font-weight:600;cursor:pointer;margin-top:10px;}',
    '.omauth-btn-ghost:hover{border-color:var(--omauth-accent);color:var(--omauth-accent);}',
    '.omauth-error{background:var(--omauth-error-bg);border:1px solid var(--omauth-error);color:var(--omauth-error);',
    'border-radius:10px;padding:10px 12px;font-size:.85rem;margin-bottom:12px;line-height:1.45;}',
    '.omauth-note{font-size:.75rem;color:var(--omauth-muted);margin-top:14px;text-align:center;line-height:1.5;}',
    '.omauth-note a{color:var(--omauth-accent);text-decoration:none;}',
    '.omauth-user{display:flex;align-items:center;gap:12px;}',
    '.omauth-avatar{width:42px;height:42px;border-radius:50%;background:var(--omauth-accent);color:#05130a;font-weight:800;',
    'display:flex;align-items:center;justify-content:center;font-size:1.1rem;flex:0 0 auto;}',
    '.omauth-user-name{font-weight:700;font-size:1rem;}',
    '.omauth-user-sub{font-size:.8rem;color:var(--omauth-muted);}',
    '.omauth-overlay{position:fixed;inset:0;background:rgba(4,5,7,.66);display:flex;align-items:center;justify-content:center;',
    'z-index:2147483000;padding:18px;backdrop-filter:blur(3px);}',
    '.omauth-overlay .omauth-card{width:100%;}',
    '.omauth-close{position:absolute;top:10px;right:12px;background:transparent;border:0;color:var(--omauth-muted);',
    'font-size:1.25rem;cursor:pointer;line-height:1;}',
    '.omauth-hidden{display:none !important;}'
  ].join('');

  var cssInjected = false;
  function injectCss() {
    if (cssInjected || typeof document === 'undefined') return;
    var style = document.createElement('style');
    style.setAttribute('data-overauth', VERSION);
    style.textContent = WIDGET_CSS;
    (document.head || document.documentElement).appendChild(style);
    cssInjected = true;
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function defaultWidgetOptions(options) {
    return Object.assign({
      theme: 'dark',
      accent: null,
      title: 'Sign in with Overmind',
      description: 'Use your Overmind account to continue.',
      buttonLabel: 'Sign in',
      signedInTitle: 'You are signed in',
      showSignUpLink: true,
      signUpUrl: 'https://v0idplayy-777.github.io/Overmind/chat.html',
      redirect: null,
      remember: true,
      onSuccess: null,
      onError: null,
      onSignOut: null
    }, options || {});
  }

  /** Forget any widget already attached to this container (re-mounts stay clean). */
  function dropWidgetFor(host) {
    state.widgets = state.widgets.filter(function (w) {
      if (w.host === host) { closeModal(w); return false; }
      return true;
    });
  }

  /** Render the full login card into a container element. */
  function mount(target, options) {
    if (typeof document === 'undefined') return null;
    var host = typeof target === 'string' ? document.querySelector(target) : target;
    if (!host) return null;
    injectCss();
    dropWidgetFor(host);
    var opts = defaultWidgetOptions(options);
    if (opts.key && opts.key !== state.key) init({ key: opts.key, origin: opts.origin, storage: opts.storage, remember: opts.remember });

    var root = el('div', 'omauth-root');
    root.setAttribute('data-theme', opts.theme === 'light' ? 'light' : 'dark');
    if (opts.accent) root.style.setProperty('--omauth-accent', opts.accent);
    host.innerHTML = '';
    host.appendChild(root);

    var widget = { host: host, root: root, opts: opts, kind: 'card' };
    state.widgets.push(widget);
    renderWidget(widget);
    return widget;
  }

  /** Render just a button that opens the login card in a modal. */
  function renderButton(target, options) {
    if (typeof document === 'undefined') return null;
    var host = typeof target === 'string' ? document.querySelector(target) : target;
    if (!host) return null;
    injectCss();
    dropWidgetFor(host);
    var opts = defaultWidgetOptions(options);
    if (opts.key && opts.key !== state.key) init({ key: opts.key, origin: opts.origin, storage: opts.storage, remember: opts.remember });

    var root = el('div', 'omauth-root');
    root.setAttribute('data-theme', opts.theme === 'light' ? 'light' : 'dark');
    if (opts.accent) root.style.setProperty('--omauth-accent', opts.accent);
    host.innerHTML = '';

    var button = el('button', 'omauth-btn', opts.buttonText || 'Continue with Overmind');
    button.type = 'button';
    root.appendChild(button);
    host.appendChild(root);

    var widget = { host: host, root: root, opts: opts, kind: 'button', button: button, overlay: null };
    button.addEventListener('click', function () { openModal(widget); });
    state.widgets.push(widget);
    refreshButtonLabel(widget);
    return widget;
  }

  function refreshButtonLabel(widget) {
    if (!widget.button) return;
    widget.button.textContent = state.user
      ? (widget.opts.signedInButtonLabel || ('Signed in as ' + state.user.username))
      : (widget.opts.buttonText || 'Continue with Overmind');
  }

  function openModal(widget) {
    closeModal(widget);
    var overlay = el('div', 'omauth-overlay');
    var shell = el('div');
    shell.style.position = 'relative';
    overlay.appendChild(shell);
    overlay.addEventListener('click', function (e) { if (e.target === overlay) closeModal(widget); });
    document.body.appendChild(overlay);
    widget.overlay = overlay;
    widget.modalHost = shell;
    var inner = mount(shell, Object.assign({}, widget.opts, { key: state.key }));
    widget.modalWidget = inner;
    var close = el('button', 'omauth-close', '✕');
    close.type = 'button';
    close.addEventListener('click', function () { closeModal(widget); });
    shell.appendChild(close);
    var first = shell.querySelector('input');
    if (first) first.focus();
  }

  function closeModal(widget) {
    if (widget.modalHost) unmount(widget.modalHost);
    if (widget.overlay && widget.overlay.parentNode) widget.overlay.parentNode.removeChild(widget.overlay);
    widget.overlay = null;
    widget.modalWidget = null;
    widget.modalHost = null;
  }

  function unmount(target) {
    var host = typeof target === 'string' ? document.querySelector(target) : target;
    state.widgets = state.widgets.filter(function (w) {
      if (w.host === host) { closeModal(w); if (w.host && w.host.parentNode) w.host.innerHTML = ''; return false; }
      return true;
    });
  }

  function renderAllWidgets() {
    for (var i = state.widgets.length - 1; i >= 0; i--) {
      var w = state.widgets[i];
      if (!w.host || !document.contains(w.host)) { state.widgets.splice(i, 1); continue; }
      if (w.kind === 'card') renderWidget(w);
      else {
        refreshButtonLabel(w);
        if (w.modalWidget) renderWidget(w.modalWidget);
      }
    }
  }

  function renderWidget(widget) {
    var opts = widget.opts;
    var root = widget.root;
    root.innerHTML = '';

    var card = el('div', 'omauth-card');
    root.appendChild(card);

    var head = el('div', 'omauth-head');
    head.appendChild(el('div', 'omauth-mark', 'O'));
    var headText = el('div');
    headText.appendChild(el('div', 'omauth-brand', 'Overmind'));
    headText.appendChild(el('div', 'omauth-title', state.user ? opts.signedInTitle : opts.title));
    head.appendChild(headText);
    card.appendChild(head);

    if (state.user) {
      var row = el('div', 'omauth-user');
      row.appendChild(el('div', 'omauth-avatar', String(state.user.username || '?').charAt(0).toUpperCase()));
      var meta = el('div');
      meta.appendChild(el('div', 'omauth-user-name', state.user.username));
      meta.appendChild(el('div', 'omauth-user-sub', 'Signed in with overAuth 1.0'));
      row.appendChild(meta);
      card.appendChild(row);

      var out = el('button', 'omauth-btn-ghost', 'Sign out');
      out.type = 'button';
      out.addEventListener('click', function () {
        signOut().then(function () {
          if (typeof opts.onSignOut === 'function') opts.onSignOut();
          renderAllWidgets();
        });
      });
      card.appendChild(out);
      card.appendChild(footNote(opts));
      return;
    }

    var errorBox = el('div', 'omauth-error');
    errorBox.classList.add('omauth-hidden');
    card.appendChild(errorBox);

    if (opts.description) card.appendChild(el('p', 'omauth-desc', opts.description));

    var form = el('form');
    form.setAttribute('autocomplete', 'on');

    var userField = el('div', 'omauth-field');
    userField.appendChild(el('label', 'omauth-label', 'Overmind username'));
    var userInput = el('input', 'omauth-input');
    userInput.type = 'text';
    userInput.name = 'username';
    userInput.placeholder = 'username';
    userInput.autocomplete = 'username';
    userInput.required = true;
    userField.appendChild(userInput);
    form.appendChild(userField);

    var passField = el('div', 'omauth-field');
    passField.appendChild(el('label', 'omauth-label', 'Password'));
    var passInput = el('input', 'omauth-input');
    passInput.type = 'password';
    passInput.name = 'password';
    passInput.placeholder = '••••••••';
    passInput.autocomplete = 'current-password';
    passInput.required = true;
    passField.appendChild(passInput);
    form.appendChild(passField);

    var submit = el('button', 'omauth-btn', opts.buttonLabel);
    submit.type = 'submit';
    form.appendChild(submit);
    card.appendChild(form);
    card.appendChild(footNote(opts));

    form.addEventListener('submit', function (event) {
      event.preventDefault();
      errorBox.classList.add('omauth-hidden');
      submit.disabled = true;
      var original = submit.textContent;
      submit.textContent = 'Checking…';
      signIn(userInput.value, passInput.value, { remember: opts.remember }).then(function (result) {
        submit.disabled = false;
        submit.textContent = original;
        if (result && result.ok) {
          passInput.value = '';
          if (typeof opts.onSuccess === 'function') opts.onSuccess(result);
          if (opts.redirect) { global.location.href = opts.redirect; return; }
          renderAllWidgets();
        } else {
          errorBox.textContent = (result && (result.message || result.reason)) || 'Sign in failed.';
          errorBox.classList.remove('omauth-hidden');
          if (typeof opts.onError === 'function') opts.onError(result);
        }
      });
    });
  }

  function footNote(opts) {
    var note = el('div', 'omauth-note');
    if (opts.showSignUpLink) {
      note.appendChild(document.createTextNode('No account? '));
      var a = el('a', null, 'Create one on Overmind');
      a.href = opts.signUpUrl;
      a.target = '_blank';
      a.rel = 'noopener';
      note.appendChild(a);
      note.appendChild(document.createTextNode(' · '));
    }
    var powered = el('a', null, 'overAuth 1.0');
    powered.href = 'https://v0idplayy-777.github.io/Overmind/overauth.html';
    powered.target = '_blank';
    powered.rel = 'noopener';
    note.appendChild(document.createTextNode('Protected by '));
    note.appendChild(powered);
    return note;
  }

  /* =====================================================================
   * 7. Zero-config boot from a <script> tag
   * ===================================================================== */

  function bootFromScript() {
    if (typeof document === 'undefined') return;
    var script = document.currentScript ||
      (function () {
        var all = document.getElementsByTagName('script');
        for (var i = all.length - 1; i >= 0; i--) {
          if (/overauth(\.min)?\.js/.test(all[i].src || '')) return all[i];
        }
        return null;
      })();
    if (!script) return;

    var key = script.getAttribute('data-key');
    var container = script.getAttribute('data-container');
    var buttonMode = script.getAttribute('data-button') === 'true';
    var autoMount = script.getAttribute('data-auto') !== 'false';

    function start() {
      var opts = {
        key: key,
        theme: script.getAttribute('data-theme') || 'dark',
        accent: script.getAttribute('data-accent') || null,
        title: script.getAttribute('data-title') || undefined,
        description: script.getAttribute('data-description') || undefined,
        buttonLabel: script.getAttribute('data-button-label') || undefined,
        buttonText: script.getAttribute('data-button-text') || undefined,
        redirect: script.getAttribute('data-redirect') || null,
        showSignUpLink: script.getAttribute('data-signup') !== 'false',
        signUpUrl: script.getAttribute('data-signup-url') || undefined
      };
      if (!key) return;
      init(opts).then(function (info) {
        if (typeof global.CustomEvent === 'function') {
          document.dispatchEvent(new CustomEvent('overauth:ready', { detail: info }));
        }
        if (!autoMount) return;
        // 1) explicit container
        if (container) {
          if (buttonMode) renderButton(container, opts);
          else mount(container, opts);
          return;
        }
        // 2) any element flagged with data-overauth
        var flagged = document.querySelectorAll('[data-overauth], [data-overauth-key]');
        if (flagged.length) {
          for (var i = 0; i < flagged.length; i++) {
            var node = flagged[i];
            var nodeOpts = Object.assign({}, opts, {
              key: node.getAttribute('data-overauth-key') || node.getAttribute('data-key') || key,
              theme: node.getAttribute('data-theme') || opts.theme
            });
            if (node.getAttribute('data-overauth') === 'button') renderButton(node, nodeOpts);
            else mount(node, nodeOpts);
          }
          return;
        }
        // 3) last resort: append a card to <body>
        if (buttonMode) return;
        var holder = document.createElement('div');
        holder.id = 'overmind-auth';
        holder.style.cssText = 'display:flex;justify-content:center;padding:24px;';
        document.body.appendChild(holder);
        mount(holder, opts);
      });
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
  }

  bootFromScript();

  /* =====================================================================
   * 8. Exports
   * ===================================================================== */

  return {
    version: VERSION,
    // config
    supabaseUrl: SUPABASE_URL,
    reasons: REASONS,
    // core
    init: init,
    checkCredentials: checkCredentials,
    signIn: signIn,
    signOut: signOut,
    getSession: getSession,
    currentUser: currentUser,
    onAuthChange: onAuthChange,
    backendStatus: backendStatus,
    // ui
    mount: mount,
    renderButton: renderButton,
    unmount: unmount,
    // helpers (also used by the developer console)
    parseKey: parseKey,
    originAllowed: originAllowed,
    utils: {
      buildKey: buildKey,
      parseKey: parseKey,
      sha256Hex: sha256Hex,
      hmacSha256Hex: hmacSha256Hex,
      b64urlEncode: b64urlEncode,
      b64urlDecode: b64urlDecode,
      randomHex: randomHex,
      randomId: function (prefix) { return (prefix || 'oak_') + randomHex(8); },
      originAllowed: originAllowed,
      currentOrigin: currentOrigin,
      rpc: rpc,
      fetchJson: fetchJson
    }
  };
});
