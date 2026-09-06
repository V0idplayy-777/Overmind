/* Shared test harness: a minimal DOM shim + a mock of the Overmind Supabase
   backend (tables and the overauth_* SQL functions, re-implemented in JS).
   Used by tests/overauth.test.js and tests/console.test.js. No dependencies. */
'use strict';
const crypto = require('node:crypto');

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

/* --------------------------------- DOM ---------------------------------- */

class ClassList {
  constructor(node) { this.node = node; }
  get set() { return new Set(String(this.node.className || '').split(/\s+/).filter(Boolean)); }
  write(set) { this.node.className = [...set].join(' '); }
  add(c) { const s = this.set; s.add(c); this.write(s); }
  remove(c) { const s = this.set; s.delete(c); this.write(s); }
  toggle(c) { this.set.has(c) ? this.remove(c) : this.add(c); }
  contains(c) { return this.set.has(c); }
}

class Node {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.attrs = {};
    this.dataset = {};
    this.style = {
      _props: {},
      setProperty(k, v) { this._props[k] = v; },
      get cssText() { return this._css || ''; },
      set cssText(v) { this._css = v; }
    };
    this.listeners = {};
    this.classList = new ClassList(this);
    this.className = '';
    this._text = '';
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.required = false;
    this.type = ''; this.name = ''; this.placeholder = ''; this.href = ''; this.rel = '';
    this.parentNode = null;
    this._html = '';
  }
  get textContent() { return this._text == null ? '' : String(this._text); }
  set textContent(v) { this._text = v == null ? '' : String(v); }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'class') this.className = String(v); if (k === 'id') this.attrs.id = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
  appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
  removeChild(child) { this.children = this.children.filter(c => c !== child); child.parentNode = null; return child; }
  set innerHTML(v) {
    if (v === '') { this.children.forEach(c => (c.parentNode = null)); this.children = []; this._html = ''; }
    else { this._html = String(v); this.children = []; }
  }
  get innerHTML() { return this._html || this.children.map(c => c.outerHTML()).join(''); }
  outerHTML() {
    return '<' + this.tagName.toLowerCase() + (this.className ? ' class="' + this.className + '"' : '') + '>' +
      (this.textContent || this.innerHTML) + '</' + this.tagName.toLowerCase() + '>';
  }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter(f => f !== fn); }
  dispatchEvent(ev) { (this.listeners[ev.type] || []).slice().forEach(fn => fn(ev)); return true; }
  click() { this.dispatchEvent({ type: 'click', target: this, preventDefault() {} }); }
  focus() { this._focused = true; }
  scrollIntoView() {}
  querySelectorAll(sel) { const out = []; walk(this, n => { if (matches(n, sel)) out.push(n); }); return out; }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  contains(node) { let found = false; walk(this, n => { if (n === node) found = true; }); return found; }
  get lastElementChild() { return this.children[this.children.length - 1] || null; }
  get firstChild() { return this.children[0] || null; }
}

function matchesSimple(node, sel) {
  sel = sel.trim();
  if (!sel) return false;
  // "div.foo" style compounds
  const parts = sel.match(/^[a-zA-Z]+|[.#][\w-]+|\[[^\]]+\]/g);
  if (!parts || parts.join('') !== sel) return false;
  return parts.every(part => {
    if (part.startsWith('.')) return node.classList.contains(part.slice(1));
    if (part.startsWith('#')) return node.attrs.id === part.slice(1);
    if (part.startsWith('[')) return node.getAttribute(part.slice(1, -1).split('=')[0]) !== null;
    return node.tagName === part.toUpperCase();
  });
}

function matches(node, sel) {
  sel = sel.trim();
  if (sel.includes(',')) return sel.split(',').some(s => matches(node, s));
  if (/\s/.test(sel)) return matchesPath(node, sel.split(/\s+/));
  return matchesSimple(node, sel);
}

/** descendant combinator support: "a b c" — c is the node, a/b must be ancestors */
function matchesPath(node, parts) {
  if (!matchesSimple(node, parts[parts.length - 1])) return false;
  let i = parts.length - 2;
  let p = node.parentNode;
  while (i >= 0 && p) {
    if (matchesSimple(p, parts[i])) i--;
    p = p.parentNode;
  }
  return i < 0;
}
function walk(node, fn) { node.children.forEach(c => { fn(c); walk(c, fn); }); }

/**
 * installDom(): puts a shim `document`, `localStorage`, `location`, `window`
 * on globalThis. getElementById / querySelector auto-create cached elements so
 * page scripts can be driven without a real browser.
 */
function buildNode(spec) {
  const n = new Node(spec.tag);
  Object.entries(spec.attrs || {}).forEach(([k, v]) => n.setAttribute(k, v));
  if (spec.text) n.textContent = spec.text.trim();
  (spec.children || []).forEach(c => n.appendChild(buildNode(c)));

  // reflect markup state the way a browser would
  const a = spec.attrs || {};
  ['type', 'name', 'placeholder', 'href', 'rel', 'target', 'value'].forEach(k => {
    if (a[k] != null && a[k] !== '') n[k] = a[k];
  });
  n.checked = a.checked != null;
  n.disabled = a.disabled != null;
  n.required = a.required != null;
  if (spec.text && (n.tagName === 'TEXTAREA' || n.tagName === 'OPTION')) n.value = spec.text.trim();
  if (n.tagName === 'SELECT') {
    const opts = n.querySelectorAll('option');
    const selected = opts.find(o => o.getAttribute('selected') != null) || opts[0];
    if (selected) n.value = selected.getAttribute('value') != null ? selected.getAttribute('value') : selected.value;
  }
  return n;
}

function findTag(spec, tag) {
  if (!spec) return null;
  if (spec.tag === tag) return spec;
  for (const child of spec.children || []) {
    const hit = findTag(child, tag);
    if (hit) return hit;
  }
  return null;
}

/**
 * installDom(): puts a shim `document`, `localStorage`, `location`, `window` on
 * globalThis.
 *   options.dom      — a DOM tree from tests/build-dom.py; when given, the page's
 *                      real elements exist and getElementById() returns null for
 *                      ids that are NOT in the markup (so typos are caught).
 *   options.autoviv  — create unknown ids on demand (default when no `dom`).
 */
function installDom(options) {
  options = options || {};
  const missingIds = [];
  const byId = new Map();

  const document = {
    readyState: 'complete',
    currentScript: null,
    createElement: (t) => new Node(t),
    createTextNode: (t) => { const n = new Node('#text'); n.textContent = t; return n; },
    head: new Node('head'),
    documentElement: new Node('html'),
    body: new Node('body'),
    getElementsByTagName: (t) => document.querySelectorAll(t),
    getElementById(id) {
      if (byId.has(id)) return byId.get(id);
      if (options.autoviv) {
        const n = new Node('div');
        n.setAttribute('id', id);
        byId.set(id, n);
        document.body.appendChild(n);
        return n;
      }
      missingIds.push(id);
      return null;
    },
    querySelectorAll(sel) {
      const out = [];
      const visit = n => { if (matches(n, sel) && out.indexOf(n) === -1) out.push(n); };
      walk(document.head, visit);
      walk(document.body, visit);
      byId.forEach(n => { if (!document.body.contains(n) && !document.head.contains(n)) visit(n); });
      return out;
    },
    querySelector(sel) {
      if (sel.startsWith('#') && !/[\s,]/.test(sel)) return document.getElementById(sel.slice(1));
      return document.querySelectorAll(sel)[0] || null;
    },
    contains(n) { return document.body.contains(n) || document.head.contains(n); },
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() {},
    execCommand: () => true,
    _byId: byId,
    _missingIds: missingIds
  };
  document.body.parentNode = document.documentElement;
  document.head.parentNode = document.documentElement;

  if (options.dom) {
    const headSpec = findTag(options.dom, 'head');
    const bodySpec = findTag(options.dom, 'body');
    if (headSpec) (headSpec.children || []).forEach(c => document.head.appendChild(buildNode(c)));
    if (bodySpec) {
      Object.entries(bodySpec.attrs || {}).forEach(([k, v]) => document.body.setAttribute(k, v));
      (bodySpec.children || []).forEach(c => document.body.appendChild(buildNode(c)));
    }
    const index = n => { if (n.attrs && n.attrs.id) byId.set(n.attrs.id, n); };
    walk(document.head, index);
    walk(document.body, index);
  }

  const store = {};
  const localStorage = {
    getItem: k => (Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: k => { delete store[k]; },
    clear: () => { Object.keys(store).forEach(k => delete store[k]); },
    _store: store
  };
  const sessionStorage = {
    _s: {},
    getItem(k) { return Object.prototype.hasOwnProperty.call(this._s, k) ? this._s[k] : null; },
    setItem(k, v) { this._s[k] = String(v); },
    removeItem(k) { delete this._s[k]; }
  };

  globalThis.document = document;
  globalThis.localStorage = localStorage;
  globalThis.sessionStorage = sessionStorage;
  globalThis.location = {
    origin: options.origin || 'https://v0idplayy-777.github.io',
    href: options.origin || 'https://v0idplayy-777.github.io',
    search: options.search || '',
    protocol: 'https:'
  };
  globalThis.window = globalThis;
  try {
    if (!globalThis.navigator) {
      Object.defineProperty(globalThis, 'navigator', { value: { clipboard: null }, configurable: true });
    }
  } catch (e) { /* node >= 21 ships a read-only navigator; that's fine */ }
  globalThis.CustomEvent = function (type, opts) { return Object.assign({ type }, opts); };
  globalThis.confirm = () => true;
  globalThis.alert = () => {};
  globalThis.open = () => null;
  globalThis.Blob = class { constructor(parts) { this.parts = parts; } };
  try {
    globalThis.URL.createObjectURL = () => 'blob:mock';
    globalThis.URL.revokeObjectURL = () => {};
  } catch (e) { /* ignore */ }

  return { document, localStorage, sessionStorage, Node, missingIds };
}

/* ---------------------------- mock Supabase ----------------------------- */

const DEFAULT_USERS = {
  alice: { username: 'alice', password: 'wonderland', is_admin: false, is_banned: false, created_at: '2026-07-29T05:03:15.119554' },
  root:  { username: 'root',  password: 'toor123',    is_admin: true,  is_banned: false, created_at: '2026-01-01T00:00:00' },
  bob:   { username: 'bob',   password: 'builder',    is_admin: false, is_banned: true,  created_at: '2026-02-02T00:00:00' }
};

function originAllowed(allowed, origin) {
  const o = String(origin || '').toLowerCase().replace(/\/+$/, '');
  return (allowed || []).some(p => {
    p = String(p).trim().toLowerCase().replace(/\/+$/, '');
    if (!p) return false;
    if (p === '*' || p === o) return true;
    if (p.includes('*')) {
      const rx = new RegExp('^' + p.split('*').map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*') + '$');
      return rx.test(o);
    }
    return false;
  });
}

/** installMock(): replaces globalThis.fetch with a PostgREST/RPC emulator. */
function installMock(options) {
  options = options || {};
  const state = {
    users: Object.assign({}, DEFAULT_USERS, options.users || {}),
    keys: [],
    sessions: {},
    backendInstalled: options.backendInstalled !== false,
    networkDown: false,
    calls: []
  };

  const json = (status, body) => ({
    status,
    ok: status >= 200 && status < 300,
    text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
    json: () => Promise.resolve(body)
  });

  const devOk = (b) => {
    const u = state.users[b.p_username];
    return !!(u && !u.is_banned && sha256(u.password) === b.p_password_hash);
  };

  globalThis.fetch = async function (url, opts) {
    if (state.networkDown) throw new Error('network unreachable');
    opts = opts || {};
    const body = opts.body ? JSON.parse(opts.body) : {};
    state.calls.push({ url: String(url), body });

    const rpcMatch = /\/rest\/v1\/rpc\/(\w+)$/.exec(url);
    if (rpcMatch) {
      const fn = rpcMatch[1];
      if (!state.backendInstalled) {
        return json(404, { code: 'PGRST202', message: 'Could not find the function public.' + fn + '(unknown) in the schema cache' });
      }
      switch (fn) {
        case 'overauth_health':
          return json(200, { ok: true, service: 'overauth', version: '1.0' });

        case 'overmind_login': {
          const u = state.users[body.p_username];
          if (!u || sha256(u.password) !== body.p_password_hash) return json(200, { ok: false, reason: 'invalid_credentials' });
          return json(200, { ok: true, username: u.username, is_admin: u.is_admin, is_banned: u.is_banned, message_limit: null, shrek_mode: false });
        }

        case 'overauth_issue_key': {
          if (!devOk(body)) return json(200, { ok: false, reason: 'invalid_credentials' });
          if (!body.p_key_id || !body.p_key_hash) return json(200, { ok: false, reason: 'invalid_request' });
          if (state.keys.some(k => k.key_id === body.p_key_id)) return json(200, { ok: false, reason: 'duplicate_key' });
          state.keys.push({
            key_id: body.p_key_id, key_hash: body.p_key_hash, owner_username: body.p_username,
            name: body.p_name || 'Untitled key', allowed_origins: body.p_allowed_origins || ['*'],
            scopes: body.p_scopes || ['profile', 'sessions'], is_active: true,
            expires_at: body.p_expires_at || null, created_at: new Date().toISOString(),
            last_used_at: null, use_count: 0
          });
          return json(200, { ok: true, key_id: body.p_key_id, id: crypto.randomUUID() });
        }

        case 'overauth_list_keys': {
          if (!devOk(body)) return json(200, { ok: false, reason: 'invalid_credentials' });
          return json(200, {
            ok: true,
            keys: state.keys.filter(k => k.owner_username === body.p_username).map(k => ({
              key_id: k.key_id, name: k.name, allowed_origins: k.allowed_origins, scopes: k.scopes,
              is_active: k.is_active, expires_at: k.expires_at, created_at: k.created_at,
              last_used_at: k.last_used_at, use_count: k.use_count,
              expired: !!(k.expires_at && new Date(k.expires_at) < new Date())
            }))
          });
        }

        case 'overauth_update_key': {
          if (!devOk(body)) return json(200, { ok: false, reason: 'invalid_credentials' });
          const k = state.keys.find(k => k.key_id === body.p_key_id && k.owner_username === body.p_username);
          if (!k) return json(200, { ok: false, reason: 'key_not_found' });
          if (body.p_name) k.name = body.p_name;
          if (body.p_allowed_origins) k.allowed_origins = body.p_allowed_origins;
          if (body.p_is_active !== null && body.p_is_active !== undefined) k.is_active = body.p_is_active;
          if (body.p_is_active === false) Object.values(state.sessions).forEach(s => { if (s.key_id === k.key_id) s.revoked = true; });
          return json(200, { ok: true });
        }

        case 'overauth_delete_key': {
          if (!devOk(body)) return json(200, { ok: false, reason: 'invalid_credentials' });
          state.keys = state.keys.filter(k => !(k.key_id === body.p_key_id && k.owner_username === body.p_username));
          Object.keys(state.sessions).forEach(t => { if (state.sessions[t].key_id === body.p_key_id) delete state.sessions[t]; });
          return json(200, { ok: true });
        }

        case 'overauth_stats': {
          if (!devOk(body)) return json(200, { ok: false, reason: 'invalid_credentials' });
          return json(200, {
            ok: true,
            keys: state.keys.filter(k => k.owner_username === body.p_username).length,
            active_keys: state.keys.filter(k => k.owner_username === body.p_username && k.is_active).length,
            verifications: state.keys.filter(k => k.owner_username === body.p_username).reduce((a, k) => a + k.use_count, 0),
            live_sessions: Object.values(state.sessions).filter(s => !s.revoked).length
          });
        }

        case 'overauth_verify': {
          const k = state.keys.find(k => k.key_id === String(body.p_key_id || '').trim());
          if (!k || k.key_hash !== body.p_key_hash) return json(200, { ok: false, reason: 'invalid_key' });
          if (!k.is_active) return json(200, { ok: false, reason: 'key_revoked', key_id: k.key_id });
          if (k.expires_at && new Date(k.expires_at) < new Date()) return json(200, { ok: false, reason: 'key_expired' });
          if (!originAllowed(k.allowed_origins, body.p_origin)) {
            return json(200, { ok: false, reason: 'origin_not_allowed', origin: body.p_origin, allowed_origins: k.allowed_origins });
          }
          const u = state.users[String(body.p_username || '').trim()];
          if (!u || sha256(u.password) !== body.p_password_hash) return json(200, { ok: false, reason: 'invalid_credentials' });
          if (u.is_banned) return json(200, { ok: false, reason: 'account_banned' });
          k.use_count += 1;
          k.last_used_at = new Date().toISOString();
          const user = { username: u.username };
          if (k.scopes.includes('profile') || k.scopes.includes('*')) user.created_at = u.created_at;
          if (k.scopes.includes('admin_flag') || k.scopes.includes('*')) user.is_admin = u.is_admin;
          const out = { ok: true, user, key: { key_id: k.key_id, name: k.name } };
          if (body.p_remember && (k.scopes.includes('sessions') || k.scopes.includes('*'))) {
            const token = crypto.randomBytes(18).toString('base64');
            state.sessions[token] = {
              key_id: k.key_id, username: u.username, origin: body.p_origin, revoked: false,
              expires_at: new Date(Date.now() + 30 * 864e5).toISOString()
            };
            out.session_token = token;
            out.session_expires_at = state.sessions[token].expires_at;
          }
          return json(200, out);
        }

        case 'overauth_session': {
          const s = state.sessions[body.p_token];
          if (!s || s.revoked || new Date(s.expires_at) < new Date()) return json(200, { ok: false, reason: 'invalid_session' });
          const k = state.keys.find(k => k.key_id === s.key_id);
          if (!k || !k.is_active) return json(200, { ok: false, reason: 'key_revoked' });
          const u = state.users[s.username];
          const user = { username: u.username };
          if (k.scopes.includes('profile')) user.created_at = u.created_at;
          return json(200, { ok: true, user, key: { key_id: k.key_id, name: k.name }, origin: s.origin, expires_at: s.expires_at });
        }

        case 'overauth_end_session': {
          if (state.sessions[body.p_token]) state.sessions[body.p_token].revoked = true;
          return json(200, { ok: true });
        }
      }
      return json(404, { code: 'PGRST202', message: 'Could not find the function public.' + fn });
    }

    // plain table select — the local-mode fallback path
    const tableMatch = /\/rest\/v1\/(\w+)\?(.*)$/.exec(url);
    if (tableMatch && tableMatch[1] === 'users') {
      const q = new URLSearchParams(tableMatch[2]);
      const uname = (q.get('username') || '').replace(/^eq\./, '');
      const phash = (q.get('password_hash') || '').replace(/^eq\./, '');
      const u = state.users[uname];
      if (u && sha256(u.password) === phash) {
        return json(200, [{ username: u.username, is_admin: u.is_admin, is_banned: u.is_banned, created_at: u.created_at }]);
      }
      return json(200, []);
    }

    if (/supabase\/overauth\.sql$/.test(url) || /overauth\.sql$/.test(url)) {
      return json(200, '-- overauth.sql mock contents');
    }

    return json(404, { message: 'not found' });
  };

  return state;
}

module.exports = { installDom, installMock, sha256, Node, originAllowed };
