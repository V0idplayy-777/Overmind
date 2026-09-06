/* Drives the pretend third-party site (overauth-demo.html) end to end.
   Run: node tests/demo.test.js */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync } = require('node:child_process');
const assert = require('node:assert');
const { installDom, installMock, sha256 } = require('./harness');

const ROOT = path.join(__dirname, '..');
const page = path.join(ROOT, 'overauth-demo.html');
const html = fs.readFileSync(page, 'utf8');
const dom = JSON.parse(execFileSync('python3', [path.join(__dirname, 'build-dom.py'), page], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }));

const SITE_ORIGIN = 'https://v0idplayy-777.github.io';
installDom({ dom, origin: SITE_ORIGIN });
const mock = installMock();

vm.runInThisContext(fs.readFileSync(path.join(ROOT, 'overauth.js'), 'utf8'), { filename: 'overauth.js' });
const sdk = globalThis.OvermindAuth;

const $ = (id) => document.getElementById(id);
const tick = (ms) => new Promise(r => setTimeout(r, ms || 15));
async function until(fn, label, timeout) {
  const deadline = Date.now() + (timeout || 4000);
  while (Date.now() < deadline) {
    try { if (fn()) return true; } catch (e) { /* keep polling */ }
    await tick(10);
  }
  throw new Error('timed out waiting for: ' + label);
}
let passed = 0;
const ok = (n) => { passed++; console.log('  ✓ ' + n); };

(async function runTests() {
  // A developer created this key for the demo site's origin.
  const built = sdk.utils.buildKey({
    owner: 'alice', name: 'Nova Notes', origins: [SITE_ORIGIN], scopes: ['profile', 'sessions'], mode: 'db'
  });
  await sdk.utils.rpc('overauth_issue_key', {
    p_username: 'alice', p_password_hash: sha256('wonderland'), p_name: 'Nova Notes',
    p_key_id: built.keyId, p_key_hash: built.keyHash,
    p_allowed_origins: [SITE_ORIGIN], p_scopes: ['profile', 'sessions'], p_expires_at: null
  });

  console.log('\n— demo site loads with ?key= —');
  globalThis.location.search = '?key=' + encodeURIComponent(built.key);
  const inline = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n;\n');
  vm.runInThisContext(inline, { filename: 'overauth-demo.html(inline)' });

  await until(() => $('overmind-login').querySelector('form'), 'login widget mounted');
  ok('the drop-in widget mounted itself from the URL key');
  assert.strictEqual(localStorage.getItem('overauth.demo.key'), built.key, 'key remembered for the next visit');
  assert.ok($('key-info').innerHTML.includes(built.keyId), 'key details decoded on the page');
  assert.ok($('key-info').innerHTML.includes('<span>origin ok</span><span>yes</span>'), 'origin shown as allowed: ' + $('key-info').innerHTML);
  assert.ok($('page-code').textContent.includes('data-container="#overmind-login"'), 'the page shows its own integration snippet');
  ok('the page explains itself and shows the snippet it uses');

  assert.ok($('header-button').querySelector('.omauth-btn'), 'header button rendered');
  ok('a header “Continue with Overmind” button rendered too');

  console.log('\n— visitor signs in —');
  assert.ok($('note-list').classList.contains('locked'), 'content starts locked');
  const inputs = $('overmind-login').querySelectorAll('input');
  inputs[0].value = 'alice';
  inputs[1].value = 'wonderland';
  $('overmind-login').querySelector('form').dispatchEvent({ type: 'submit', preventDefault() {} });
  await until(() => !$('note-list').classList.contains('locked'), 'notes unlocked');

  assert.strictEqual($('state-badge').textContent, 'unlocked');
  assert.ok($('who').innerHTML.includes('alice'), 'header shows who is signed in');
  assert.strictEqual($('signed-in-extra').style.display, 'block');
  const raw = JSON.parse($('raw').textContent);
  assert.strictEqual(raw.ok, true);
  assert.strictEqual(raw.user.username, 'alice');
  assert.ok(raw.session_token, 'session token issued');
  assert.ok(/session token/.test($('session-kv').innerHTML), 'session details shown');
  ok('signing in unlocks the site and prints the raw overAuth response');
  assert.strictEqual(mock.keys[0].use_count, 1, 'the developer can see this login in their console');
  ok('the login is counted against the developer’s key');

  console.log('\n— wrong password on the demo site —');
  $('signout-btn').dispatchEvent({ type: 'click' });
  await until(() => $('note-list').classList.contains('locked'), 'locked again');
  assert.strictEqual($('state-badge').textContent, 'locked');
  ok('signing out locks the site again');

  const inputs2 = $('overmind-login').querySelectorAll('input');
  inputs2[0].value = 'alice';
  inputs2[1].value = 'not-my-password';
  $('overmind-login').querySelector('form').dispatchEvent({ type: 'submit', preventDefault() {} });
  await until(() => {
    const box = $('overmind-login').querySelector('.omauth-error');
    return box && !box.classList.contains('omauth-hidden');
  }, 'error shown');
  assert.match($('overmind-login').querySelector('.omauth-error').textContent, /Incorrect username or password/);
  assert.ok($('note-list').classList.contains('locked'), 'still locked');
  ok('a wrong password shows an inline error and keeps the site locked');

  console.log('\n— key from another origin is refused —');
  localStorage.clear();
  Object.keys(mock.sessions).forEach(t => delete mock.sessions[t]);
  const foreign = sdk.utils.buildKey({ owner: 'alice', origins: ['https://somewhere-else.example'], scopes: ['profile'], mode: 'db' });
  await sdk.utils.rpc('overauth_issue_key', {
    p_username: 'alice', p_password_hash: sha256('wonderland'), p_name: 'other site',
    p_key_id: foreign.keyId, p_key_hash: foreign.keyHash,
    p_allowed_origins: ['https://somewhere-else.example'], p_scopes: ['profile'], p_expires_at: null
  });
  const res = await sdk.init({ key: foreign.key, origin: SITE_ORIGIN, storage: false });
  assert.strictEqual(res.originAllowed, false);
  const denied = await sdk.checkCredentials('alice', 'wonderland');
  assert.strictEqual(denied.ok, false);
  assert.strictEqual(denied.reason, 'origin_not_allowed');
  ok('a key scoped to another website cannot be used here');

  console.log('\nAll ' + passed + ' demo-site checks passed ✅\n');
})().catch(e => { console.error('\n❌ FAILED:', (e && e.stack) || e); process.exit(1); });
