/* End-to-end test for overauth.js (the SDK a developer embeds on their site).
   Run: node tests/overauth.test.js — no dependencies, no network. */
'use strict';
const assert = require('node:assert');
const { installDom, installMock, sha256 } = require('./harness');

installDom({ origin: 'https://novanotes.example', autoviv: true });
const mock = installMock();

const sdk = require('../overauth.js');
const U = sdk.utils;
const ORIGIN = 'https://novanotes.example';

let passed = 0;
const ok = (name) => { passed++; console.log('  ✓ ' + name); };
const tick = (ms) => new Promise(r => setTimeout(r, ms || 20));

(async function run() {
  console.log('\n— crypto —');
  assert.strictEqual(U.sha256Hex('wonderland'), sha256('wonderland'));
  assert.strictEqual(U.sha256Hex(''), sha256(''));
  assert.strictEqual(U.sha256Hex('x'.repeat(200)), sha256('x'.repeat(200)));
  ok('SHA-256 matches node:crypto (incl. padding edge lengths)');

  console.log('\n— key issuing (what the console does) —');
  const built = U.buildKey({ owner: 'alice', name: 'Nova Notes', origins: [ORIGIN, 'http://localhost:*'], scopes: ['profile', 'sessions'], mode: 'db' });
  assert.ok(/^oav1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(built.key), 'key shape');
  const issue = await U.rpc('overauth_issue_key', {
    p_username: 'alice', p_password_hash: sha256('wonderland'), p_name: 'Nova Notes',
    p_key_id: built.keyId, p_key_hash: built.keyHash,
    p_allowed_origins: [ORIGIN, 'http://localhost:*'], p_scopes: ['profile', 'sessions'], p_expires_at: null
  });
  assert.strictEqual(issue.data.ok, true);
  ok('a key can be issued with valid developer credentials');

  const badIssue = await U.rpc('overauth_issue_key', { p_username: 'alice', p_password_hash: sha256('wrong'), p_name: 'x', p_key_id: 'oak_x', p_key_hash: 'h' });
  assert.strictEqual(badIssue.data.reason, 'invalid_credentials');
  ok('issuing is rejected with a wrong developer password');

  const list = await U.rpc('overauth_list_keys', { p_username: 'alice', p_password_hash: sha256('wonderland') });
  assert.strictEqual(list.data.keys.length, 1);
  assert.strictEqual(list.data.keys[0].key_hash, undefined, 'the hash must never be sent back');
  ok('the key list contains no secret material');

  console.log('\n— DB mode: a visitor logging in —');
  const info = await sdk.init({ key: built.key, origin: ORIGIN });
  assert.strictEqual(info.ok, true);
  assert.strictEqual(info.backend, 'ready');
  assert.strictEqual(info.mode, 'db');
  assert.strictEqual(info.originAllowed, true);
  assert.strictEqual(info.owner, 'alice');
  ok('init reports backend ready, db mode, origin allowed');

  const res = await sdk.signIn('alice', 'wonderland');
  assert.strictEqual(res.ok, true, JSON.stringify(res));
  assert.strictEqual(res.mode, 'db');
  assert.strictEqual(res.user.username, 'alice');
  assert.strictEqual(res.user.created_at, mock.users.alice.created_at);
  assert.strictEqual(res.user.is_admin, undefined, 'admin_flag is not in scope');
  assert.ok(res.session_token && !res.session_token.startsWith('local_'));
  ok('signIn(alice) succeeds and returns a server session token');

  assert.ok(localStorage.getItem('overauth.session.' + built.keyId), 'session persisted');
  ok('the session is persisted for return visits');

  let session = await sdk.getSession();
  assert.strictEqual(session.ok, true);
  assert.strictEqual(session.cached, true);
  ok('getSession() restores the visitor without a network round trip');

  session = await sdk.getSession({ force: true });
  assert.strictEqual(session.ok, true);
  assert.strictEqual(session.mode, 'db');
  ok('getSession({force:true}) re-validates the token server-side');

  assert.deepStrictEqual(await sdk.checkCredentials('alice', 'nope'),
    { ok: false, reason: 'invalid_credentials', message: 'Incorrect username or password.', mode: 'db' });
  ok('a wrong password → invalid_credentials (+ human message)');

  assert.strictEqual((await sdk.checkCredentials('nobody', 'x')).reason, 'invalid_credentials');
  ok('an unknown username → invalid_credentials (not "no such user")');

  assert.strictEqual((await sdk.checkCredentials('bob', 'builder')).reason, 'account_banned');
  ok('a banned account → account_banned');

  assert.deepStrictEqual((await sdk.checkCredentials('', '')).reason, 'missing_credentials');
  ok('empty fields → missing_credentials');

  const adminKey = U.buildKey({ owner: 'root', origins: ['*'], scopes: ['profile', 'admin_flag'], mode: 'db' });
  await U.rpc('overauth_issue_key', { p_username: 'root', p_password_hash: sha256('toor123'), p_name: 'admin', p_key_id: adminKey.keyId, p_key_hash: adminKey.keyHash, p_allowed_origins: ['*'], p_scopes: ['profile', 'admin_flag'], p_expires_at: null });
  await sdk.init({ key: adminKey.key, origin: ORIGIN, storage: false });
  const adminRes = await sdk.checkCredentials('root', 'toor123');
  assert.strictEqual(adminRes.user.is_admin, true);
  assert.strictEqual(adminRes.session_token, undefined, 'no sessions scope → no token');
  ok('scopes are respected: admin_flag returns is_admin, no sessions → no token');

  console.log('\n— origin + revocation enforcement —');
  await sdk.init({ key: built.key, origin: 'https://evil.example' });
  const blocked = await sdk.checkCredentials('alice', 'wonderland');
  assert.strictEqual(blocked.reason, 'origin_not_allowed');
  assert.deepStrictEqual(blocked.allowed_origins, [ORIGIN, 'http://localhost:*']);
  ok('a key refuses an origin that is not allow-listed');

  await sdk.init({ key: built.key, origin: 'http://localhost:3000' });
  assert.strictEqual((await sdk.checkCredentials('alice', 'wonderland')).ok, true);
  ok('the localhost:* wildcard is accepted');

  await sdk.init({ key: built.key, origin: ORIGIN });
  await U.rpc('overauth_update_key', { p_username: 'alice', p_password_hash: sha256('wonderland'), p_key_id: built.keyId, p_name: null, p_allowed_origins: null, p_is_active: false });
  assert.strictEqual((await sdk.checkCredentials('alice', 'wonderland')).reason, 'key_revoked');
  assert.strictEqual((await U.rpc('overauth_session', { p_token: res.session_token })).data.ok, false);
  ok('pausing a key blocks new logins AND kills its live sessions');

  await U.rpc('overauth_update_key', { p_username: 'alice', p_password_hash: sha256('wonderland'), p_key_id: built.keyId, p_name: null, p_allowed_origins: null, p_is_active: true });
  assert.strictEqual((await sdk.checkCredentials('alice', 'wonderland')).ok, true);
  ok('resuming the key works again');

  await U.rpc('overauth_delete_key', { p_username: 'alice', p_password_hash: sha256('wonderland'), p_key_id: built.keyId });
  const deleted = await sdk.checkCredentials('alice', 'wonderland');
  assert.strictEqual(deleted.ok, false);
  assert.strictEqual(deleted.reason, 'invalid_key');
  assert.notStrictEqual(deleted.mode, 'local', 'a deleted key must not silently fall back to local mode');
  ok('deleting a key kills it for good (no local-mode resurrection)');
  await U.rpc('overauth_issue_key', { p_username: 'alice', p_password_hash: sha256('wonderland'), p_name: 'Nova Notes', p_key_id: built.keyId, p_key_hash: built.keyHash, p_allowed_origins: [ORIGIN, 'http://localhost:*'], p_scopes: ['profile', 'sessions'], p_expires_at: null });

  const expiredKey = U.buildKey({ owner: 'alice', origins: ['*'], expiresAt: Date.now() - 60000 });
  assert.strictEqual((await sdk.init({ key: expiredKey.key, origin: ORIGIN })).reason, 'key_expired');
  ok('an expired key is refused offline, before any request');

  const tampered = built.key.slice(0, -4) + 'AAAA';
  assert.strictEqual((await sdk.init({ key: tampered, origin: ORIGIN })).reason, 'invalid_key');
  assert.strictEqual((await sdk.init({ key: 'oav1_not.a.key.at.all', origin: ORIGIN })).reason, 'invalid_key');
  ok('a tampered or garbage key is refused');

  console.log('\n— sign out —');
  const reSigned = await sdk.signIn('alice', 'wonderland');
  const token = reSigned.session_token;
  const out = await sdk.signOut();
  assert.strictEqual(out.ok, true);
  assert.strictEqual(sdk.currentUser(), null);
  assert.strictEqual(localStorage.getItem('overauth.session.' + built.keyId), null);
  assert.strictEqual((await U.rpc('overauth_session', { p_token: token })).data.ok, false);
  ok('signOut clears local state and revokes the server session');

  console.log('\n— local mode (SQL not installed yet) —');
  mock.backendInstalled = false;
  mock.keys = [];
  await sdk.backendStatus(true);
  const localKey = U.buildKey({ owner: 'alice', origins: [ORIGIN], scopes: ['profile', 'sessions'], mode: 'local' });
  const linfo = await sdk.init({ key: localKey.key, origin: ORIGIN, storage: false });
  assert.strictEqual(linfo.backend, 'missing');
  assert.strictEqual(linfo.mode, 'local');
  ok('falls back to local mode when the SQL functions are missing');

  const lres = await sdk.signIn('alice', 'wonderland');
  assert.strictEqual(lres.ok, true);
  assert.strictEqual(lres.mode, 'local');
  assert.strictEqual(lres.user.username, 'alice');
  assert.ok(String(lres.session_token).startsWith('local_'));
  ok('local mode verifies credentials against the users table');

  assert.strictEqual((await sdk.checkCredentials('alice', 'wrong')).reason, 'invalid_credentials');
  ok('local mode rejects a wrong password');

  await sdk.init({ key: localKey.key, origin: 'https://other.example', storage: false });
  assert.strictEqual((await sdk.checkCredentials('alice', 'wonderland')).reason, 'origin_not_allowed');
  ok('local mode enforces the origin allow-list offline');

  console.log('\n— graceful degradation —');
  mock.backendInstalled = true;
  await sdk.backendStatus(true);
  mock.backendInstalled = false; // functions vanish mid-session
  await sdk.init({ key: localKey.key, origin: ORIGIN, storage: false });
  const degrade = await sdk.checkCredentials('alice', 'wonderland');
  assert.strictEqual(degrade.ok, true, JSON.stringify(degrade));
  assert.strictEqual(degrade.mode, 'local');
  ok('a missing RPC mid-flight degrades to local verification instead of failing');
  mock.backendInstalled = true;
  await sdk.backendStatus(true);

  console.log('\n— transport failures —');
  mock.networkDown = true;
  assert.strictEqual((await sdk.checkCredentials('alice', 'wonderland')).reason, 'network_error');
  mock.networkDown = false;
  ok('a network failure surfaces as network_error, not a crash');

  console.log('\n— widget —');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const widgetKey = U.buildKey({ owner: 'alice', origins: ['*'], scopes: ['profile', 'sessions'], mode: 'db' });
  await U.rpc('overauth_issue_key', { p_username: 'alice', p_password_hash: sha256('wonderland'), p_name: 'widget', p_key_id: widgetKey.keyId, p_key_hash: widgetKey.keyHash, p_allowed_origins: ['*'], p_scopes: ['profile', 'sessions'], p_expires_at: null });
  await sdk.init({ key: widgetKey.key, origin: ORIGIN, storage: false });

  let successEvent = null;
  const events = [];
  sdk.onAuthChange(e => events.push(e.type));
  const widget = sdk.mount(host, { theme: 'light', accent: '#5b57d8', onSuccess: r => { successEvent = r; } });
  assert.ok(widget, 'mount returns a widget');
  assert.strictEqual(host.querySelectorAll('input').length, 2, 'username + password inputs');
  assert.ok(host.querySelector('form'), 'form rendered');
  assert.ok(host.querySelector('.omauth-card'), 'card rendered');
  assert.strictEqual(host.getAttribute('data-x'), null);
  assert.ok(document.head.querySelector('[data-overauth]'), 'widget CSS injected once');
  ok('mount renders a themed card with username + password fields');

  const inputs = host.querySelectorAll('input');
  inputs[0].value = 'alice';
  inputs[1].value = 'wonderland';
  let prevented = false;
  host.querySelector('form').dispatchEvent({ type: 'submit', preventDefault: () => { prevented = true; } });
  assert.strictEqual(prevented, true, 'submit is intercepted');
  await tick(30);
  assert.ok(successEvent && successEvent.ok, 'onSuccess fired');
  assert.ok(host.querySelector('.omauth-avatar'), 'signed-in view rendered');
  const nameNode = host.querySelector('.omauth-user-name');
  assert.ok(nameNode && nameNode.textContent === 'alice', 'username shown');
  assert.ok(!host.querySelector('form'), 'the password form is gone once signed in');
  assert.ok(events.includes('SIGNED_IN'), 'onAuthChange fired SIGNED_IN');
  ok('submitting the widget signs the visitor in and flips to the signed-in view');

  const outBtn = host.querySelector('.omauth-btn-ghost');
  assert.ok(outBtn, 'sign-out button rendered');
  outBtn.dispatchEvent({ type: 'click' });
  await tick(20);
  assert.ok(host.querySelector('form'), 'back to the login form after sign out');
  assert.ok(events.includes('SIGNED_OUT'), 'onAuthChange fired SIGNED_OUT');
  ok('signing out returns the widget to the login form');

  const btnHost = document.createElement('div');
  document.body.appendChild(btnHost);
  const btnWidget = sdk.renderButton(btnHost, { theme: 'dark' });
  assert.ok(btnWidget.button, 'button rendered');
  btnWidget.button.dispatchEvent({ type: 'click' });
  await tick();
  assert.ok(document.body.querySelector('.omauth-overlay'), 'modal opened');
  assert.ok(document.body.querySelector('.omauth-overlay form'), 'modal contains a login form');
  document.body.querySelector('.omauth-close').dispatchEvent({ type: 'click' });
  await tick();
  assert.strictEqual(document.body.querySelector('.omauth-overlay'), null, 'modal closed');
  ok('renderButton opens a modal login and closes it again');

  const errHost = document.createElement('div');
  document.body.appendChild(errHost);
  sdk.mount(errHost, {});
  const eInputs = errHost.querySelectorAll('input');
  eInputs[0].value = 'alice';
  eInputs[1].value = 'wrongpass';
  errHost.querySelector('form').dispatchEvent({ type: 'submit', preventDefault: () => {} });
  await tick(30);
  const errBox = errHost.querySelector('.omauth-error');
  assert.ok(errBox && !errBox.classList.contains('omauth-hidden'), 'error box visible');
  assert.ok(/Incorrect username or password/.test(errBox.textContent), 'friendly message: ' + errBox.textContent);
  ok('a failed login shows a friendly inline error');

  sdk.unmount(errHost);
  assert.strictEqual(errHost.querySelectorAll('input').length, 0);
  ok('unmount() clears the container');

  console.log('\nAll ' + passed + ' SDK checks passed ✅\n');
})().catch(e => { console.error('\n❌ FAILED:', (e && e.stack) || e); process.exit(1); });
