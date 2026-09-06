/* Drives the developer console (overauth.html) headlessly against the mocked
   Supabase backend: real markup, real page script, real SDK.
   Run: node tests/console.test.js */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync } = require('node:child_process');
const assert = require('node:assert');
const { installDom, installMock } = require('./harness');

const ROOT = path.join(__dirname, '..');
const htmlPath = path.join(ROOT, 'overauth.html');
const html = fs.readFileSync(htmlPath, 'utf8');

// real markup -> shim DOM
const dom = JSON.parse(execFileSync('python3', [path.join(__dirname, 'build-dom.py'), htmlPath], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }));
const { missingIds } = installDom({ dom, origin: 'https://v0idplayy-777.github.io' });
const mock = installMock();

// load overauth.js the way a browser would (as a classic script -> global)
vm.runInThisContext(fs.readFileSync(path.join(ROOT, 'overauth.js'), 'utf8'), { filename: 'overauth.js' });
assert.ok(globalThis.OvermindAuth, 'overauth.js should define window.OvermindAuth');

// run the console's inline script
const inline = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n;\n');
vm.runInThisContext(inline, { filename: 'overauth.html(inline)' });

const run = (code) => vm.runInThisContext(code);
const $ = (id) => document.getElementById(id);
const tick = (ms) => new Promise(r => setTimeout(r, ms || 15));

async function until(fn, label, timeout) {
  const deadline = Date.now() + (timeout || 4000);
  while (Date.now() < deadline) {
    let v;
    try { v = fn(); } catch (e) { v = false; }
    if (v) return v;
    await tick(10);
  }
  throw new Error('timed out waiting for: ' + label);
}

let passed = 0;
const ok = (name) => { passed++; console.log('  ✓ ' + name); };

(async function runTests() {
  console.log('\n— page boot —');
  await until(() => run('backend') === 'ready', 'backend status');
  assert.deepStrictEqual(missingIds, [], 'getElementById() was called for ids that are not in the markup: ' + missingIds.join(', '));
  ok('boots with no unknown element ids (no typos in the markup)');
  assert.strictEqual($('backend-chip').classList.contains('ok'), true);
  assert.strictEqual($('backend-chip-text').textContent, 'backend ready');
  assert.ok(/installed/i.test($('setup-msg').innerHTML), 'setup panel explains the installed state');
  ok('status chip + setup panel report “backend ready”');
  assert.ok(/oav1_YOUR_KEY_HERE/.test($('snippet-widget').textContent), 'snippets render before any key exists');
  ok('code snippets render a placeholder before a key exists');
  assert.ok($('preview-card').querySelector('.omauth-card'), 'widget preview mounted with a demo key');
  ok('the widget preview renders on load');

  console.log('\n— developer sign in —');
  assert.strictEqual($('signin-done').classList.contains('hidden'), true, 'account panel hidden while signed out');
  assert.strictEqual($('create-locked').classList.contains('hidden'), false, 'create panel locked while signed out');

  $('dev-username').value = 'alice';
  $('dev-password').value = 'definitely-wrong';
  run('devSignIn()');
  await until(() => !$('signin-error').classList.contains('hidden'), 'sign-in error');
  assert.match($('signin-error').textContent, /Incorrect username or password/);
  ok('a wrong password is rejected with a clear message');

  $('dev-password').value = 'wonderland';
  run('devSignIn()');
  await until(() => run('dev') !== null, 'dev session');
  assert.strictEqual(run('dev.username'), 'alice');
  assert.strictEqual($('dev-name').textContent, 'alice');
  assert.strictEqual($('signin-form').classList.contains('hidden'), true);
  assert.strictEqual($('signin-done').classList.contains('hidden'), false);
  assert.strictEqual($('create-form').classList.contains('hidden'), false);
  assert.strictEqual(sessionStorage.getItem('overmind.dev.session') !== null, true, 'dev session kept for this tab');
  ok('signing in unlocks the console and remembers the tab session');

  console.log('\n— creating a key —');
  $('key-name').value = 'Nova Notes (prod)';
  $('key-origins').value = 'https://novanotes.example\nhttp://localhost:*\n';
  $('scope-admin').checked = true;
  $('key-expiry').value = '90';
  run('createKey()');
  await until(() => !$('key-reveal').classList.contains('hidden'), 'key reveal');

  const rawKey = $('reveal-key').textContent;
  assert.match(rawKey, /^oav1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, 'a real overAuth key was generated');
  assert.strictEqual(mock.keys.length, 1, 'the key hash was stored server-side');
  assert.strictEqual(mock.keys[0].name, 'Nova Notes (prod)');
  assert.deepStrictEqual(mock.keys[0].allowed_origins, ['https://novanotes.example', 'http://localhost:*']);
  assert.deepStrictEqual(mock.keys[0].scopes, ['profile', 'sessions', 'admin_flag']);
  assert.ok(mock.keys[0].expires_at, 'expiry applied');
  assert.ok(!Object.values(mock.keys[0]).some(v => typeof v === 'string' && v.startsWith('oav1_')), 'the raw key is never stored server-side');
  ok('key created server-side with name, origins, scopes and expiry — raw key never stored');

  const vault = JSON.parse(localStorage.getItem('overauth.console.vault'));
  assert.strictEqual(vault.length, 1);
  assert.strictEqual(vault[0].key, rawKey, 'this browser keeps a copy so it can be re-copied');
  ok('the browser keeps a private copy for the “Copy key” button');

  const listHtml = $('keys-list').innerHTML;
  assert.ok(listHtml.includes('Nova Notes (prod)'), 'key listed');
  assert.ok(listHtml.includes('live'), 'status pill rendered');
  assert.ok(listHtml.includes('https://novanotes.example'), 'origins shown');
  ok('the key shows up in “Your keys” with its state and origins');

  console.log('\n— generated snippets —');
  assert.strictEqual($('snippet-key').value, mock.keys[0].key_id, 'newest key preselected');
  const widgetSnippet = $('snippet-widget').textContent;
  assert.ok(widgetSnippet.includes('<div id="overmind-login"></div>'));
  assert.ok(widgetSnippet.includes('https://v0idplayy-777.github.io/Overmind/overauth.js'));
  assert.ok(widgetSnippet.includes('data-key="' + rawKey + '"'), 'the real key is embedded');
  assert.ok(/<\/script>/.test(widgetSnippet), 'the copied snippet must contain a real closing script tag');
  // ...while the page source keeps it escaped so the console page itself parses
  const inlineScript = html.slice(html.lastIndexOf('<script>'), html.lastIndexOf('</' + 'script>'));
  assert.ok(!/<\/script>/.test(inlineScript.replace(/<\\\/script>/g, '')), 'the page source must escape </script> inside strings');
  assert.ok(/data-redirect/.test(widgetSnippet));
  ok('drop-in widget snippet contains the container, the SDK URL and the key');

  const apiSnippet = $('snippet-api').textContent;
  assert.ok(/OvermindAuth\.init\(\{ key: 'oav1_/.test(apiSnippet));
  assert.ok(/OvermindAuth\.signIn\(/.test(apiSnippet));
  assert.ok(/result\.reason/.test(apiSnippet) && /result\.message/.test(apiSnippet));
  ok('“your own form” snippet shows init + signIn + error handling');

  const restSnippet = $('snippet-rest').textContent;
  assert.ok(restSnippet.includes('/rest/v1/rpc/overauth_verify'));
  assert.ok(restSnippet.includes('"p_key_id":        "' + mock.keys[0].key_id + '"'));
  assert.ok(restSnippet.includes('"p_key_hash":      "' + require('node:crypto').createHash('sha256').update(rawKey, 'utf8').digest('hex') + '"'), 'hash precomputed for server-side use');
  ok('REST snippet is ready to paste into any backend, hash included');

  const nodeSnippet = $('snippet-node').textContent;
  assert.ok(/overauth_session/.test(nodeSnippet) && /createHash\('sha256'\)/.test(nodeSnippet));
  ok('Node snippet covers login + session re-validation');

  console.log('\n— built-in tester —');
  $('test-user').value = 'alice';
  $('test-pass').value = 'wonderland';
  $('test-origin').value = 'https://novanotes.example';
  run('runTest()');
  await until(() => $('test-verdict').classList.contains('show'), 'test verdict');
  assert.ok(/Login accepted/.test($('test-verdict').innerHTML), $('test-verdict').innerHTML);
  assert.ok(/"ok": true/.test($('test-output').textContent));
  assert.strictEqual(mock.keys[0].use_count, 1, 'the verify call was counted');
  ok('a correct username/password is accepted (and counted)');

  $('test-pass').value = 'nope';
  run('runTest()');
  await until(() => /invalid_credentials/.test($('test-output').textContent), 'rejection');
  assert.ok(/Rejected/.test($('test-verdict').innerHTML));
  ok('a wrong password is rejected in the tester');

  $('test-pass').value = 'wonderland';
  $('test-origin').value = 'https://evil.example';
  run('runTest()');
  await until(() => /origin_not_allowed/.test($('test-output').textContent), 'origin rejection');
  ok('a foreign origin is rejected (origin_not_allowed)');

  $('test-origin').value = 'http://localhost:5173';
  run('runTest()');
  await until(() => /"ok": true/.test($('test-output').textContent), 'localhost accepted');
  ok('the localhost:* wildcard passes');

  console.log('\n— managing the key —');
  $('test-origin').value = 'https://novanotes.example';
  run('toggleKey(' + JSON.stringify(mock.keys[0].key_id) + ', true)');
  await until(() => mock.keys[0].is_active === false, 'pause');
  run('runTest()');
  await until(() => /key_revoked/.test($('test-output').textContent), 'revoked rejection');
  ok('pausing a key immediately blocks logins with it');

  run('toggleKey(' + JSON.stringify(mock.keys[0].key_id) + ', false)'); // Resume button passes pause=false
  await until(() => mock.keys[0].is_active === true, 'resume');
  run('runTest()');
  await until(() => /"ok": true/.test($('test-output').textContent), 'login works again');
  ok('resuming it works again');

  run('openEdit(' + JSON.stringify(mock.keys[0].key_id) + ')');
  assert.strictEqual($('edit-modal').classList.contains('open'), true);
  assert.strictEqual($('edit-name').value, 'Nova Notes (prod)');
  $('edit-name').value = 'Renamed';
  $('edit-origins').value = 'https://renamed.example';
  run('saveEdit()');
  await until(() => mock.keys[0].name === 'Renamed', 'rename');
  assert.deepStrictEqual(mock.keys[0].allowed_origins, ['https://renamed.example']);
  ok('a key can be renamed and re-scoped to new origins');

  console.log('\n— stats + refresh —');
  run('loadStats()');
  await until(() => $('stat-keys').textContent === '1' &&
                    Number($('stat-uses').textContent) === mock.keys[0].use_count, 'stats');
  assert.ok(mock.keys[0].use_count >= 3, 'only successful logins are counted: ' + mock.keys[0].use_count);
  ok('the console shows the key count and how many logins it verified');

  console.log('\n— deleting a key —');
  run('deleteKey(' + JSON.stringify(mock.keys[0].key_id) + ')');
  await until(() => mock.keys.length === 0 && localStorage.getItem('overauth.console.vault') === '[]', 'delete');
  assert.strictEqual(localStorage.getItem('overauth.console.vault'), '[]', 'local copy removed too');
  assert.ok(/No keys yet/.test($('keys-list').innerHTML));
  ok('deleting removes it server-side and from this browser');

  console.log('\n— local mode (no SQL installed) —');
  mock.backendInstalled = false;
  run('checkBackend(true)');
  await until(() => run('backend') === 'missing', 'local mode detected');
  assert.strictEqual($('backend-chip').classList.contains('warn'), true);
  assert.strictEqual($('backend-chip-text').textContent, 'local mode');
  assert.ok(/local mode/i.test($('setup-msg').innerHTML));
  ok('the console detects a missing backend and explains local mode');

  $('key-name').value = 'Quick test';
  $('key-origins').value = '*';
  run('createKey()');
  await until(() => /Quick test/.test($('keys-list').innerHTML), 'local key listed');
  const localKey = $('reveal-key').textContent;
  assert.ok(localKey.startsWith('oav1_'), 'a real key was generated');
  assert.strictEqual(mock.keys.length, 0, 'nothing written to a backend that does not exist');
  assert.ok(/pill local/.test($('keys-list').innerHTML), 'flagged as a local-mode key');
  ok('keys can still be created with no backend at all');

  run('useInTester(' + JSON.stringify(localKey) + ')');
  $('test-user').value = 'alice';
  $('test-pass').value = 'wonderland';
  $('test-origin').value = 'https://anything.example';
  run('runTest()');
  await until(() => /"ok": true/.test($('test-output').textContent), 'local verify');
  assert.ok(/"mode": "local"/.test($('test-output').textContent));
  ok('logins verify against the Overmind users table in local mode');

  $('test-pass').value = 'wrong';
  run('runTest()');
  await until(() => /invalid_credentials/.test($('test-output').textContent), 'local rejection');
  ok('wrong passwords still fail in local mode');

  console.log('\n— upgrading local keys to the backend —');
  const localKeyId = JSON.parse(localStorage.getItem('overauth.console.vault'))[0].keyId;
  const localRaw = JSON.parse(localStorage.getItem('overauth.console.vault'))[0].key;
  mock.backendInstalled = true;
  run('checkBackend(true)');
  await until(() => run('backend') === 'ready', 'backend back');
  run('loadKeys()');
  await until(() => mock.keys.length === 1, 'local key migrated into the backend');
  assert.strictEqual(mock.keys[0].key_id, localKeyId, 'same key id — the key string did not change');
  assert.strictEqual(mock.keys[0].key_hash, require('node:crypto').createHash('sha256').update(localRaw, 'utf8').digest('hex'), 'only the hash is stored');
  assert.strictEqual(mock.keys[0].name, 'Quick test');
  assert.deepStrictEqual(mock.keys[0].allowed_origins, ['*']);
  await until(() => !/pill local/.test($('keys-list').innerHTML), 'no longer flagged local');
  ok('installing the SQL upgrades existing local keys without changing them');

  // and the very same key still verifies, now through the backend
  run('useInTester(' + JSON.stringify(localRaw) + ')');
  $('test-user').value = 'alice';
  $('test-pass').value = 'wonderland';
  $('test-origin').value = 'https://anything.example';
  run('runTest()');
  await until(() => /"mode": "db"/.test($('test-output').textContent), 'db verify');
  assert.ok(/"ok": true/.test($('test-output').textContent));
  ok('the migrated key now verifies through the backend (db mode)');

  console.log('\n— sign out —');
  run('devSignOut()');
  await tick();
  assert.strictEqual(run('dev'), null);
  assert.strictEqual(sessionStorage.getItem('overmind.dev.session'), null);
  assert.strictEqual($('signin-form').classList.contains('hidden'), false);
  assert.strictEqual($('create-form').classList.contains('hidden'), true);
  ok('signing out clears the session and locks the console again');

  console.log('\nAll ' + passed + ' console checks passed ✅\n');
})().catch(e => {
  console.error('\n❌ FAILED:', (e && e.stack) || e);
  if (missingIds.length) console.error('   (unknown element ids seen: ' + missingIds.join(', ') + ')');
  process.exit(1);
});
