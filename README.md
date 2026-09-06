# Overmind

https://v0idplayy-777.github.io/Overmind/

A static site (GitHub Pages, no build step) plus a Supabase project.

| Page | What it is |
| --- | --- |
| `index.html` | Landing page |
| `chat` (`chat.html`) | The Overmind chat app — accounts, chat history, admin panel |
| `experimental.html` / `testing123.html` | Experimental builds of the chat app |
| **`overauth.html`** | **overAuth 1.0 developer console — “Sign in with Overmind” for other websites** |
| `overauth-demo.html` | A pretend third-party site, used to test a key end to end |
| `overauth.js` | The SDK other sites embed |
| `supabase/overauth.sql` | One-time backend install for overAuth |
| `supabase/harden-users-rls.sql` | Optional: stop the anon key from reading password hashes |

Accounts live in the Supabase `users` table as `username` + unsalted SHA-256 `password_hash`.

---

## overAuth 1.0 — let other sites use Overmind logins

A developer signs in to <https://v0idplayy-777.github.io/Overmind/overauth.html> with their normal
Overmind account, creates an **overAuth key**, and pastes a snippet into their own website. Their
visitors can then log in with the Overmind username and password they already have.

### For a developer using it

```html
<!-- 1) where the login box goes -->
<div id="overmind-login"></div>

<!-- 2) before </body> -->
<script src="https://v0idplayy-777.github.io/Overmind/overauth.js"
        data-key="oav1_..."
        data-container="#overmind-login"
        data-theme="dark"
        data-redirect="/dashboard.html"></script>
```

Or keep your own form and just check the credentials:

```js
OvermindAuth.init({ key: 'oav1_...' });

const result = await OvermindAuth.signIn(username, password);
if (result.ok) {
  console.log(result.user.username, result.session_token);
} else {
  console.log(result.reason, result.message); // invalid_credentials, key_revoked, origin_not_allowed, ...
}
```

Also available: `checkCredentials()`, `getSession()`, `signOut()`, `currentUser()`,
`onAuthChange()`, `mount()`, `renderButton()`, `backendStatus()`. The same check is a plain HTTPS
POST to `overauth_verify` if you'd rather do it from PHP/Python/Go/Node — the console generates that
snippet too, with your key hash pre-filled.

Keys carry an **origin allow-list** (`https://example.com`, `https://*.example.com`,
`http://localhost:*`, or `*`), **scopes** (`profile`, `sessions`, `admin_flag`) and an optional
**expiry**. They can be paused, renamed, re-scoped and deleted from the console; deleting or pausing
a key also revokes every session it issued.

### Backend install (one time, optional but recommended)

Supabase dashboard → **SQL Editor** → paste [`supabase/overauth.sql`](supabase/overauth.sql) → **Run**.

That adds `overauth_keys`, `overauth_sessions` and the `overauth_*` functions. Both tables have RLS
enabled with **no** anon policies — every access goes through `SECURITY DEFINER` functions that check
the key hash, the origin and the account themselves. Only a SHA-256 hash of each key is stored.

Without it, overAuth still works in **local mode**: keys are signed self-contained tokens and logins
are checked straight against the `users` table. Local-mode keys live in the browser that created them,
can't be revoked, and have no server-side sessions — the console tells you which mode you're in.

### Security notes (read these)

* Overmind hashes passwords with **unsalted SHA-256**, so a hash is password-equivalent. Always use
  HTTPS, never log the hash, never put it in a URL.
* The Supabase `anon` key is public (it ships inside the site), so all enforcement is in RLS and the
  SQL functions — not in the key.
* Origin checks run in the browser, so they stop casual abuse, not a determined attacker. For hard
  enforcement, call `overauth_verify` from your own server.
* No rate limiting is built in.
* ⚠️ As of now, anyone with the anon key can read `users.password_hash` for every account. That
  predates overAuth. [`supabase/harden-users-rls.sql`](supabase/harden-users-rls.sql) fixes it with
  column-level grants + an `overmind_login()` RPC — read its warnings first, because the chat app's
  login call has to change at the same time.

### Tests

No npm install, no network — just Node 18+ and python3 (used to parse the pages into a shim DOM):

```sh
sh tests/run-all.sh
```

* `tests/overauth.test.js` — the SDK: crypto vs `node:crypto`, key signing/tampering/expiry, DB mode,
  local mode, origin + revocation enforcement, sessions, and the widget UI.
* `tests/console.test.js` — drives `overauth.html` itself: sign-in, key creation, snippet generation,
  the built-in tester, pause/rename/delete, stats, local mode. Fails if the page references an element
  id that isn't in the markup.
* `tests/demo.test.js` — drives `overauth-demo.html` as a visitor of a third-party site.
* `tests/harness.js` — the DOM shim and the mocked Supabase (tables + `overauth_*` functions).
