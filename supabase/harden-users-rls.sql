-- ============================================================================
--  OPTIONAL — harden the Overmind `users` table
--  (not required for overAuth; run it only when you're ready)
-- ============================================================================
--
--  WHY
--  Right now anyone who has the public anon key (it is embedded in every page of
--  the site) can run:
--
--      GET /rest/v1/users?select=username,password_hash
--
--  and download every Overmind account's username + unsalted SHA-256 password
--  hash, then crack them offline on a GPU. This has nothing to do with overAuth —
--  it is how the project is set up today — but it is worth fixing.
--
--  THE FIX (2 steps)
--    step 1: run this file
--    step 2: change the login call in chat.html / experimental.html from a table
--            select to the RPC created below (see the snippet at the bottom).
--
--  ⚠️ If you run step 1 WITHOUT step 2, logging in on the Overmind site stops
--     working, because the app currently filters on `password_hash` itself.
--     overAuth keeps working either way — it never reads the table directly once
--     supabase/overauth.sql is installed.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. A safe login function the web app can call instead of reading the table
-- ---------------------------------------------------------------------------

create or replace function public.overmind_login(p_username text, p_password_hash text)
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  u record;
begin
  select * into u
  from public.users
  where username = btrim(coalesce(p_username, ''))
  limit 1;

  if u.username is null or u.password_hash is distinct from coalesce(p_password_hash, '') then
    return jsonb_build_object('ok', false, 'reason', 'invalid_credentials');
  end if;

  return jsonb_build_object(
    'ok', true,
    'username',      u.username,
    'is_admin',      coalesce(u.is_admin, false),
    'is_banned',     coalesce(u.is_banned, false),
    'message_limit', to_jsonb(u.message_limit),
    'shrek_mode',    coalesce(u.shrek_mode, false)
  );
end;
$$;

grant execute on function public.overmind_login(text, text) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- 2. Column-level privileges: everything except the password hash
-- ---------------------------------------------------------------------------

-- revoke the blanket SELECT, then hand back only the columns the app shows
revoke select on table public.users from anon, authenticated;

grant select (
  username,
  is_admin,
  is_banned,
  message_limit,
  shrek_mode,
  created_at
) on public.users to anon, authenticated;

-- Keep inserts working so registration from the site still succeeds.
-- (If registration is also broken for you, re-grant the columns it writes:)
grant insert (username, password_hash) on public.users to anon, authenticated;

-- The admin panel updates these; leave updates alone if that flow already works,
-- otherwise grant the specific columns:
grant update (is_admin, is_banned, message_limit, shrek_mode) on public.users to anon, authenticated;

-- SECURITY DEFINER functions run as the table owner (postgres), so overAuth and
-- overmind_login() can still see password_hash. Nothing else can.

-- ---------------------------------------------------------------------------
-- 3. Verify
-- ---------------------------------------------------------------------------
-- Should now FAIL with "permission denied for column password_hash":
--   GET /rest/v1/users?select=username,password_hash
-- Should still work:
--   GET /rest/v1/users?select=username,is_admin&limit=5
--   POST /rest/v1/rpc/overmind_login  {"p_username":"x","p_password_hash":"<sha256>"}

-- ---------------------------------------------------------------------------
-- 4. The matching change in the web app (chat.html / experimental.html)
-- ---------------------------------------------------------------------------
/*
  // BEFORE — inside handleLogin()
  const { data, error } = await supabaseClient
    .from('users')
    .select('username, is_admin, is_banned, message_limit, shrek_mode')
    .eq('username', username)
    .eq('password_hash', hash)
    .single();
  if (error || !data) { alert('Incorrect username or password.'); return; }

  // AFTER
  const { data: res, error } = await supabaseClient.rpc('overmind_login', {
    p_username: username,
    p_password_hash: hash
  });
  if (error || !res || !res.ok) { alert('Incorrect username or password.'); return; }
  const data = res;   // same fields as before: username, is_admin, is_banned, ...
*/

-- ---------------------------------------------------------------------------
-- 5. Rollback (if you need the old behaviour back)
-- ---------------------------------------------------------------------------
-- grant select on table public.users to anon, authenticated;
