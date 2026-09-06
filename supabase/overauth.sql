-- ============================================================================
--  overAuth 1.0 — backend for "Sign in with Overmind"
--  https://v0idplayy-777.github.io/Overmind/overauth.html
--
--  HOW TO INSTALL (one time, ~30 seconds)
--    1. Open your Supabase project → SQL Editor → New query
--    2. Paste this whole file → Run
--    3. Reload the overAuth developer console — the status chip turns green.
--
--  It is safe to run more than once (everything is IF NOT EXISTS / OR REPLACE).
--
--  What it creates:
--    public.overauth_keys      issued developer keys (stores only a SHA-256 hash)
--    public.overauth_sessions  login sessions minted for visitors of dev sites
--    public.overauth_*()       the RPC functions overauth.js talks to
--
--  Security model: both tables have RLS enabled with **no** anon policies, so
--  nobody can read or write them directly with the public anon key. All access
--  goes through the SECURITY DEFINER functions below, which check the key hash,
--  the allowed origins and the Overmind username/password hash themselves.
-- ============================================================================

-- pgcrypto is already enabled on Supabase; this is a no-op there and is wrapped
-- so it can never be the reason the script fails.
do $$
begin
  create extension if not exists pgcrypto;
exception when others then
  null;
end
$$;

-- ---------------------------------------------------------------------------
-- 1. Tables
-- ---------------------------------------------------------------------------

create table if not exists public.overauth_keys (
  id               uuid        primary key default gen_random_uuid(),
  key_id           text        not null unique,             -- public id, embedded in the key (oak_...)
  key_hash         text        not null unique,             -- sha256 hex of the full key; the key itself is never stored
  owner_username   text        not null,                    -- Overmind account that owns the key
  name             text        not null default 'Untitled key',
  allowed_origins  text[]      not null default array['*'], -- e.g. {https://example.com, https://*.myapp.dev}
  scopes           text[]      not null default array['profile','sessions'],
  is_active        boolean     not null default true,
  expires_at       timestamptz,
  created_at       timestamptz not null default now(),
  last_used_at     timestamptz,
  use_count        bigint      not null default 0
);

create index if not exists overauth_keys_owner_idx on public.overauth_keys (owner_username);

create table if not exists public.overauth_sessions (
  id             text        primary key default replace(gen_random_uuid()::text, '-', ''),
  key_id         text        not null,
  username       text        not null,
  origin         text,
  created_at     timestamptz not null default now(),
  last_seen_at   timestamptz not null default now(),
  expires_at     timestamptz not null default (now() + interval '30 days'),
  revoked        boolean     not null default false
);

create index if not exists overauth_sessions_key_idx on public.overauth_sessions (key_id);
create index if not exists overauth_sessions_user_idx on public.overauth_sessions (username);

-- Locked down: no policies at all, only the functions below can touch these.
alter table public.overauth_keys     enable row level security;
alter table public.overauth_sessions enable row level security;

-- ---------------------------------------------------------------------------
-- 2. Helpers
-- ---------------------------------------------------------------------------

-- Origin allow-list check. Supports '*', exact origins and single-segment
-- wildcards such as 'https://*.example.com' or 'http://localhost:*'.
create or replace function public.overauth_origin_allowed(p_allowed text[], p_origin text)
returns boolean
language plpgsql
immutable
as $$
declare
  pattern text;
  likepat text;
  o       text;
begin
  if p_allowed is null or cardinality(p_allowed) = 0 then
    return false;
  end if;

  o := regexp_replace(lower(coalesce(p_origin, '')), '/+$', '');
  if o = '' then
    return false;
  end if;

  foreach pattern in array p_allowed loop
    pattern := regexp_replace(lower(btrim(pattern)), '/+$', '');
    if pattern = '' then
      continue;
    elsif pattern = '*' or pattern = o then
      return true;
    elsif position('*' in pattern) > 0 then
      -- wildcard match: escape LIKE metacharacters first, then turn '*' into '%'
      likepat := replace(replace(replace(pattern, '\', '\\'), '%', '\%'), '_', '\_');
      likepat := replace(likepat, '*', '%');
      if o like likepat then
        return true;
      end if;
    end if;
  end loop;

  return false;
end;
$$;

-- Proves the caller owns the Overmind account they claim (username + sha256 password).
create or replace function public.overauth_assert_dev(p_username text, p_password_hash text)
returns boolean
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  return exists (
    select 1
    from public.users u
    where u.username = p_username
      and u.password_hash = p_password_hash
      and coalesce(u.is_banned, false) = false
  );
end;
$$;

-- Shapes the public user object, filtered by the key's scopes.
create or replace function public.overauth_public_user(p_username text, p_scopes text[])
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  u   record;
  out jsonb;
begin
  select * into u from public.users where username = p_username limit 1;
  if u.username is null then
    return null;
  end if;

  out := jsonb_build_object('username', u.username);

  if p_scopes is null or 'profile' = any (p_scopes) or '*' = any (p_scopes) then
    out := out || jsonb_build_object('created_at', to_jsonb(u.created_at));
  end if;
  if 'admin_flag' = any (coalesce(p_scopes, array[]::text[])) or '*' = any (coalesce(p_scopes, array[]::text[])) then
    out := out || jsonb_build_object('is_admin', coalesce(u.is_admin, false));
  end if;

  return out;
end;
$$;

-- ---------------------------------------------------------------------------
-- 3. Health check (used by the console's status chip)
-- ---------------------------------------------------------------------------

create or replace function public.overauth_health()
returns jsonb
language sql
stable
as $$
  select jsonb_build_object(
    'ok', true,
    'service', 'overauth',
    'version', '1.0',
    'server_time', to_jsonb(now())
  );
$$;

-- ---------------------------------------------------------------------------
-- 4. Developer console functions
-- ---------------------------------------------------------------------------

-- Issue (register) a new key. The console generates the key client-side and
-- only ever sends the hash, so the raw key is never stored server-side.
create or replace function public.overauth_issue_key(
  p_username        text,
  p_password_hash   text,
  p_name            text,
  p_key_id          text,
  p_key_hash        text,
  p_allowed_origins text[]  default null,
  p_scopes          text[]  default null,
  p_expires_at      timestamptz default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  new_id uuid;
begin
  if not public.overauth_assert_dev(p_username, p_password_hash) then
    return jsonb_build_object('ok', false, 'reason', 'invalid_credentials');
  end if;

  if coalesce(btrim(p_key_id), '') = '' or coalesce(btrim(p_key_hash), '') = '' then
    return jsonb_build_object('ok', false, 'reason', 'invalid_request');
  end if;

  insert into public.overauth_keys
    (key_id, key_hash, owner_username, name, allowed_origins, scopes, expires_at)
  values
    (btrim(p_key_id),
     lower(btrim(p_key_hash)),
     p_username,
     coalesce(nullif(btrim(p_name), ''), 'Untitled key'),
     coalesce(p_allowed_origins, array['*']),
     coalesce(p_scopes, array['profile', 'sessions']),
     p_expires_at)
  returning id into new_id;

  return jsonb_build_object('ok', true, 'key_id', p_key_id, 'id', new_id::text);
exception
  when unique_violation then
    return jsonb_build_object('ok', false, 'reason', 'duplicate_key');
end;
$$;

create or replace function public.overauth_list_keys(p_username text, p_password_hash text)
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  if not public.overauth_assert_dev(p_username, p_password_hash) then
    return jsonb_build_object('ok', false, 'reason', 'invalid_credentials');
  end if;

  return jsonb_build_object(
    'ok', true,
    'keys', coalesce((
      select jsonb_agg(t order by t.created_at desc)
      from (
        select k.key_id,
               k.name,
               k.allowed_origins,
               k.scopes,
               k.is_active,
               k.expires_at,
               k.created_at,
               k.last_used_at,
               k.use_count,
               (k.expires_at is not null and k.expires_at < now()) as expired
        from public.overauth_keys k
        where k.owner_username = p_username
      ) t
    ), '[]'::jsonb)
  );
end;
$$;

create or replace function public.overauth_update_key(
  p_username        text,
  p_password_hash   text,
  p_key_id          text,
  p_name            text     default null,
  p_allowed_origins text[]   default null,
  p_is_active       boolean  default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  k record;
begin
  if not public.overauth_assert_dev(p_username, p_password_hash) then
    return jsonb_build_object('ok', false, 'reason', 'invalid_credentials');
  end if;

  select * into k from public.overauth_keys
  where key_id = p_key_id and owner_username = p_username limit 1;

  if k.key_id is null then
    return jsonb_build_object('ok', false, 'reason', 'key_not_found');
  end if;

  update public.overauth_keys set
    name            = coalesce(nullif(btrim(p_name), ''), name),
    allowed_origins = coalesce(p_allowed_origins, allowed_origins),
    is_active       = coalesce(p_is_active, is_active)
  where id = k.id;

  -- pausing a key should not leave live sessions behind
  if p_is_active is false then
    update public.overauth_sessions set revoked = true
    where key_id = p_key_id and revoked = false;
  end if;

  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.overauth_delete_key(p_username text, p_password_hash text, p_key_id text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.overauth_assert_dev(p_username, p_password_hash) then
    return jsonb_build_object('ok', false, 'reason', 'invalid_credentials');
  end if;

  delete from public.overauth_sessions where key_id = p_key_id;
  delete from public.overauth_keys where key_id = p_key_id and owner_username = p_username;

  return jsonb_build_object('ok', true);
end;
$$;

-- Aggregate numbers for the console header.
create or replace function public.overauth_stats(p_username text, p_password_hash text)
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  if not public.overauth_assert_dev(p_username, p_password_hash) then
    return jsonb_build_object('ok', false, 'reason', 'invalid_credentials');
  end if;

  return jsonb_build_object(
    'ok', true,
    'keys',        (select count(*) from public.overauth_keys where owner_username = p_username),
    'active_keys', (select count(*) from public.overauth_keys where owner_username = p_username and is_active and (expires_at is null or expires_at > now())),
    'verifications', (select coalesce(sum(use_count), 0) from public.overauth_keys where owner_username = p_username),
    'live_sessions', (select count(*) from public.overauth_sessions s
                       join public.overauth_keys k on k.key_id = s.key_id
                      where k.owner_username = p_username and s.revoked = false and s.expires_at > now())
  );
end;
$$;

-- ---------------------------------------------------------------------------
-- 5. Runtime: what a visitor's browser calls when they log in on a dev site
-- ---------------------------------------------------------------------------

create or replace function public.overauth_verify(
  p_key_id        text,
  p_key_hash      text,
  p_username      text,
  p_password_hash text,
  p_origin        text    default null,
  p_remember      boolean default true
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  k        record;
  u        record;
  usr      jsonb;
  token    text;
  exp_at   timestamptz;
begin
  select * into k from public.overauth_keys where key_id = btrim(coalesce(p_key_id, '')) limit 1;

  if k.key_id is null or k.key_hash is distinct from lower(btrim(coalesce(p_key_hash, ''))) then
    return jsonb_build_object('ok', false, 'reason', 'invalid_key');
  end if;
  if not k.is_active then
    return jsonb_build_object('ok', false, 'reason', 'key_revoked', 'key_id', k.key_id);
  end if;
  if k.expires_at is not null and k.expires_at < now() then
    return jsonb_build_object('ok', false, 'reason', 'key_expired', 'key_id', k.key_id);
  end if;
  if not public.overauth_origin_allowed(k.allowed_origins, p_origin) then
    return jsonb_build_object('ok', false, 'reason', 'origin_not_allowed',
                              'origin', p_origin, 'allowed_origins', to_jsonb(k.allowed_origins));
  end if;

  select * into u from public.users where username = btrim(coalesce(p_username, '')) limit 1;

  if u.username is null or u.password_hash is distinct from coalesce(p_password_hash, '') then
    return jsonb_build_object('ok', false, 'reason', 'invalid_credentials');
  end if;
  if coalesce(u.is_banned, false) then
    return jsonb_build_object('ok', false, 'reason', 'account_banned');
  end if;

  update public.overauth_keys
     set last_used_at = now(),
         use_count    = use_count + 1
   where id = k.id;

  usr := public.overauth_public_user(u.username, k.scopes);

  if p_remember and ('sessions' = any (coalesce(k.scopes, array[]::text[])) or '*' = any (coalesce(k.scopes, array[]::text[]))) then
    insert into public.overauth_sessions (key_id, username, origin)
    values (k.key_id, u.username, p_origin)
    returning id, expires_at into token, exp_at;

    return jsonb_build_object(
      'ok', true,
      'user', usr,
      'key', jsonb_build_object('key_id', k.key_id, 'name', k.name),
      'session_token', token,
      'session_expires_at', to_jsonb(exp_at)
    );
  end if;

  return jsonb_build_object(
    'ok', true,
    'user', usr,
    'key', jsonb_build_object('key_id', k.key_id, 'name', k.name)
  );
end;
$$;

-- Validate a session token (e.g. from a dev's own backend, or on page load).
create or replace function public.overauth_session(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  s   record;
  k   record;
  u   record;
begin
  select * into s from public.overauth_sessions where id = coalesce(p_token, '') limit 1;

  if s.id is null or s.revoked or s.expires_at < now() then
    return jsonb_build_object('ok', false, 'reason', 'invalid_session');
  end if;

  select * into k from public.overauth_keys where key_id = s.key_id limit 1;
  if k.key_id is null or not k.is_active then
    return jsonb_build_object('ok', false, 'reason', 'key_revoked');
  end if;
  if k.expires_at is not null and k.expires_at < now() then
    return jsonb_build_object('ok', false, 'reason', 'key_expired');
  end if;

  select * into u from public.users where username = s.username limit 1;
  if u.username is null then
    return jsonb_build_object('ok', false, 'reason', 'invalid_session');
  end if;
  if coalesce(u.is_banned, false) then
    return jsonb_build_object('ok', false, 'reason', 'account_banned');
  end if;

  update public.overauth_sessions set last_seen_at = now() where id = s.id;

  return jsonb_build_object(
    'ok', true,
    'user', public.overauth_public_user(u.username, k.scopes),
    'key', jsonb_build_object('key_id', k.key_id, 'name', k.name),
    'origin', s.origin,
    'created_at', to_jsonb(s.created_at),
    'expires_at', to_jsonb(s.expires_at)
  );
end;
$$;

create or replace function public.overauth_end_session(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.overauth_sessions set revoked = true where id = coalesce(p_token, '');
  return jsonb_build_object('ok', true);
end;
$$;

-- ---------------------------------------------------------------------------
-- 6. Housekeeping (optional): drop expired sessions + keys older than 90 days
--    Supabase → Database → Cron jobs, or just run it by hand now and then.
-- ---------------------------------------------------------------------------
-- select cron.schedule('overauth-cleanup', '0 4 * * *', $$
--   delete from public.overauth_sessions where expires_at < now() - interval '7 days' or revoked;
-- $$);

-- ---------------------------------------------------------------------------
-- 7. Permissions
-- ---------------------------------------------------------------------------

grant usage on schema public to anon, authenticated;

grant execute on function public.overauth_health()                                                    to anon, authenticated;
grant execute on function public.overauth_issue_key(text, text, text, text, text, text[], text[], timestamptz) to anon, authenticated;
grant execute on function public.overauth_list_keys(text, text)                                       to anon, authenticated;
grant execute on function public.overauth_update_key(text, text, text, text, text[], boolean)         to anon, authenticated;
grant execute on function public.overauth_delete_key(text, text, text)                                to anon, authenticated;
grant execute on function public.overauth_stats(text, text)                                           to anon, authenticated;
grant execute on function public.overauth_verify(text, text, text, text, text, boolean)               to anon, authenticated;
grant execute on function public.overauth_session(text)                                               to anon, authenticated;
grant execute on function public.overauth_end_session(text)                                           to anon, authenticated;

-- These two are internal helpers; they must stay callable by the definer functions only.
revoke execute on function public.overauth_assert_dev(text, text)          from public;
revoke execute on function public.overauth_public_user(text, text[])       from public;
revoke execute on function public.overauth_origin_allowed(text[], text)    from public;

-- Done. Reload https://v0idplayy-777.github.io/Overmind/overauth.html and hit
-- “Re-check”. If it still says “local mode”, give Supabase a few seconds to
-- reload its schema cache (or run:  notify pgrst, 'reload schema';  ) and try
-- again -- PostgREST caches the list of functions it exposes.
