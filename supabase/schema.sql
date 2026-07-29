-- Super Speed Delivery — Blog + Admin schema
-- Run once in: Supabase Dashboard → SQL Editor → New query → Run

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------------
-- Admin users & sessions
-- ---------------------------------------------------------------------------
create table if not exists public.admin_users (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  password_hash text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.admin_sessions (
  token uuid primary key default gen_random_uuid(),
  admin_id uuid not null references public.admin_users (id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists admin_sessions_expires_idx on public.admin_sessions (expires_at);

-- Default admin (username / password as requested)
insert into public.admin_users (username, password_hash)
values (
  'superspeeddelivery',
  extensions.crypt('superspeeddeliverypass', extensions.gen_salt('bf'))
)
on conflict (username) do nothing;

-- ---------------------------------------------------------------------------
-- Blogs
-- ---------------------------------------------------------------------------
create table if not exists public.blogs (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  content text not null,
  images text[] not null default '{}'::text[],
  status text not null default 'draft' check (status in ('draft', 'published')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint blogs_images_max check (coalesce(array_length(images, 1), 0) <= 4)
);

create index if not exists blogs_status_created_idx
  on public.blogs (status, created_at desc);

alter table public.blogs enable row level security;
alter table public.admin_users enable row level security;
alter table public.admin_sessions enable row level security;

-- No direct table access for anon (all admin ops go through SECURITY DEFINER RPCs)
drop policy if exists "Public read published blogs" on public.blogs;
create policy "Public read published blogs"
  on public.blogs
  for select
  to anon, authenticated
  using (status = 'published');

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------
create or replace function public._admin_id_from_token(p_token uuid)
returns uuid
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_admin_id uuid;
begin
  delete from public.admin_sessions where expires_at < now();

  select s.admin_id
    into v_admin_id
  from public.admin_sessions s
  where s.token = p_token
    and s.expires_at > now();

  return v_admin_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- Auth RPCs
-- ---------------------------------------------------------------------------
create or replace function public.admin_login(p_username text, p_password text)
returns json
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_admin public.admin_users%rowtype;
  v_token uuid;
  v_expires timestamptz;
begin
  select * into v_admin
  from public.admin_users
  where username = lower(trim(p_username));

  if not found then
    return json_build_object('ok', false, 'error', 'Invalid username or password.');
  end if;

  if v_admin.password_hash <> extensions.crypt(p_password, v_admin.password_hash) then
    return json_build_object('ok', false, 'error', 'Invalid username or password.');
  end if;

  v_expires := now() + interval '14 days';
  insert into public.admin_sessions (admin_id, expires_at)
  values (v_admin.id, v_expires)
  returning token into v_token;

  return json_build_object(
    'ok', true,
    'token', v_token,
    'username', v_admin.username,
    'expires_at', v_expires
  );
end;
$$;

create or replace function public.admin_logout(p_token uuid)
returns json
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  delete from public.admin_sessions where token = p_token;
  return json_build_object('ok', true);
end;
$$;

create or replace function public.admin_change_password(
  p_token uuid,
  p_current_password text,
  p_new_password text
)
returns json
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_admin_id uuid;
  v_hash text;
begin
  if length(trim(coalesce(p_new_password, ''))) < 8 then
    return json_build_object('ok', false, 'error', 'New password must be at least 8 characters.');
  end if;

  v_admin_id := public._admin_id_from_token(p_token);
  if v_admin_id is null then
    return json_build_object('ok', false, 'error', 'Session expired. Please sign in again.');
  end if;

  select password_hash into v_hash from public.admin_users where id = v_admin_id;
  if v_hash <> extensions.crypt(p_current_password, v_hash) then
    return json_build_object('ok', false, 'error', 'Current password is incorrect.');
  end if;

  update public.admin_users
  set
    password_hash = extensions.crypt(p_new_password, extensions.gen_salt('bf')),
    updated_at = now()
  where id = v_admin_id;

  return json_build_object('ok', true);
end;
$$;

create or replace function public.admin_session_check(p_token uuid)
returns json
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_admin_id uuid;
  v_username text;
begin
  v_admin_id := public._admin_id_from_token(p_token);
  if v_admin_id is null then
    return json_build_object('ok', false);
  end if;

  select username into v_username from public.admin_users where id = v_admin_id;
  return json_build_object('ok', true, 'username', v_username);
end;
$$;

-- ---------------------------------------------------------------------------
-- Blog RPCs
-- ---------------------------------------------------------------------------
create or replace function public.admin_list_blogs(p_token uuid)
returns json
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_admin_id uuid;
  v_rows json;
begin
  v_admin_id := public._admin_id_from_token(p_token);
  if v_admin_id is null then
    return json_build_object('ok', false, 'error', 'Session expired. Please sign in again.');
  end if;

  select coalesce(json_agg(row_to_json(b)), '[]'::json)
    into v_rows
  from (
    select id, title, content, images, status, created_at, updated_at
    from public.blogs
    order by updated_at desc
  ) b;

  return json_build_object('ok', true, 'blogs', v_rows);
end;
$$;

create or replace function public.admin_upsert_blog(
  p_token uuid,
  p_id uuid default null,
  p_title text default null,
  p_content text default null,
  p_images text[] default null,
  p_status text default null
)
returns json
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_admin_id uuid;
  v_id uuid;
  v_images text[] := coalesce(p_images, '{}'::text[]);
  v_status text := lower(trim(coalesce(p_status, 'draft')));
  v_row public.blogs%rowtype;
begin
  v_admin_id := public._admin_id_from_token(p_token);
  if v_admin_id is null then
    return json_build_object('ok', false, 'error', 'Session expired. Please sign in again.');
  end if;

  if length(trim(coalesce(p_title, ''))) = 0 then
    return json_build_object('ok', false, 'error', 'Title is required.');
  end if;

  if length(trim(coalesce(p_content, ''))) = 0 then
    return json_build_object('ok', false, 'error', 'Content is required.');
  end if;

  if v_status not in ('draft', 'published') then
    return json_build_object('ok', false, 'error', 'Status must be draft or published.');
  end if;

  if coalesce(array_length(v_images, 1), 0) > 4 then
    return json_build_object('ok', false, 'error', 'A maximum of 4 images is allowed.');
  end if;

  if p_id is null then
    insert into public.blogs (title, content, images, status)
    values (trim(p_title), trim(p_content), v_images, v_status)
    returning * into v_row;
  else
    update public.blogs
    set
      title = trim(p_title),
      content = trim(p_content),
      images = v_images,
      status = v_status,
      updated_at = now()
    where id = p_id
    returning * into v_row;

    if not found then
      return json_build_object('ok', false, 'error', 'Blog not found.');
    end if;
  end if;

  return json_build_object('ok', true, 'blog', row_to_json(v_row));
end;
$$;

create or replace function public.admin_delete_blog(p_token uuid, p_id uuid)
returns json
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_admin_id uuid;
begin
  v_admin_id := public._admin_id_from_token(p_token);
  if v_admin_id is null then
    return json_build_object('ok', false, 'error', 'Session expired. Please sign in again.');
  end if;

  delete from public.blogs where id = p_id;
  if not found then
    return json_build_object('ok', false, 'error', 'Blog not found.');
  end if;

  return json_build_object('ok', true);
end;
$$;

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
grant usage on schema public to anon, authenticated;
grant select on public.blogs to anon, authenticated;

grant execute on function public.admin_login(text, text) to anon, authenticated;
grant execute on function public.admin_logout(uuid) to anon, authenticated;
grant execute on function public.admin_change_password(uuid, text, text) to anon, authenticated;
grant execute on function public.admin_session_check(uuid) to anon, authenticated;
grant execute on function public.admin_list_blogs(uuid) to anon, authenticated;
grant execute on function public.admin_upsert_blog(uuid, uuid, text, text, text[], text) to anon, authenticated;
grant execute on function public.admin_delete_blog(uuid, uuid) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- Storage bucket for blog images (public read + upload)
-- ---------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'blog-images',
  'blog-images',
  true,
  5242880,
  array['image/jpeg', 'image/png', 'image/webp', 'image/gif']
)
on conflict (id) do update
set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Public read blog images" on storage.objects;
drop policy if exists "Public upload blog images" on storage.objects;
drop policy if exists "Public update blog images" on storage.objects;
drop policy if exists "Public delete blog images" on storage.objects;

create policy "Public read blog images"
  on storage.objects for select
  to anon, authenticated
  using (bucket_id = 'blog-images');

create policy "Public upload blog images"
  on storage.objects for insert
  to anon, authenticated
  with check (bucket_id = 'blog-images');

create policy "Public update blog images"
  on storage.objects for update
  to anon, authenticated
  using (bucket_id = 'blog-images');

create policy "Public delete blog images"
  on storage.objects for delete
  to anon, authenticated
  using (bucket_id = 'blog-images');
