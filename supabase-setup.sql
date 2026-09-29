-- הקופה שלנו · הגדרת מסד הנתונים ב-Supabase (גרסה עם שם משתמש וסיסמה)
-- להריץ פעם אחת: Supabase → SQL Editor → New query → להדביק → Run
-- (אם הרצת את הגרסה הקודמת עם קוד קופה, הטבלאות pm_* לא נוגעות לגרסה הזאת ואפשר למחוק אותן)

create extension if not exists pgcrypto with schema extensions;

create table if not exists kupa_families (
  id          uuid primary key default gen_random_uuid(),
  settings    jsonb not null default '{}'::jsonb,
  created_at  timestamptz default now()
);
create table if not exists kupa_members (
  user_id   uuid primary key references auth.users(id) on delete cascade,
  family    uuid not null references kupa_families(id) on delete cascade,
  role      text not null check (role in ('parent','child')),
  username  text not null
);
create table if not exists kupa_tx (
  id text primary key, family uuid not null references kupa_families(id) on delete cascade,
  data jsonb not null, ts bigint not null
);
create table if not exists kupa_requests (
  id text primary key, family uuid not null references kupa_families(id) on delete cascade,
  data jsonb not null, ts bigint not null
);
create index if not exists kupa_tx_f on kupa_tx(family, ts desc);
create index if not exists kupa_req_f on kupa_requests(family, ts desc);

-- אין גישה ישירה לטבלאות. הכול עובר דרך הפונקציות למטה, שבודקות מי מחובר.
alter table kupa_families enable row level security;
alter table kupa_members  enable row level security;
alter table kupa_tx       enable row level security;
alter table kupa_requests enable row level security;
revoke all on kupa_families, kupa_members, kupa_tx, kupa_requests from anon, authenticated;

-- עזר: הקופה והתפקיד של המשתמש המחובר
create or replace function kupa_my() returns kupa_members
language sql stable security definer set search_path = public as $$
  select * from kupa_members where user_id = auth.uid();
$$;

create or replace function kupa_me() returns jsonb
language sql stable security definer set search_path = public as $$
  select case when m.user_id is null then jsonb_build_object('family', null) else jsonb_build_object(
    'family', m.family, 'role', m.role, 'username', m.username,
    'members', (select jsonb_agg(jsonb_build_object('user_id', x.user_id, 'username', x.username, 'role', x.role))
                from kupa_members x where x.family = m.family)
  ) end
  from (select 1) d left join kupa_members m on m.user_id = auth.uid();
$$;

create or replace function kupa_create_family(p_settings jsonb, p_username text) returns uuid
language plpgsql security definer set search_path = public as $$
declare f uuid;
begin
  if auth.uid() is null then raise exception 'not allowed'; end if;
  if exists (select 1 from kupa_members where user_id = auth.uid()) then raise exception 'already in a family'; end if;
  insert into kupa_families(settings) values (p_settings) returning id into f;
  insert into kupa_members(user_id, family, role, username) values (auth.uid(), f, 'parent', coalesce(nullif(p_username,''),'הורה'));
  return f;
end $$;

-- הורה מצרף את המשתמש שיצר לבת (רק משתמש חדש לגמרי, שנוצר ב-10 הדקות האחרונות)
create or replace function kupa_add_child(p_user_id uuid, p_username text) returns void
language plpgsql security definer set search_path = public as $$
declare me kupa_members;
begin
  me := kupa_my();
  if me.role is distinct from 'parent' then raise exception 'not allowed'; end if;
  if exists (select 1 from kupa_members where user_id = p_user_id) then raise exception 'not allowed'; end if;
  if not exists (select 1 from auth.users where id = p_user_id and created_at > now() - interval '10 minutes') then raise exception 'not allowed'; end if;
  insert into kupa_members(user_id, family, role, username) values (p_user_id, me.family, 'child', p_username);
end $$;

-- הורה מחליף סיסמה לבת שלו (אם שכחה)
create or replace function kupa_reset_child_password(p_user_id uuid, p_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare me kupa_members;
begin
  me := kupa_my();
  if me.role is distinct from 'parent' then raise exception 'not allowed'; end if;
  if not exists (select 1 from kupa_members where user_id = p_user_id and family = me.family and role = 'child') then raise exception 'not allowed'; end if;
  if length(p_password) < 6 then raise exception 'password too short'; end if;
  update auth.users set encrypted_password = extensions.crypt(p_password, extensions.gen_salt('bf')), updated_at = now() where id = p_user_id;
end $$;

create or replace function kupa_get() returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare me kupa_members;
begin
  me := kupa_my();
  if me.family is null then raise exception 'not allowed'; end if;
  return jsonb_build_object(
    'settings', (select settings from kupa_families where id = me.family),
    'tx', coalesce((select jsonb_agg(t.data || jsonb_build_object('id', t.id) order by t.ts desc)
                    from (select * from kupa_tx where family = me.family order by ts desc limit 400) t), '[]'::jsonb),
    'requests', coalesce((select jsonb_agg(r.data || jsonb_build_object('id', r.id) order by r.ts desc)
                    from (select * from kupa_requests where family = me.family order by ts desc limit 60) r), '[]'::jsonb));
end $$;

-- הבת יכולה לשנות רק את מטרת החיסכון; ההורה את הכול
create or replace function kupa_update_settings(p_patch jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare me kupa_members;
begin
  me := kupa_my();
  if me.family is null then raise exception 'not allowed'; end if;
  if me.role = 'child' and exists (select 1 from jsonb_object_keys(p_patch) k where k <> 'goal') then raise exception 'not allowed'; end if;
  update kupa_families set settings = settings || p_patch where id = me.family;
end $$;

create or replace function kupa_add_tx(p_tx jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare me kupa_members;
begin
  me := kupa_my();
  if me.family is null then raise exception 'not allowed'; end if;
  -- הבת יכולה לרשום רק הוצאות ומתנות שקיבלה, בשמה
  if me.role = 'child' and not (p_tx->>'type' in ('spend','gift') and p_tx->>'by' = 'child') then raise exception 'not allowed'; end if;
  insert into kupa_tx(id, family, data, ts)
  values (p_tx->>'id', me.family, p_tx - 'id', coalesce((p_tx->>'ts')::bigint, 0)) on conflict (id) do nothing;
end $$;

create or replace function kupa_del_tx(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare me kupa_members;
begin
  me := kupa_my();
  if me.family is null then raise exception 'not allowed'; end if;
  delete from kupa_tx where family = me.family and id = p_id and (me.role = 'parent' or data->>'by' = 'child');
end $$;

create or replace function kupa_add_req(p_req jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare me kupa_members;
begin
  me := kupa_my();
  if me.family is null then raise exception 'not allowed'; end if;
  insert into kupa_requests(id, family, data, ts)
  values (p_req->>'id', me.family, (p_req - 'id') || '{"status":"pending"}'::jsonb, coalesce((p_req->>'ts')::bigint, 0)) on conflict (id) do nothing;
end $$;

create or replace function kupa_set_req_status(p_id text, p_status text) returns void
language plpgsql security definer set search_path = public as $$
declare me kupa_members;
begin
  me := kupa_my();
  if me.role is distinct from 'parent' then raise exception 'not allowed'; end if;
  update kupa_requests set data = data || jsonb_build_object('status', p_status, 'decidedAt', (extract(epoch from now())*1000)::bigint)
  where family = me.family and id = p_id;
end $$;

create or replace function kupa_del_req(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare me kupa_members;
begin
  me := kupa_my();
  if me.family is null then raise exception 'not allowed'; end if;
  delete from kupa_requests where family = me.family and id = p_id;
end $$;

-- רק משתמשים מחוברים יכולים להריץ את הפונקציות
revoke execute on function kupa_my, kupa_me, kupa_create_family, kupa_add_child, kupa_reset_child_password,
  kupa_get, kupa_update_settings, kupa_add_tx, kupa_del_tx, kupa_add_req, kupa_set_req_status, kupa_del_req from public, anon;
grant execute on function kupa_me, kupa_create_family, kupa_add_child, kupa_reset_child_password,
  kupa_get, kupa_update_settings, kupa_add_tx, kupa_del_tx, kupa_add_req, kupa_set_req_status, kupa_del_req to authenticated;
