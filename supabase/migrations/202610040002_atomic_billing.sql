-- Preparada para revisar/aplicar SOLO a una copia del esquema real o a pruebas.
-- Requiere usuarios(email,plan_activo,tokens_pro,tokens_ent,tokens_pdf,
-- fecha_vencimiento,cancelacion_pendiente,reporte_pdf_desbloqueado) y auth.users.
begin;
alter table public.usuarios add column if not exists billing_user_id uuid references auth.users(id);
alter table public.usuarios add column if not exists billing_status text,
  add column if not exists billing_period_end bigint;
create unique index if not exists usuarios_billing_user_unique on public.usuarios(billing_user_id)
  where billing_user_id is not null;
create table public.billing_accounts (
  user_id uuid primary key references auth.users(id),
  customer_id text unique,
  subscription_id text unique,
  subscription_created bigint,
  status text,
  period_end bigint,
  lease_token uuid,
  lease_until timestamptz
);
create table public.billing_events (
  event_id text primary key,
  user_id uuid not null references auth.users(id),
  event_created bigint not null,
  applied_at timestamptz not null default now()
);
create table public.billing_purchases (
  checkout_id text primary key,
  user_id uuid not null references auth.users(id),
  credit text check (credit in ('tokens_pro','tokens_ent','tokens_pdf')),
  created_at timestamptz not null default now()
);
create table public.billing_spends (
  user_id uuid not null references auth.users(id),
  operation_id text not null,
  credit text not null check (credit in ('tokens_pro','tokens_ent','tokens_pdf')),
  primary key(user_id,operation_id)
);
alter table public.billing_accounts enable row level security;
alter table public.billing_events enable row level security;
alter table public.billing_purchases enable row level security;
alter table public.billing_spends enable row level security;
revoke all on public.billing_accounts,public.billing_events,public.billing_purchases,public.billing_spends
  from public,anon,authenticated;
grant all on public.billing_accounts,public.billing_events,public.billing_purchases,public.billing_spends to service_role;

create function public.billing_claim(p_user uuid,p_event text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare a public.billing_accounts; token uuid;
begin
  insert into public.billing_accounts(user_id) values(p_user) on conflict do nothing;
  select * into strict a from public.billing_accounts where user_id=p_user for update;
  if exists(select 1 from public.billing_events where event_id=p_event and user_id=p_user) then
    return jsonb_build_object('duplicate',true);
  end if;
  if a.lease_until > clock_timestamp() then return jsonb_build_object('busy',true); end if;
  token := gen_random_uuid();
  update public.billing_accounts set lease_token=token,lease_until=clock_timestamp()+interval '120 seconds'
    where user_id=p_user;
  return jsonb_build_object('token',token);
end $$;

create function public.billing_release(p_user uuid,p_token uuid) returns void
language sql security definer set search_path = '' as $$
  update public.billing_accounts set lease_token=null,lease_until=null
    where user_id=p_user and lease_token=p_token;
$$;

create function public.billing_apply(p_update jsonb) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := (p_update->>'user_id')::uuid;
  a public.billing_accounts;
  sub jsonb := p_update->'subscription';
  customer text := p_update->>'customer_id';
  credit text := p_update->>'credit';
  checkout text := p_update->>'checkout_id';
  email_auth text;
  affected integer;
  new_purchase boolean := false;
  apply_sub boolean := false;
begin
  select * into strict a from public.billing_accounts where user_id=uid for update;
  if a.lease_token is null or a.lease_until is null
     or a.lease_token is distinct from (p_update->>'token')::uuid or a.lease_until <= clock_timestamp() then
    raise exception 'Lease expired or superseded';
  end if;
  if exists(select 1 from public.billing_events where event_id=p_update->>'event_id') then
    perform public.billing_release(uid,a.lease_token);
    return jsonb_build_object('duplicate',true);
  end if;
  if customer is null or (a.customer_id is not null and a.customer_id<>customer) then
    raise exception 'Customer mismatch';
  end if;
  select email into strict email_auth from auth.users where id=uid;
  -- Identity is the trusted UUID from Stripe metadata, NOT its email/customer_email.
  -- Email is only the compatibility lookup of that UUID's existing local profile.
  if (select count(*) from public.usuarios where billing_user_id=uid or
      (billing_user_id is null and email collate "C"=email_auth collate "C")) <> 1 then
    raise exception 'Missing or ambiguous profile; reconcile';
  end if;
  update public.usuarios set billing_user_id=uid,stripe_customer_id=customer
    where billing_user_id=uid or (billing_user_id is null and email collate "C"=email_auth collate "C");
  if credit is not null and (checkout is null or credit not in ('tokens_pro','tokens_ent','tokens_pdf')) then
    raise exception 'Invalid credit grant';
  end if;
  if checkout is not null then
    if exists(select 1 from public.billing_purchases where checkout_id=checkout and user_id<>uid) then
      raise exception 'Purchase owner mismatch';
    end if;
    insert into public.billing_purchases(checkout_id,user_id,credit) values(checkout,uid,credit)
      on conflict do nothing;
    get diagnostics affected = row_count;
    new_purchase := affected=1;
    if new_purchase and credit is not null then
      update public.usuarios set
        tokens_pro=coalesce(tokens_pro,0)+case when credit='tokens_pro' then 1 else 0 end,
        tokens_ent=coalesce(tokens_ent,0)+case when credit='tokens_ent' then 1 else 0 end,
        tokens_pdf=coalesce(tokens_pdf,0)+case when credit='tokens_pdf' then 1 else 0 end
      where billing_user_id=uid;
    end if;
  end if;
  if sub is not null and sub<>'null'::jsonb then
    if sub->>'plan' not in ('Basic','Pro','Enterprise') or sub->>'customer_id'<>customer
       or sub->>'subscription_id' is null or sub->>'subscription_created' is null then
      raise exception 'Invalid subscription';
    end if;
    -- A late event for an old subscription must not replace a newer one.
    apply_sub := a.subscription_id is null or a.subscription_id=sub->>'subscription_id'
      or (sub->>'subscription_created')::bigint > a.subscription_created;
    if apply_sub then
      update public.billing_accounts set subscription_id=sub->>'subscription_id',
        subscription_created=(sub->>'subscription_created')::bigint,status=sub->>'status',
        period_end=(sub->>'period_end')::bigint where user_id=uid;
      update public.usuarios set stripe_subscription_id=sub->>'subscription_id',
        plan_activo=sub->>'plan',cancelacion_pendiente=(sub->>'cancel_at_period_end')::boolean,
        billing_status=sub->>'status',billing_period_end=(sub->>'period_end')::bigint,
        fecha_vencimiento=to_char(to_timestamp((sub->>'period_end')::bigint) at time zone 'UTC','DD/MM/YYYY')
        where billing_user_id=uid;
    end if;
  end if;
  update public.billing_accounts set customer_id=customer where user_id=uid;
  insert into public.billing_events(event_id,user_id,event_created)
    values(p_update->>'event_id',uid,(p_update->>'event_created')::bigint);
  perform public.billing_release(uid,a.lease_token);
  return jsonb_build_object('applied',true,'credited',new_purchase and credit is not null,
                           'subscription_applied',apply_sub);
end $$;

-- Atomic spending, only a decrease, bound to auth.uid() and an idempotent operation.
create function public.billing_spend(p_credit text,p_operation text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid(); u public.usuarios; amount integer; auth_email text;
begin
  if uid is null or p_credit is null or p_operation is null
     or p_credit not in ('tokens_pro','tokens_ent','tokens_pdf')
     or length(p_operation) not between 1 and 200 then raise exception 'Invalid spend'; end if;
  select email into strict auth_email from auth.users where id=uid;
  select * into strict u from public.usuarios where billing_user_id=uid or
    (billing_user_id is null and email collate "C"=auth_email collate "C") for update;
  amount := coalesce((to_jsonb(u)->>p_credit)::integer,0);
  if exists(select 1 from public.billing_spends where user_id=uid and operation_id=p_operation) then
    if not exists(select 1 from public.billing_spends where user_id=uid and operation_id=p_operation and credit=p_credit) then
      raise exception 'Operation conflict';
    end if;
    return jsonb_build_object('remaining',amount,'duplicate',true);
  end if;
  if amount<=0 then raise exception 'Insufficient credits'; end if;
  update public.usuarios set
    tokens_pro=coalesce(tokens_pro,0)-case when p_credit='tokens_pro' then 1 else 0 end,
    tokens_ent=coalesce(tokens_ent,0)-case when p_credit='tokens_ent' then 1 else 0 end,
    tokens_pdf=coalesce(tokens_pdf,0)-case when p_credit='tokens_pdf' then 1 else 0 end
    where email=u.email;
  insert into public.billing_spends values(uid,p_operation,p_credit);
  return jsonb_build_object('remaining',amount-1);
end $$;

-- Require a persisted scan owned by auth.uid() before exposing PDF bytes.
-- The idempotent spend also acts as a durable per-report PDF entitlement.
create function public.billing_authorize_pdf(p_report text,p_consume boolean default true) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare uid uuid:=auth.uid(); auth_email text; u public.usuarios; spent jsonb;
begin
  if uid is null or p_report is null or length(p_report) not between 1 and 160 then
    raise exception 'Invalid report';
  end if;
  select email into strict auth_email from auth.users where id=uid;
  select * into strict u from public.usuarios where billing_user_id=uid or
    (billing_user_id is null and email collate "C"=auth_email collate "C") for update;
  -- First identify the owner's profile, then match the persisted report exactly.
  -- Alice@example.invalid and alice@example.invalid must never be interchangeable.
  if not exists(select 1 from public.escaneos where id::text=p_report
      and email_cliente collate "C"=u.email collate "C") then
    raise exception 'Report not owned';
  end if;
  if u.plan_activo in ('Pro','Enterprise') and u.billing_status='active'
     and u.billing_period_end>extract(epoch from clock_timestamp()) then
    return jsonb_build_object('authorized',true);
  end if;
  if exists(select 1 from public.billing_spends where user_id=uid and operation_id='pdf:'||p_report and credit='tokens_pdf') then
    return jsonb_build_object('authorized',true,'remaining',coalesce(u.tokens_pdf,0));
  end if;
  if not p_consume then return jsonb_build_object('authorized',false); end if;
  spent:=public.billing_spend('tokens_pdf','pdf:'||p_report);
  update public.usuarios set reporte_pdf_desbloqueado=p_report where email=u.email;
  return spent||jsonb_build_object('authorized',true);
end $$;


revoke all on function public.billing_claim(uuid,text),public.billing_release(uuid,uuid),
  public.billing_apply(jsonb),public.billing_spend(text,text) from public,anon,authenticated;
revoke all on function public.billing_authorize_pdf(text,boolean) from public,anon,authenticated;
grant execute on function public.billing_claim(uuid,text),public.billing_release(uuid,uuid),
  public.billing_apply(jsonb) to service_role;
grant execute on function public.billing_spend(text,text) to authenticated;
grant execute on function public.billing_authorize_pdf(text,boolean) to authenticated;

-- Protect entitlements even if broad pre-existing permissive RLS policies exist.
-- Owner of SECURITY DEFINER functions must remain the trusted migration/admin role.
create function public.billing_protect_profile() returns trigger
language plpgsql set search_path = '' as $$
declare old_protected jsonb; new_protected jsonb; k text;
begin
  if current_user not in ('anon','authenticated') then return new; end if;
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if tg_op='INSERT' then
    if new.email collate "C" is distinct from (auth.jwt()->>'email') collate "C"
       or coalesce(new.plan_activo,'Basic')<>'Basic'
       or coalesce(new.tokens_pro,0)<>0 or coalesce(new.tokens_ent,0)<>0 or coalesce(new.tokens_pdf,0)<>0
       or new.stripe_customer_id is not null or new.stripe_subscription_id is not null
       or new.reporte_pdf_desbloqueado is not null or new.billing_status is not null
       or new.billing_period_end is not null
       or new.fecha_vencimiento is not null or new.fecha_inicio_trial is not null
       or coalesce(new.trial_pro_usada,false) or coalesce(new.cancelacion_pendiente,false)
       then raise exception 'Invalid initial profile'; end if;
    -- NULL booleans cannot leave a profile in an ambiguous initial state.
    new.trial_pro_usada:=false;
    new.cancelacion_pendiente:=false;
    new.billing_user_id:=auth.uid();
  else
    foreach k in array array['email','billing_user_id','plan_activo','tokens_pro','tokens_ent','tokens_pdf',
      'stripe_customer_id','stripe_subscription_id','fecha_vencimiento','cancelacion_pendiente',
      'reporte_pdf_desbloqueado','trial_pro_usada','fecha_inicio_trial'] loop
      if to_jsonb(new)->k is distinct from to_jsonb(old)->k then raise exception 'Protected billing field'; end if;
    end loop;
    if new.billing_status is distinct from old.billing_status or new.billing_period_end is distinct from old.billing_period_end then
      raise exception 'Protected billing state';
    end if;
  end if;
  return new;
end $$;
create trigger billing_protect_profile before insert or update on public.usuarios
  for each row execute function public.billing_protect_profile();
alter table public.usuarios enable row level security;
revoke all on public.usuarios from public,anon;
revoke delete,truncate,references,trigger on public.usuarios from authenticated;
grant select,insert,update on public.usuarios to authenticated;
create policy billing_owner_boundary on public.usuarios as restrictive to authenticated
  using (billing_user_id=auth.uid() or (billing_user_id is null and email collate "C"=(auth.jwt()->>'email') collate "C"))
  with check (billing_user_id=auth.uid() or (billing_user_id is null and email collate "C"=(auth.jwt()->>'email') collate "C"));
create policy billing_owner_read on public.usuarios for select to authenticated
  using (billing_user_id=auth.uid() or (billing_user_id is null and email collate "C"=(auth.jwt()->>'email') collate "C"));
create policy billing_owner_insert on public.usuarios for insert to authenticated with check(billing_user_id=auth.uid());
create policy billing_owner_update on public.usuarios for update to authenticated
  using(billing_user_id=auth.uid() or (billing_user_id is null and email collate "C"=(auth.jwt()->>'email') collate "C"));
commit;
