-- PREPARADO, NO APLICADO. ORIGINAL. Ejecutar completo, antes de publicar el codigo.
-- Requiere el paquete compatible ya instalado. No cambia saldos ni informes.
begin;
set local lock_timeout = '5s';
set local statement_timeout = '30s';
do $$ begin
  if current_user<>'postgres' then raise exception 'Trusted postgres owner required'; end if;
  if to_regprocedure('public.billing_spend(text,text)') is null
     or to_regprocedure('public.billing_internal_access()') is null
     or to_regclass('public.billing_spends') is null then
    raise exception 'Missing compatible billing dependencies';
  end if;
  if to_regclass('public.billing_scan_runs') is not null then
    raise exception 'Already installed: inspect before reapplying';
  end if;
  if exists(select 1 from (values
      ('dominio','text'),('tipo','text'),('fecha','text'),('riesgo','text'),('resultados_json','jsonb')) expected(col,typ)
      left join information_schema.columns c on c.table_schema='public' and c.table_name='escaneos'
        and c.column_name=expected.col where c.data_type is distinct from expected.typ) then
    raise exception 'Scan schema differs from reviewed original';
  end if;
end $$;

create table public.billing_scan_runs (
  user_id uuid not null references auth.users(id),
  operation uuid not null,
  target text not null,
  engine text not null,
  credit text check(credit in ('tokens_pro','tokens_ent')),
  state text not null check(state in ('reserved','completed','failed','expired')),
  lease_until timestamptz not null,
  hard_until timestamptz not null,
  report_id text,
  primary key(user_id,operation)
);
create unique index billing_one_reserved_scan on public.billing_scan_runs(user_id)
  where state='reserved';
create unique index billing_one_completed_report on public.billing_scan_runs(user_id,report_id)
  where state='completed';
alter table public.billing_scan_runs enable row level security;
revoke all on public.billing_scan_runs from public,anon,authenticated,service_role;

-- Shared lock order: profile first, reservation second (including billing_spend).
create function public.billing_scan_profile() returns public.usuarios
language plpgsql security definer set search_path='' as $$
declare u public.usuarios; uid uuid:=auth.uid(); e text;
begin
  if uid is null then raise exception 'Authentication required'; end if;
  select email into strict e from auth.users where id=uid;
  select * into strict u from public.usuarios where billing_user_id=uid
    or (billing_user_id is null and email collate "C"=e collate "C") for update;
  return u;
end $$;
revoke all on function public.billing_scan_profile() from public,anon,authenticated,service_role;

create function public.billing_scan_claim(p_operation uuid,p_credit text,p_target text,p_engine text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare u public.usuarios; r public.billing_scan_runs; available integer; plan text:='Basic';
  deadline timestamptz:=clock_timestamp()+interval '1 hour';
begin
  u:=public.billing_scan_profile();
  if p_operation is null or p_target is null or length(p_target) not between 1 and 253
     or p_engine is null or p_engine not in ('Rápido (Passive)','Profundo (Active)','Auditoría Completa (OWASP)')
     or (p_credit is not null and p_credit not in ('tokens_pro','tokens_ent')) then
    raise exception 'Invalid reservation';
  end if;
  -- Expiration frees a HOLD, not a previously deducted credit.
  update public.billing_scan_runs set state='expired'
    where user_id=auth.uid() and state='reserved' and lease_until<=clock_timestamp();
  select * into r from public.billing_scan_runs where user_id=auth.uid() and operation=p_operation;
  if found then
    if r.target<>p_target or r.engine<>p_engine or r.credit is distinct from p_credit then
      raise exception 'Operation conflict';
    end if;
    if r.state='completed' then
      return jsonb_build_object('status','completed','report_id',r.report_id,
                               'remaining',(to_jsonb(u)->>r.credit)::integer);
    end if;
    if r.state='reserved' then deadline:=r.hard_until; end if;
  end if;
  if exists(select 1 from public.billing_scan_runs where user_id=auth.uid()
      and state='reserved' and operation<>p_operation) then
    return jsonb_build_object('status','busy');
  end if;
  if p_credit is not null then
    if (p_credit='tokens_pro' and p_engine<>'Profundo (Active)')
       or (p_credit='tokens_ent' and p_engine<>'Auditoría Completa (OWASP)') then
      raise exception 'Credit/engine mismatch';
    end if;
    available:=coalesce((to_jsonb(u)->>p_credit)::integer,0);
    if available<1 then raise exception 'Insufficient credits'; end if;
  else
    if u.billing_status='active' and u.billing_period_end>extract(epoch from clock_timestamp()) then
      plan:=coalesce(u.plan_activo,'Basic');
    end if;
    if public.billing_internal_access()->>'plan'='Enterprise' then plan:='Enterprise'; end if;
    if (p_engine='Profundo (Active)' and plan not in ('Pro','Enterprise'))
       or (p_engine='Auditoría Completa (OWASP)' and plan<>'Enterprise') then
      raise exception 'Plan does not include engine';
    end if;
  end if;
  insert into public.billing_scan_runs(user_id,operation,target,engine,credit,state,lease_until,hard_until)
    values(auth.uid(),p_operation,p_target,p_engine,p_credit,'reserved',
           least(deadline,clock_timestamp()+interval '5 minutes'),deadline)
    on conflict(user_id,operation) do update set state='reserved',lease_until=excluded.lease_until,
                                               hard_until=excluded.hard_until;
  return jsonb_build_object('status','reserved','remaining',available);
end $$;

create function public.billing_scan_heartbeat(p_operation uuid) returns jsonb
language plpgsql security definer set search_path='' as $$
declare u public.usuarios; n integer;
begin
  u:=public.billing_scan_profile();
  update public.billing_scan_runs set lease_until=least(hard_until,clock_timestamp()+interval '5 minutes')
    where user_id=auth.uid() and operation=p_operation and state='reserved'
      and lease_until>clock_timestamp() and hard_until>clock_timestamp();
  get diagnostics n=row_count;
  return jsonb_build_object('status',case when n=1 then 'reserved' else 'expired' end);
end $$;

-- Direct spending must respect a credit held by another pending scan.
create or replace function public.billing_spend(p_credit text,p_operation text) returns jsonb
language plpgsql security definer set search_path='' as $$
declare uid uuid:=auth.uid(); u public.usuarios; amount integer; held integer;
begin
  if p_credit is null or p_operation is null
     or p_credit not in ('tokens_pro','tokens_ent','tokens_pdf')
     or length(p_operation) not between 1 and 200 then raise exception 'Invalid spend'; end if;
  u:=public.billing_scan_profile();
  amount:=coalesce((to_jsonb(u)->>p_credit)::integer,0);
  if exists(select 1 from public.billing_spends where user_id=uid and operation_id=p_operation) then
    if not exists(select 1 from public.billing_spends where user_id=uid and operation_id=p_operation and credit=p_credit) then
      raise exception 'Operation conflict'; end if;
    return jsonb_build_object('remaining',amount,'duplicate',true);
  end if;
  select count(*) into held from public.billing_scan_runs where user_id=uid
    and state='reserved' and lease_until>clock_timestamp() and credit=p_credit;
  if amount-held<=0 then raise exception 'Insufficient available credits'; end if;
  update public.usuarios set
    tokens_pro=coalesce(tokens_pro,0)-case when p_credit='tokens_pro' then 1 else 0 end,
    tokens_ent=coalesce(tokens_ent,0)-case when p_credit='tokens_ent' then 1 else 0 end,
    tokens_pdf=coalesce(tokens_pdf,0)-case when p_credit='tokens_pdf' then 1 else 0 end
    where email=u.email;
  insert into public.billing_spends values(uid,p_operation,p_credit);
  return jsonb_build_object('remaining',amount-1);
end $$;

create function public.billing_scan_complete(p_operation uuid,p_report text) returns jsonb
language plpgsql security definer set search_path='' as $$
declare u public.usuarios; r public.billing_scan_runs; spent jsonb;
begin
  u:=public.billing_scan_profile();
  select * into strict r from public.billing_scan_runs
    where user_id=auth.uid() and operation=p_operation for update;
  if p_report is null or not exists(select 1 from public.escaneos
      where id::text=p_report and email_cliente collate "C"=u.email collate "C" and tipo=r.engine
        and split_part(replace(replace(dominio,'https://',''),'http://',''),'/',1)=r.target) then
    raise exception 'Persisted own report required';
  end if;
  if r.state='completed' then
    if r.report_id<>p_report then raise exception 'Report conflict'; end if;
    return jsonb_build_object('status','completed','remaining',(to_jsonb(u)->>r.credit)::integer);
  end if;
  -- Recover a lost completion response only if no newer account reservation exists.
  if r.state not in ('reserved','expired') or exists(select 1 from public.billing_scan_runs
      where user_id=auth.uid() and operation<>p_operation and state='reserved') then
    raise exception 'Reservation superseded';
  end if;
  update public.billing_scan_runs set state='completed',report_id=p_report
    where user_id=auth.uid() and operation=p_operation;
  if r.credit is not null then
    spent:=public.billing_spend(r.credit,'scan:'||p_operation::text);
  end if;
  return coalesce(spent,'{}'::jsonb)||jsonb_build_object('status','completed');
end $$;

-- Result insertion and consumption have one commit point and one retry key.
create function public.billing_scan_store(p_operation uuid,p_payload jsonb) returns jsonb
language plpgsql security definer set search_path='' as $$
declare u public.usuarios; r public.billing_scan_runs; report text; result jsonb;
begin
  u:=public.billing_scan_profile();
  select * into strict r from public.billing_scan_runs
    where user_id=auth.uid() and operation=p_operation for update;
  if r.state='completed' then
    return jsonb_build_object('status','completed','report_id',r.report_id,
                             'remaining',(to_jsonb(u)->>r.credit)::integer);
  end if;
  if r.state<>'reserved' or r.lease_until<=clock_timestamp() then
    return jsonb_build_object('status','expired');
  end if;
  if p_payload is null or jsonb_typeof(p_payload)<>'object'
     or p_payload->>'dominio' is null
     or split_part(replace(replace(p_payload->>'dominio','https://',''),'http://',''),'/',1)<>r.target
     or jsonb_typeof(p_payload->'resultados_json') is distinct from 'string'
     or jsonb_typeof((p_payload->>'resultados_json')::jsonb) is distinct from 'array' then
    raise exception 'Invalid scan payload';
  end if;
  insert into public.escaneos(email_cliente,dominio,tipo,fecha,riesgo,resultados_json)
    values(u.email,p_payload->>'dominio',r.engine,
      to_char(clock_timestamp() at time zone 'UTC','DD/MM/YYYY'),p_payload->>'riesgo',
      (p_payload->>'resultados_json')::jsonb) returning id::text into report;
  result:=public.billing_scan_complete(p_operation,report);
  return result||jsonb_build_object('report_id',report);
end $$;

create function public.billing_scan_abort(p_operation uuid) returns jsonb
language plpgsql security definer set search_path='' as $$
declare u public.usuarios; r public.billing_scan_runs;
begin
  u:=public.billing_scan_profile();
  select * into r from public.billing_scan_runs where user_id=auth.uid() and operation=p_operation for update;
  if not found then return jsonb_build_object('status','missing'); end if;
  if r.state='reserved' then
    update public.billing_scan_runs set state='failed' where user_id=auth.uid() and operation=p_operation;
    r.state:='failed';
  end if;
  return jsonb_build_object('status',r.state,'remaining',(to_jsonb(u)->>r.credit)::integer);
end $$;

revoke all on function public.billing_scan_claim(uuid,text,text,text),public.billing_scan_heartbeat(uuid),
  public.billing_scan_complete(uuid,text),public.billing_scan_abort(uuid),public.billing_scan_store(uuid,jsonb)
  from public,anon,authenticated,service_role;
grant execute on function public.billing_scan_claim(uuid,text,text,text),public.billing_scan_heartbeat(uuid),
  public.billing_scan_complete(uuid,text),public.billing_scan_abort(uuid),public.billing_scan_store(uuid,jsonb) to authenticated;

-- Scheduled jobs use the same account lock, never an unprotected motor path.
-- Only a trusted service JWT can select another user's identity here.
create function public.billing_scan_job(p_email text,p_action text,p_operation uuid,
  p_target text default null,p_engine text default null,p_report text default null,p_payload jsonb default null) returns jsonb
language plpgsql security definer set search_path='' as $$
declare uid uuid; old_claims text:=current_setting('request.jwt.claims',true);
  old_sub text:=current_setting('request.jwt.claim.sub',true); result jsonb;
begin
  if auth.role() is distinct from 'service_role' then raise exception 'Trusted scheduler required'; end if;
  select a.id into strict uid from auth.users a join public.usuarios u
    on u.email collate "C"=a.email collate "C"
    where u.email collate "C"=p_email collate "C"
      and (u.billing_user_id is null or u.billing_user_id=a.id);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',uid,'email',p_email,'role','authenticated')::text,true);
  perform set_config('request.jwt.claim.sub',uid::text,true);
  case p_action
    when 'claim' then result:=public.billing_scan_claim(p_operation,null,p_target,p_engine);
    when 'heartbeat' then result:=public.billing_scan_heartbeat(p_operation);
    when 'complete' then result:=public.billing_scan_complete(p_operation,p_report);
    when 'abort' then result:=public.billing_scan_abort(p_operation);
    when 'store' then result:=public.billing_scan_store(p_operation,p_payload);
    else raise exception 'Invalid scheduler action';
  end case;
  perform set_config('request.jwt.claims',coalesce(old_claims,''),true);
  perform set_config('request.jwt.claim.sub',coalesce(old_sub,''),true);
  return result;
end $$;
revoke all on function public.billing_scan_job(text,text,uuid,text,text,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.billing_scan_job(text,text,uuid,text,text,text,jsonb) to service_role;
-- billing_spend retains the compatible package's existing EXECUTE permissions.
notify pgrst,'reload schema';
commit;
