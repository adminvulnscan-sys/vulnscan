-- SOLO VulnScan-Pruebas, como postgres, después de las migraciones 001 y 002.
-- Pruebas SQL reales preparadas; no ejecutadas por Codex. No requieren pgTAP.
-- Fixtures y modificaciones se revierten al final. No se crean contraseñas.
begin;

insert into auth.users(id,email,role) values
 ('33333333-3333-4333-8333-333333333333','case-owner@example.invalid','authenticated'),
 ('44444444-4444-4444-8444-444444444444','case-other@example.invalid','authenticated'),
 ('55555555-5555-4555-8555-555555555555','case-create@example.invalid','authenticated');

-- Ambos perfiles son válidos en una PK text que distingue mayúsculas.
-- Se mantienen sin vínculo UUID al principio para probar el fallback antiguo.
insert into public.usuarios(email,tokens_pro,tokens_ent,tokens_pdf) values
 ('case-owner@example.invalid',2,2,2),
 ('Case-owner@example.invalid',7,7,7);
insert into public.escaneos(email_cliente,dominio,tipo,fecha,resultados_json) values
 ('case-owner@example.invalid','case.example.invalid','Rapido (Passive)','05/10/2026','["fixture anterior"]'),
 ('case-owner@example.invalid','case.example.invalid','Rapido (Passive)','06/10/2026','["fixture reciente"]'),
 ('Case-owner@example.invalid','other.example.invalid','Rapido (Passive)','06/10/2026','["fixture ajeno"]');

set local role authenticated;
select set_config('request.jwt.claims','{"sub":"55555555-5555-4555-8555-555555555555","role":"authenticated","email":"case-create@example.invalid"}',true);
select set_config('request.jwt.claim.email','case-create@example.invalid',true);

do $$
declare statement text; accepted boolean;
begin
  if current_user<>'authenticated' then raise exception 'Wrong test role'; end if;
  foreach statement in array array[
    'insert into public.usuarios(email,fecha_vencimiento) values (''case-create@example.invalid'',''31/12/2099'')',
    'insert into public.usuarios(email,fecha_inicio_trial) values (''case-create@example.invalid'',''2099-01-01'')',
    'insert into public.usuarios(email,trial_pro_usada) values (''case-create@example.invalid'',true)',
    'insert into public.usuarios(email,cancelacion_pendiente) values (''case-create@example.invalid'',true)',
    'insert into public.usuarios(email) values (''Case-create@example.invalid'')'
  ] loop
    accepted:=false;
    begin
      execute statement;
      accepted:=true;
    exception when sqlstate 'P0001' then
      if sqlerrm<>'Invalid initial profile' then raise; end if;
    end;
    if accepted then raise exception 'Unsafe initial profile was accepted'; end if;
  end loop;
  insert into public.usuarios(email,trial_pro_usada,cancelacion_pendiente)
    values('case-create@example.invalid',null,null);
  if not exists(select 1 from public.usuarios where email='case-create@example.invalid'
    and billing_user_id=auth.uid() and plan_activo='Basic'
    and trial_pro_usada=false and cancelacion_pendiente=false
    and fecha_vencimiento is null and fecha_inicio_trial is null) then
    raise exception 'Safe initial profile was not normalized';
  end if;
end $$;

select set_config('request.jwt.claims','{"sub":"33333333-3333-4333-8333-333333333333","role":"authenticated","email":"case-owner@example.invalid"}',true);
select set_config('request.jwt.claim.email','case-owner@example.invalid',true);

do $$
declare rows integer; report text; result jsonb; accepted boolean;
begin
  if (select count(*) from public.usuarios)<>1 then raise exception 'Case variant profile visible through RLS'; end if;
  update public.usuarios set webhook_url='https://fixture.example.invalid'
    where email='Case-owner@example.invalid';
  get diagnostics rows=row_count;
  if rows<>0 then raise exception 'Case variant profile writable'; end if;
  result:=public.billing_spend('tokens_pro','case-own-scan');
  if (result->>'remaining')::integer<>1 then raise exception 'Wrong profile was debited'; end if;
  select id::text into report from public.escaneos where email_cliente='case-owner@example.invalid'
    order by id desc limit 1;
  if not exists(select 1 from public.escaneos where id::text=report
    and resultados_json='["fixture reciente"]'::jsonb) then raise exception 'Last scan recovery failed'; end if;
  result:=public.billing_authorize_pdf(report);
  if not (result->>'authorized')::boolean or (result->>'remaining')::integer<>1 then
    raise exception 'Own PDF purchase failed';
  end if;
  result:=public.billing_authorize_pdf(report);
  if (result->>'remaining')::integer<>1 then raise exception 'PDF charged twice'; end if;
end $$;
reset role;

-- Fetch the other report's ID as administrator, not as the attacker.
-- Then try authorizing that known ID with Alice's role and UUID.
select set_config('vulnscan.test_other_report',
 (select id::text from public.escaneos where email_cliente='Case-owner@example.invalid'),true);
set local role authenticated;
do $$
declare accepted boolean:=false;
begin
  begin
    perform public.billing_authorize_pdf(current_setting('vulnscan.test_other_report'));
    accepted:=true;
  exception when sqlstate 'P0001' then
    if sqlerrm<>'Report not owned' then raise; end if;
  end;
  if accepted then raise exception 'Case variant report was authorized'; end if;
end $$;
reset role;

-- Trusted server simulation: grants exactly the lowercase profile's credit,
-- then links its UUID. It must not treat the uppercase profile as a match.
do $$
declare uid uuid:='33333333-3333-4333-8333-333333333333'; token text; result jsonb;
begin
  token:=public.billing_claim(uid,'evt_case_credit')->>'token';
  result:=public.billing_apply(jsonb_build_object('user_id',uid,'token',token,
    'event_id','evt_case_credit','event_created',1800000000,'checkout_id','cs_case_credit',
    'credit','tokens_ent','customer_id','cus_case_fixture','subscription',null));
  if not (result->>'credited')::boolean then raise exception 'One-off credit not granted'; end if;
  if not exists(select 1 from public.usuarios where email='case-owner@example.invalid'
    and billing_user_id=uid and tokens_ent=3) then raise exception 'Wrong profile linked or credited'; end if;
  if not exists(select 1 from public.usuarios where email='Case-owner@example.invalid'
    and billing_user_id is null and tokens_ent=7 and tokens_pro=7 and tokens_pdf=7
    and webhook_url is null and stripe_customer_id is null) then raise exception 'Case variant profile changed'; end if;
  token:=public.billing_claim(uid,'evt_case_subscription')->>'token';
  result:=public.billing_apply(jsonb_build_object('user_id',uid,'token',token,
    'event_id','evt_case_subscription','event_created',1800000001,'checkout_id','cs_case_subscription',
    'credit',null,'customer_id','cus_case_fixture','subscription',jsonb_build_object(
      'subscription_id','sub_case_fixture','subscription_created',1800000000,
      'customer_id','cus_case_fixture','status','active','plan','Pro',
      'period_end',extract(epoch from now())::bigint+86400,'cancel_at_period_end',false)));
  if not exists(select 1 from public.usuarios where email='case-owner@example.invalid'
    and plan_activo='Pro' and stripe_subscription_id='sub_case_fixture') then raise exception 'Subscription not retained'; end if;
end $$;

set local role authenticated;
do $$
declare rows integer; accepted boolean:=false;
begin
  if (select count(*) from public.usuarios)<>1 then raise exception 'Bound profile isolation failed'; end if;
  select count(*) into rows from public.escaneos;
  if rows<>2 then raise exception 'Report isolation failed after UUID linking'; end if;
  begin
    perform public.billing_authorize_pdf(current_setting('vulnscan.test_other_report'));
    accepted:=true;
  exception when sqlstate 'P0001' then
    if sqlerrm<>'Report not owned' then raise; end if;
  end;
  if accepted then raise exception 'Premium plan authorized another profile report'; end if;
end $$;
reset role;

rollback;
select 'Initial fields, exact-case ownership, RLS, PDF, credits, subscription and last scan tests passed; fixtures rolled back' as resultado;
