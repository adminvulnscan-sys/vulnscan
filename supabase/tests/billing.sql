-- NO ejecutado aquí. Requiere esquema real copiado, ambas migraciones y pgTAP.
-- Solo ejecutar en instancia desechable de prueba. Los fixtures se revierten.
begin;
create extension if not exists pgtap with schema extensions;
set local search_path=public,extensions;
select no_plan();
select ok(not has_function_privilege('authenticated','public.billing_apply(jsonb)','EXECUTE'), 'Usuario no concede créditos');
select ok(not has_function_privilege('anon','public.billing_claim(uuid,text)','EXECUTE'), 'Anon no bloquea cuentas');
select ok(has_function_privilege('service_role','public.billing_apply(jsonb)','EXECUTE'), 'Webhook puede aplicar');
select ok(has_function_privilege('authenticated','public.billing_spend(text,text)','EXECUTE'), 'Usuario puede gastar con RPC');
select ok(not has_table_privilege('authenticated','public.billing_events','SELECT'), 'Ledger privado');
select ok((select relrowsecurity from pg_class where oid='public.usuarios'::regclass), 'RLS de perfiles habilitada');

insert into auth.users(id,email,role) values
 ('11111111-1111-4111-8111-111111111111','billing-fixture@example.invalid','authenticated'),
 ('22222222-2222-4222-8222-222222222222','billing-other@example.invalid','authenticated');
insert into public.usuarios(email,plan_activo,tokens_pro,tokens_ent,tokens_pdf,billing_user_id) values
 ('billing-fixture@example.invalid','Basic',0,0,0,'11111111-1111-4111-8111-111111111111'),
 ('billing-other@example.invalid','Basic',0,0,0,'22222222-2222-4222-8222-222222222222');
create temporary table billing_fixture_payload(payload jsonb);
insert into billing_fixture_payload select jsonb_build_object(
 'user_id','11111111-1111-4111-8111-111111111111','event_id','evt_fixture_1',
 'event_created',1800000000,'checkout_id','cs_fixture','credit','tokens_pdf',
 'customer_id','cus_fixture','subscription',null,
 'token',public.billing_claim('11111111-1111-4111-8111-111111111111','evt_fixture_1')->>'token');
select ok((public.billing_apply((select payload from billing_fixture_payload))->>'credited')::boolean, 'Compra concede un crédito');
select is((select tokens_pdf::integer from usuarios where email='billing-fixture@example.invalid'),1,'Saldo inicial');
select ok((public.billing_claim('11111111-1111-4111-8111-111111111111','evt_fixture_1')->>'duplicate')::boolean,'Evento duplicado');
update billing_fixture_payload set payload=payload||jsonb_build_object('event_id','evt_fixture_2','token',
 public.billing_claim('11111111-1111-4111-8111-111111111111','evt_fixture_2')->>'token');
select ok(not (public.billing_apply((select payload from billing_fixture_payload))->>'credited')::boolean, 'Mismo Checkout no repite crédito');
select is((select tokens_pdf::integer from usuarios where email='billing-fixture@example.invalid'),1,'Saldo no duplicado');

set local role authenticated;
select set_config('request.jwt.claims','{"sub":"11111111-1111-4111-8111-111111111111","role":"authenticated","email":"billing-fixture@example.invalid"}',true);
select is((select count(*)::integer from public.usuarios),1,'Solo perfil propio');
select throws_ok($$update public.usuarios set plan_activo='Enterprise' where email='billing-fixture@example.invalid'$$,
 'P0001','Protected billing field','No autoasignar plan');
select throws_ok($$update public.usuarios set tokens_pdf=100 where email='billing-fixture@example.invalid'$$,
 'P0001','Protected billing field','No cambiar créditos');
select throws_ok($$update public.usuarios set stripe_customer_id='cus_other' where email='billing-fixture@example.invalid'$$,
 'P0001','Protected billing field','No cambiar identificador Stripe');
select is((public.billing_spend('tokens_pdf','fixture-spend')->>'remaining')::integer,0,'Gasto atómico');
select is((public.billing_spend('tokens_pdf','fixture-spend')->>'remaining')::integer,0,'Gasto idempotente');
select throws_ok($$select public.billing_spend('tokens_pdf','another-spend')$$,
 'P0001','Insufficient credits','No saldo negativo');
reset role;
select * from finish();
rollback;
