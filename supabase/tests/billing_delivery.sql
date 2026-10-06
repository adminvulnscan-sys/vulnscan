-- SOLO VulnScan-Pruebas, SQL Editor como postgres, tras migraciones 001 y 002.
-- Simula entradas de confianza a las RPC; NO contacta Stripe.
-- Verifica duplicados, bloqueo por lease y rollback atomico.
-- No prueba concurrencia entre conexiones reales. Todos los fixtures se revierten.
begin;
insert into auth.users(id,email,role) values
 ('77777777-7777-4777-8777-777777777777','delivery@example.invalid','authenticated');
insert into public.usuarios(email,tokens_pro,tokens_ent,tokens_pdf)
 values ('delivery@example.invalid',0,0,0);

do $$
declare
 uid uuid := '77777777-7777-4777-8777-777777777777';
 claim jsonb; result jsonb; payload jsonb; previous_token uuid; next_token uuid;
 rejected boolean := false; n integer;
begin
 claim := public.billing_claim(uid,'evt_fixture_first');
 payload := jsonb_build_object('user_id',uid,'token',claim->>'token',
   'event_id','evt_fixture_first','event_created',1700000000,
   'customer_id','cus_fixture_delivery','checkout_id','cs_fixture_first','credit','tokens_pdf');
 result := public.billing_apply(payload);
 if result->>'credited' is distinct from 'true' then raise exception 'First purchase not credited'; end if;
 claim := public.billing_claim(uid,'evt_fixture_first');
 if claim->>'duplicate' is distinct from 'true' then raise exception 'Event not deduplicated'; end if;

 -- Another event for the SAME Checkout must not grant a second credit.
 claim := public.billing_claim(uid,'evt_fixture_same_checkout');
 payload := payload || jsonb_build_object('token',claim->>'token','event_id','evt_fixture_same_checkout');
 result := public.billing_apply(payload);
 if result->>'credited' is distinct from 'false' then raise exception 'Checkout credited twice'; end if;
 select tokens_pdf into n from public.usuarios where billing_user_id=uid;
 if n<>1 then raise exception 'Duplicate changed credits'; end if;

 -- Two distinct purchases must both survive, independently of delivery order.
 claim := public.billing_claim(uid,'evt_fixture_older');
 payload := payload || jsonb_build_object('token',claim->>'token','event_id','evt_fixture_older',
   'event_created',1699999999,'checkout_id','cs_fixture_second');
 perform public.billing_apply(payload);
 select tokens_pdf into n from public.usuarios where billing_user_id=uid;
 if n<>2 then raise exception 'Distinct older purchase lost'; end if;

 claim := public.billing_claim(uid,'evt_fixture_failure');
 previous_token := (claim->>'token')::uuid;
 result := public.billing_claim(uid,'evt_fixture_busy');
 if result->>'busy' is distinct from 'true' then raise exception 'Lease did not block another claim'; end if;

 -- Cause a late NOT NULL error, after the credit update: all changes must roll back.
 payload := payload || jsonb_build_object('token',previous_token,'event_id','evt_fixture_failure',
   'event_created',null,'checkout_id','cs_fixture_failure');
 begin
   perform public.billing_apply(payload);
 exception when not_null_violation then rejected:=true;
 end;
 if not rejected then raise exception 'Expected failure was not raised'; end if;
 select tokens_pdf into n from public.usuarios where billing_user_id=uid;
 if n<>2 or exists(select 1 from public.billing_purchases where checkout_id='cs_fixture_failure')
   or exists(select 1 from public.billing_events where event_id='evt_fixture_failure') then
   raise exception 'Failed delivery left partial changes';
 end if;

 -- An expired worker cannot apply or release the replacement worker's lease.
 update public.billing_accounts set lease_until=clock_timestamp()-interval '1 second' where user_id=uid;
 claim := public.billing_claim(uid,'evt_fixture_replacement');
 next_token := (claim->>'token')::uuid;
 rejected:=false;
 begin
   perform public.billing_apply(payload);
 exception when sqlstate 'P0001' then
   if sqlerrm<>'Lease expired or superseded' then raise; end if;
   rejected:=true;
 end;
 if not rejected then raise exception 'Superseded worker accepted'; end if;
 perform public.billing_release(uid,previous_token);
 if not exists(select 1 from public.billing_accounts where user_id=uid and lease_token=next_token) then
   raise exception 'Old worker released new lease';
 end if;
 payload := payload || jsonb_build_object('token',next_token,'event_id','evt_fixture_replacement',
   'event_created',1700000001,'checkout_id','cs_fixture_replacement');
 perform public.billing_apply(payload);
 select tokens_pdf into n from public.usuarios where billing_user_id=uid;
 if n<>3 then raise exception 'Replacement purchase not credited'; end if;
end $$;
rollback;
select 'Duplicados, compras distintas, lease y rollback atomico comprobados; fixtures revertidos' as resultado;
