-- SOLO LECTURA. ORIGINAL. SOLO despues de instalar billing_scan_reservation.sql.
-- No consulta datos, saldos, dominios ni identidades.
with signatures(signature) as (values
 ('public.billing_scan_profile()'),
 ('public.billing_scan_claim(uuid,text,text,text)'),
 ('public.billing_scan_heartbeat(uuid)'),
 ('public.billing_scan_complete(uuid,text)'),
 ('public.billing_scan_store(uuid,jsonb)'),
 ('public.billing_scan_abort(uuid)'),
 ('public.billing_scan_job(text,text,uuid,text,text,text,jsonb)')
)
select jsonb_build_object(
 'table_installed',to_regclass('public.billing_scan_runs') is not null,
 'table_rls',(select relrowsecurity from pg_class where oid=to_regclass('public.billing_scan_runs')),
 'table_privileges',(select jsonb_agg(jsonb_build_object('role',r,
   'select',has_any_column_privilege(r,to_regclass('public.billing_scan_runs'),'SELECT'),
   'insert',has_any_column_privilege(r,to_regclass('public.billing_scan_runs'),'INSERT'),
   'update',has_any_column_privilege(r,to_regclass('public.billing_scan_runs'),'UPDATE'),
   'delete',has_table_privilege(r,to_regclass('public.billing_scan_runs'),'DELETE'),
   'truncate',has_table_privilege(r,to_regclass('public.billing_scan_runs'),'TRUNCATE')))
   from unnest(array['anon','authenticated','service_role']) r),
 'functions',(select jsonb_agg(jsonb_build_object('signature',s.signature,
   'installed',p.oid is not null,'owner',pg_get_userbyid(p.proowner),
   'security_definer',p.prosecdef,'settings',p.proconfig,
   'anon_execute',has_function_privilege('anon',p.oid,'EXECUTE'),
   'authenticated_execute',has_function_privilege('authenticated',p.oid,'EXECUTE'),
   'service_execute',has_function_privilege('service_role',p.oid,'EXECUTE')))
   from signatures s left join pg_proc p on p.oid=to_regprocedure(s.signature)),
 'indexes',(select jsonb_agg(jsonb_build_object('name',c.relname,
   'unique',i.indisunique,'valid',i.indisvalid,'definition',pg_get_indexdef(i.indexrelid)))
   from pg_index i join pg_class c on c.oid=i.indexrelid
   where i.indrelid=to_regclass('public.billing_scan_runs')),
 'spend_respects_hold',(select position('billing_scan_runs' in pg_get_functiondef(p.oid))>0
   from pg_proc p where p.oid=to_regprocedure('public.billing_spend(text,text)'))
) as billing_scan_reservation_postcheck;
