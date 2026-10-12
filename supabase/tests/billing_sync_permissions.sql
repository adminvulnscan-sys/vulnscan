-- ONLY READS metadata. No fixtures, accounts or data changes. ORIGINAL.
select jsonb_build_object(
 'installed',to_regprocedure('public.billing_sync_status(text)') is not null,
 'rpc',(select jsonb_build_object('owner',pg_get_userbyid(p.proowner),
   'security_definer',p.prosecdef,'settings',p.proconfig,
   'anon_execute',has_function_privilege('anon',p.oid,'EXECUTE'),
   'authenticated_execute',has_function_privilege('authenticated',p.oid,'EXECUTE'))
   from pg_proc p where p.oid=to_regprocedure('public.billing_sync_status(text)')),
 'ledger_access',has_table_privilege('authenticated','public.billing_purchases','SELECT')
) as billing_sync_permissions;
