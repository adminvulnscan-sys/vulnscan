-- SOLO LECTURA: estructura y permisos; no contiene filas de usuarios/clientes.
-- Ejecutar en SQL Editor del proyecto que se quiera identificar/verificar.
select jsonb_build_object(
  'columns', (select jsonb_agg(to_jsonb(c) order by c.table_name,c.ordinal_position)
    from (select table_name,column_name,data_type,is_nullable,column_default,ordinal_position
      from information_schema.columns where table_schema='public'
      and (table_name='usuarios' or table_name like 'billing_%')) c),
  'rls', (select jsonb_agg(jsonb_build_object('table',c.relname,'enabled',c.relrowsecurity,'forced',c.relforcerowsecurity))
    from pg_class c join pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public' and c.relkind in ('r','p')
    and (c.relname='usuarios' or c.relname like 'billing_%')),
  'policies', (select jsonb_agg(to_jsonb(p)) from pg_policies p
    where schemaname='public' and (tablename='usuarios' or tablename like 'billing_%')),
  'triggers', (select jsonb_agg(jsonb_build_object('table',c.relname,'trigger',t.tgname,'enabled',t.tgenabled,'definition',pg_get_triggerdef(t.oid)))
    from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public' and c.relname='usuarios' and not t.tgisinternal),
  'functions', (select jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),
       'security_definer',p.prosecdef,'owner',pg_get_userbyid(p.proowner),'settings',p.proconfig,
       'definition',pg_get_functiondef(p.oid),'acl',p.proacl))
    from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.proname like 'billing_%'),
  'table_grants', (select jsonb_agg(to_jsonb(g)) from information_schema.table_privileges g
    where table_schema='public' and (table_name='usuarios' or table_name like 'billing_%')),
  'column_grants', (select jsonb_agg(to_jsonb(g)) from information_schema.column_privileges g
    where table_schema='public' and table_name='usuarios'
    and column_name in ('stripe_customer_id','stripe_subscription_id','billing_user_id','tokens_pro','tokens_ent','tokens_pdf','plan_activo'))
) as billing_schema_metadata;
