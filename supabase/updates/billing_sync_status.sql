-- ORIGINAL. Review then run separately; NOT executed by Codex.
-- Adds a read-only RPC and its permissions. No profile/credit/ledger writes.
begin;
set local lock_timeout = '5s';
set local statement_timeout = '30s';
do $$ begin
  if current_user <> 'postgres' then raise exception 'Trusted postgres owner required'; end if;
  if to_regclass('public.billing_purchases') is null
     or to_regprocedure('public.billing_internal_access()') is null then
    raise exception 'Compatible billing package must be installed first';
  end if;
end $$;
create or replace function public.billing_sync_status(p_checkout text default null)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare uid uuid := auth.uid(); email_auth text; u public.usuarios; profile jsonb;
begin
  if uid is null then raise exception 'Authentication required'; end if;
  if p_checkout is not null and (length(p_checkout)>255 or p_checkout !~ '^cs_[A-Za-z0-9_]+$') then
    raise exception 'Invalid Checkout identifier';
  end if;
  select email into strict email_auth from auth.users where id=uid;
  select * into strict u from public.usuarios where billing_user_id=uid or
    (billing_user_id is null and email collate "C"=email_auth collate "C");
  profile := jsonb_build_object('email',u.email,'plan_activo',u.plan_activo,
    'billing_status',u.billing_status,'billing_period_end',u.billing_period_end,
    'fecha_vencimiento',u.fecha_vencimiento,'cancelacion_pendiente',u.cancelacion_pendiente,
    'tokens_pro',u.tokens_pro,'tokens_ent',u.tokens_ent,'tokens_pdf',u.tokens_pdf);
  return jsonb_build_object('profile',profile,
    'checkout_applied',p_checkout is not null and exists(
      select 1 from public.billing_purchases where user_id=uid and checkout_id=p_checkout));
end $$;
revoke all on function public.billing_sync_status(text) from public,anon,authenticated;
grant execute on function public.billing_sync_status(text) to authenticated;
commit;
