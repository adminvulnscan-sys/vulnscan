-- Preparación local. No concede planes ni créditos y no sustituye la revisión RLS.
begin;
alter table public.usuarios
  add column if not exists stripe_customer_id text,
  add column if not exists stripe_subscription_id text;
create unique index if not exists usuarios_stripe_subscription_unique
  on public.usuarios (stripe_subscription_id)
  where stripe_subscription_id is not null;
commit;
