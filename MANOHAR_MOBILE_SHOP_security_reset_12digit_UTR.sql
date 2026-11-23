-- MANOHAR MOBILE SHOP — Fresh Start + Security Hardening
-- IMPORTANT: This permanently deletes every customer account and all orders,
-- while preserving the Supabase Auth account for manoharmobileshop01@gmail.com.
-- Run this entire script once in Supabase Dashboard > SQL Editor as project owner.
-- It does NOT delete website files, product images, app-config.js, UPI settings, or QR images.

begin;

do $$
declare
  v_admin_id uuid;
begin
  select id into v_admin_id
  from auth.users
  where lower(email) = lower('manoharmobileshop01@gmail.com')
  limit 1;

  if v_admin_id is null then
    raise exception 'STOP: Admin Auth account manoharmobileshop01@gmail.com was not found. No customer data was deleted.';
  end if;

  -- Remove all old orders, including any order rows not linked to a current auth user.
  delete from public.orders;

  -- Remove every profile except the Admin profile.
  delete from public.profiles where id <> v_admin_id;

  -- Permanently delete all other Supabase Auth accounts. FK cascade removes their profiles.
  delete from auth.users where id <> v_admin_id;

  -- Ensure the preserved Admin has an Admin profile row.
  insert into public.profiles (id, email, role, created_at, updated_at)
  select id, email, 'admin', now(), now()
  from auth.users
  where id = v_admin_id
  on conflict (id) do update
    set email = excluded.email,
        role = 'admin',
        updated_at = now();
end $$;

-- Ensure UTR cannot be reused on another order (case/space insensitive).
create unique index if not exists orders_unique_upi_utr
on public.orders (lower(trim(upi_transaction_id)))
where upi_transaction_id is not null and length(trim(upi_transaction_id)) > 0;

-- Every non-empty UTR must contain exactly 12 digits.
do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'orders_upi_utr_exactly_12_digits'
      and conrelid = 'public.orders'::regclass
  ) then
    alter table public.orders
      add constraint orders_upi_utr_exactly_12_digits
      check (
        upi_transaction_id is null
        or btrim(upi_transaction_id) = ''
        or btrim(upi_transaction_id) ~ '^[0-9]{12}$'
      );
  end if;
end $$;

-- Keep role and order/payment-critical fields protected even if a permissive policy is added later.
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  );
$$;

create or replace function public.mms_guard_profile_changes()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- Trusted SQL / service operations (no authenticated user context) are allowed.
  if auth.uid() is null or public.is_admin() then
    return new;
  end if;
  if new.id is distinct from old.id or new.role is distinct from old.role then
    raise exception 'Customers cannot change account ID or role.';
  end if;
  return new;
end;
$$;

drop trigger if exists mms_guard_profile_changes on public.profiles;
create trigger mms_guard_profile_changes
before update on public.profiles
for each row execute function public.mms_guard_profile_changes();

create or replace function public.mms_guard_customer_order_changes()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null or public.is_admin() then
    if new.payment_status = 'verified' and old.payment_status is distinct from 'verified' then
      new.payment_status_verified_at := coalesce(new.payment_status_verified_at, now());
    end if;
    return new;
  end if;

  if old.customer_id <> auth.uid() or new.customer_id is distinct from old.customer_id
     or new.order_id is distinct from old.order_id
     or new.customer_name is distinct from old.customer_name
     or new.customer_phone is distinct from old.customer_phone
     or new.address is distinct from old.address
     or new.city is distinct from old.city
     or new.pin is distinct from old.pin
     or new.landmark is distinct from old.landmark
     or new.items is distinct from old.items
     or new.total is distinct from old.total
     or new.payment_method is distinct from old.payment_method
     or new.payment_status is distinct from old.payment_status
     or new.upi_transaction_id is distinct from old.upi_transaction_id
     or new.payment_status_verified_at is distinct from old.payment_status_verified_at
     or new.tracking_number is distinct from old.tracking_number then
    raise exception 'Customers may not change order, amount, UTR, or payment verification details.';
  end if;

  -- Customer cancellation is allowed only while the order is still New.
  if new.status is distinct from old.status
     and not (old.status = 'New' and new.status = 'Cancelled') then
    raise exception 'Customers may only cancel an order before it is confirmed.';
  end if;
  return new;
end;
$$;

drop trigger if exists mms_guard_customer_order_changes on public.orders;
create trigger mms_guard_customer_order_changes
before update on public.orders
for each row execute function public.mms_guard_customer_order_changes();

-- Remove all existing policies on these two tables so no older permissive policy remains active.
do $$
declare p record;
begin
  for p in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public' and tablename in ('profiles', 'orders')
  loop
    execute format('drop policy if exists %I on %I.%I', p.policyname, p.schemaname, p.tablename);
  end loop;
end $$;

alter table public.profiles enable row level security;
alter table public.orders enable row level security;

-- Profiles: customers see/edit only their own profile; role changes are trigger-blocked.
create policy mms_profiles_select on public.profiles
for select to authenticated
using (id = auth.uid() or public.is_admin());

create policy mms_profiles_insert on public.profiles
for insert to authenticated
with check (id = auth.uid() and role = 'customer');

create policy mms_profiles_update on public.profiles
for update to authenticated
using (id = auth.uid() or public.is_admin())
with check (id = auth.uid() or public.is_admin());

-- Orders: customers can see only their own; Admin can see all.
create policy mms_orders_select on public.orders
for select to authenticated
using (customer_id = auth.uid() or public.is_admin());

-- New UPI orders are submitted with a UTR. COD remains possible if enabled later in the site.
create policy mms_orders_insert on public.orders
for insert to authenticated
with check (
  customer_id = auth.uid()
  and status = 'New'
  and (
    (payment_method = 'upi' and payment_status = 'submitted'
      and upi_transaction_id is not null
      and btrim(upi_transaction_id) ~ '^[0-9]{12}$')
    or
    (payment_method = 'cod' and payment_status = 'pending'
      and coalesce(trim(upi_transaction_id), '') = '')
  )
);

-- Customer updates are restricted by the trigger above (only pre-confirmation cancellation / note updates).
create policy mms_orders_customer_update on public.orders
for update to authenticated
using (customer_id = auth.uid())
with check (customer_id = auth.uid());

create policy mms_orders_admin_update on public.orders
for update to authenticated
using (public.is_admin())
with check (public.is_admin());

create policy mms_orders_admin_delete on public.orders
for delete to authenticated
using (public.is_admin());

commit;

-- Verification: exactly one Admin profile should remain; zero orders should remain.
select id, email, role from public.profiles;
select count(*) as remaining_orders from public.orders;
select count(*) as remaining_auth_accounts_except_admin
from auth.users
where lower(email) <> lower('manoharmobileshop01@gmail.com');
