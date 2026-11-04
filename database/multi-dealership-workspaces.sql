create table public.sc_dealerships(id uuid primary key default gen_random_uuid(),name text not null unique check(length(trim(name)) between 1 and 100),created_at timestamptz not null default now());
alter table public.sc_dealerships enable row level security;
insert into public.sc_dealerships(id,name) values('10000000-0000-4000-8000-000000000001','Subaru'),('10000000-0000-4000-8000-000000000002','Spreen Acura');
alter table public.sc_staff add column is_group_admin boolean not null default false;
update public.sc_staff set is_group_admin=true where email='justice@spreen.net';
create table public.sc_store_access(dealership_id uuid not null references public.sc_dealerships(id),staff_email text not null references public.sc_staff(email),role text not null check(role in ('manager','employee')),primary key(dealership_id,staff_email));
create index sc_store_access_email on public.sc_store_access(staff_email);
alter table public.sc_store_access enable row level security;
insert into public.sc_store_access(dealership_id,staff_email,role) select '10000000-0000-4000-8000-000000000001',email,role from public.sc_staff;
insert into public.sc_store_access(dealership_id,staff_email,role) values('10000000-0000-4000-8000-000000000002','justice@spreen.net','manager');
alter table public.sc_lists add column dealership_id uuid not null default '10000000-0000-4000-8000-000000000001' references public.sc_dealerships(id);
alter table public.sc_customers add column dealership_id uuid not null default '10000000-0000-4000-8000-000000000001' references public.sc_dealerships(id);
create index sc_lists_dealership on public.sc_lists(dealership_id);
create index sc_customers_dealership on public.sc_customers(dealership_id);
create function service_private.group_admin() returns boolean language sql stable security definer set search_path='' as $$
select coalesce((select s.is_group_admin from public.sc_staff s where s.email=service_private.staff_email() and s.active and service_private.staff_role() is not null),false)
$$;
create function service_private.store_role(store_id uuid) returns text language sql stable security definer set search_path='' as $$
select case when service_private.group_admin() then 'manager' else (select a.role from public.sc_store_access a where a.dealership_id=store_id and a.staff_email=service_private.staff_email() and service_private.staff_role() is not null) end
$$;
create function service_private.see_staff(target_email text) returns boolean language sql stable security definer set search_path='' as $$
select service_private.staff_role() is not null and (target_email=service_private.staff_email() or service_private.group_admin() or exists(select 1 from public.sc_store_access a where a.staff_email=target_email and service_private.store_role(a.dealership_id)='manager'))
$$;
revoke all on function service_private.group_admin(),service_private.store_role(uuid),service_private.see_staff(text) from public,anon;
grant execute on function service_private.group_admin(),service_private.store_role(uuid),service_private.see_staff(text) to authenticated;
do $$declare r record;begin for r in select tablename,policyname from pg_policies where schemaname='public' and tablename in ('sc_staff','sc_lists','sc_customers','sc_activity','sc_list_customers') loop execute format('drop policy %I on public.%I',r.policyname,r.tablename);end loop;end$$;
revoke all on public.sc_dealerships,public.sc_store_access from anon,authenticated;
grant select on public.sc_dealerships,public.sc_store_access to authenticated;
revoke insert,update,delete on public.sc_staff from authenticated;
create policy dealership_read on public.sc_dealerships for select to authenticated using(service_private.store_role(id) is not null);
create policy access_read on public.sc_store_access for select to authenticated using(service_private.group_admin() or (service_private.staff_role() is not null and staff_email=service_private.staff_email()) or service_private.store_role(dealership_id)='manager');
create policy staff_read_scoped on public.sc_staff for select to authenticated using(service_private.see_staff(email));
create policy lists_read_scoped on public.sc_lists for select to authenticated using(service_private.store_role(dealership_id) is not null);
create policy lists_manage_scoped on public.sc_lists for all to authenticated using(service_private.store_role(dealership_id)='manager') with check(service_private.store_role(dealership_id)='manager');
create policy customers_read_scoped on public.sc_customers for select to authenticated using(service_private.store_role(dealership_id)='manager' or (service_private.store_role(dealership_id)='employee' and assigned_email=service_private.staff_email()));
create policy customers_manage_scoped on public.sc_customers for all to authenticated using(service_private.store_role(dealership_id)='manager') with check(service_private.store_role(dealership_id)='manager');
create policy activity_read_scoped on public.sc_activity for select to authenticated using(exists(select 1 from public.sc_customers c where c.id=customer_id and (service_private.store_role(c.dealership_id)='manager' or employee_email=service_private.staff_email())));
create policy activity_insert_scoped on public.sc_activity for insert to authenticated with check(employee_email=service_private.staff_email() and created_at=now() and exists(select 1 from public.sc_customers c where c.id=customer_id));
create policy activity_update_scoped on public.sc_activity for update to authenticated using(exists(select 1 from public.sc_customers c where c.id=customer_id and (service_private.store_role(c.dealership_id)='manager' or employee_email=service_private.staff_email()))) with check(exists(select 1 from public.sc_customers c where c.id=customer_id and (service_private.store_role(c.dealership_id)='manager' or employee_email=service_private.staff_email())));
create policy membership_read_scoped on public.sc_list_customers for select to authenticated using(exists(select 1 from public.sc_customers c where c.id=customer_id));
create policy membership_insert_scoped on public.sc_list_customers for insert to authenticated with check(exists(select 1 from public.sc_lists l where l.id=list_id and service_private.store_role(l.dealership_id)='manager') and exists(select 1 from public.sc_customers c join public.sc_lists l on l.dealership_id=c.dealership_id where l.id=list_id and c.id=customer_id));
create policy membership_update_scoped on public.sc_list_customers for update to authenticated using(exists(select 1 from public.sc_lists l where l.id=list_id and service_private.store_role(l.dealership_id)='manager')) with check(exists(select 1 from public.sc_lists l where l.id=list_id and service_private.store_role(l.dealership_id)='manager') and exists(select 1 from public.sc_customers c join public.sc_lists l on l.dealership_id=c.dealership_id where l.id=list_id and c.id=customer_id));
create function service_private.validate_customer_store() returns trigger language plpgsql security invoker set search_path='' as $$
begin
 if tg_op='UPDATE' and new.dealership_id<>old.dealership_id then raise exception 'Customer records cannot be moved between dealerships.';end if;
 if not exists(select 1 from public.sc_lists l where l.id=new.list_id and l.dealership_id=new.dealership_id) then raise exception 'Customer and list must belong to the same dealership.';end if;
 if new.assigned_email is not null and not exists(select 1 from public.sc_store_access a join public.sc_staff s on s.email=a.staff_email where a.dealership_id=new.dealership_id and a.staff_email=new.assigned_email and s.active) then raise exception 'Assign an active user with access to this dealership.';end if;
 return new;
end $$;
revoke all on function service_private.validate_customer_store() from public,anon,authenticated;
create trigger sc_validate_customer_store before insert or update of list_id,dealership_id,assigned_email on public.sc_customers for each row execute function service_private.validate_customer_store();
create function service_private.lock_list_store() returns trigger language plpgsql security invoker set search_path='' as $$
begin if new.dealership_id<>old.dealership_id then raise exception 'Lists cannot be moved between dealerships.';end if;return new;end$$;
revoke all on function service_private.lock_list_store() from public,anon,authenticated;
create trigger sc_lock_list_store before update on public.sc_lists for each row execute function service_private.lock_list_store();
CREATE OR REPLACE FUNCTION public.sc_import_dealership_list(dealership uuid, list_name text, owner_email text, records jsonb, update_existing boolean DEFAULT false)
 RETURNS jsonb
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
declare new_list uuid; r record; ids uuid[]; target uuid; added integer:=0; refreshed integer:=0; skipped integer:=0; ambiguous integer:=0;
begin
 if service_private.store_role(dealership) is distinct from 'manager' then raise exception 'Only managers can import lists.';end if;
 if list_name is null or length(trim(list_name)) not between 1 and 200 then raise exception 'Enter a list name (1–200 characters).';end if;
 if records is null or jsonb_typeof(records)<>'array' or jsonb_array_length(records) not between 1 and 5000 then raise exception 'Import 1–5000 rows.';end if;
 perform pg_advisory_xact_lock(193810,782);
 insert into public.sc_lists(name,dealership_id) values(trim(list_name),dealership) returning id into new_list;
 for r in select * from jsonb_to_recordset(records) as x(name text,first_name text,last_name text,vehicle text,phone text,email text,vin text,last_service_date date,mileage bigint,declined_services text)
 loop
 select array_agg(c.id) into ids from public.sc_customers c
 where c.dealership_id=dealership and lower(regexp_replace(trim(c.name),'[[:space:]]+',' ','g'))=lower(regexp_replace(trim(r.name),'[[:space:]]+',' ','g'))
 and ((coalesce(trim(r.vin),'')<>'' and upper(trim(c.vin))=upper(trim(r.vin)))
 or (coalesce(trim(r.vin),'')='' and lower(trim(c.vehicle))=lower(trim(r.vehicle)) and
 ((coalesce(r.phone,'')<>'' and regexp_replace(c.phone,'[^0-9]','','g')=regexp_replace(r.phone,'[^0-9]','','g'))
 or (coalesce(r.email,'')<>'' and lower(trim(c.email))=lower(trim(r.email))))));
 if coalesce(cardinality(ids),0)>1 then ambiguous:=ambiguous+1;continue;end if;
 if cardinality(ids)=1 then
 target:=ids[1];
 if update_existing then
 update public.sc_customers c set
 first_name=coalesce(nullif(r.first_name,''),c.first_name),
 last_name=coalesce(nullif(r.last_name,''),c.last_name),
 vehicle=coalesce(nullif(r.vehicle,''),c.vehicle),
 phone=coalesce(nullif(r.phone,''),c.phone),
 email=coalesce(nullif(r.email,''),c.email),
 vin=coalesce(nullif(upper(trim(r.vin)),''),c.vin),
 mileage=case when r.mileage is null then c.mileage when c.last_service_date is null or (r.last_service_date is not null and r.last_service_date>=c.last_service_date) then r.mileage when c.mileage is null and r.last_service_date is null then r.mileage else c.mileage end,
 last_service_date=greatest(c.last_service_date,r.last_service_date)
 where c.id=target;
 refreshed:=refreshed+1;
 else skipped:=skipped+1;end if;
 else
 insert into public.sc_customers(list_id,name,first_name,last_name,vehicle,phone,email,vin,last_service_date,mileage,assigned_email,dealership_id)
 values(new_list,r.name,coalesce(r.first_name,''),coalesce(r.last_name,''),coalesce(r.vehicle,''),coalesce(r.phone,''),coalesce(r.email,''),coalesce(upper(trim(r.vin)),''),r.last_service_date,r.mileage,owner_email,dealership)
 returning id into target;
 added:=added+1;
 end if;
 insert into public.sc_list_customers as existing(list_id,customer_id,declined_services) values(new_list,target,coalesce(r.declined_services,''))
 on conflict(list_id,customer_id) do update set declined_services=
 case when existing.declined_services='' then excluded.declined_services when excluded.declined_services='' or existing.declined_services=excluded.declined_services then existing.declined_services else existing.declined_services||chr(10)||excluded.declined_services end;
 end loop;
 return jsonb_build_object('list_id',new_list,'added',added,'updated',refreshed,'existing_unchanged',skipped,'ambiguous_skipped',ambiguous);
end $function$
;
revoke all on function public.sc_import_dealership_list(uuid,text,text,jsonb,boolean) from public,anon;
grant execute on function public.sc_import_dealership_list(uuid,text,text,jsonb,boolean) to authenticated;
revoke execute on function public.sc_import_customer_list(text,text,jsonb,boolean),public.sc_import_customers(text,text,jsonb) from authenticated,anon,public;
CREATE OR REPLACE FUNCTION service_private.save_call_attempt(customer uuid, contact boolean, voicemail boolean, appointment boolean, opt_out boolean, note text, followup_date date)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare c public.sc_customers; actor text; staff_role text; key text; saved uuid; was_cleared boolean:=false;
begin
 actor:=service_private.staff_email();staff_role:=service_private.staff_role();
 if auth.uid() is null or staff_role is null then raise exception 'Sign in with two-factor verification to save this update.';end if;
 select * into c from public.sc_customers where id=customer for update;
 if not found or service_private.store_role(c.dealership_id) is null or (service_private.store_role(c.dealership_id)<>'manager' and c.assigned_email is distinct from actor) then raise exception 'You do not have access to this customer.';end if;
 if opt_out is null then raise exception 'Choose a do-not-call setting.';end if;
 if length(coalesce(note,''))>5000 then raise exception 'Notes must be 5000 characters or fewer.';end if;
 key:=service_private.normalize_phone(c.phone);
 if not opt_out and c.do_not_call then
 if key is not null then
 delete from service_private.sc_phone_opt_out where phone_key=key;
 update public.sc_customers set do_not_call=false where service_private.normalize_phone(phone)=key;
 else update public.sc_customers set do_not_call=false where id=customer;end if;
 was_cleared:=true;
 end if;
 insert into public.sc_activity(customer_id,employee_email,made_contact,left_voicemail,booked,do_not_call,notes,followup,do_not_call_cleared)
 values(customer,actor,coalesce(contact,false),coalesce(voicemail,false),coalesce(appointment,false),opt_out,
 coalesce(note,''),followup_date,was_cleared)
 returning id into saved;
 return saved;
end $function$
;
CREATE OR REPLACE FUNCTION service_private.persist_opt_out()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
 if auth.uid() is null or service_private.staff_role() is null then raise exception 'Unauthorized'; end if;
 if new.do_not_call then
 update public.sc_customers set do_not_call=true where id=new.customer_id and (service_private.store_role(dealership_id)='manager' or (service_private.store_role(dealership_id)='employee' and assigned_email=service_private.staff_email()));
 end if; return new;
end $function$
;
create table service_private.sc_access_audit(id uuid primary key default gen_random_uuid(),actor text not null,target text,dealership_id uuid,action text not null,created_at timestamptz not null default now());
alter table service_private.sc_access_audit enable row level security;
revoke all on service_private.sc_access_audit from public,anon,authenticated;
create function service_private.manage_user(store uuid,target_email text,display_name text,store_role text,operation text) returns void language plpgsql security definer set search_path='' as $$
declare actor text:=service_private.staff_email(); target text:=lower(trim(target_email)); target_admin boolean;
begin
 if auth.uid() is null or service_private.store_role(store) is distinct from 'manager' then raise exception 'Manager access to this dealership is required.';end if;
 if operation not in('add','rename','remove') then raise exception 'Invalid user operation.';end if;
 if target is null or target !~ '^[^[:space:]@]+@[^[:space:]@]+[.][^[:space:]@]+$' then raise exception 'Enter a valid email.';end if;
 if operation in('add','rename') and (display_name is null or length(trim(display_name)) not between 1 and 100) then raise exception 'Enter a name (1–100 characters).';end if;
 select is_group_admin into target_admin from public.sc_staff where email=target;
 if target_admin and not service_private.group_admin() and target<>actor then raise exception 'Group administrator accounts are managed by a group administrator.';end if;
 if operation='add' then
 if store_role not in('manager','employee') or store_role is null then raise exception 'Choose Manager or Employee.';end if;
 insert into public.sc_staff(email,name,role) values(target,trim(display_name),'employee') on conflict do nothing;
 if exists(select 1 from public.sc_staff where email=target and not active) then if service_private.group_admin() then update public.sc_staff set active=true where email=target;else raise exception 'This account is disabled. Contact the group administrator.';end if;end if;
 insert into public.sc_store_access(dealership_id,staff_email,role) values(store,target,store_role) on conflict(dealership_id,staff_email) do update set role=excluded.role;
 elsif operation='rename' then
 if not (service_private.group_admin() or target=actor or exists(select 1 from public.sc_store_access where dealership_id=store and staff_email=target)) then raise exception 'User is not in this dealership.';end if;
 update public.sc_staff set name=trim(display_name) where email=target;
 else
 if target=actor or coalesce(target_admin,false) then raise exception 'You cannot remove your own or a group administrator account.';end if;
 delete from public.sc_store_access where dealership_id=store and staff_email=target;
 end if;
 insert into service_private.sc_access_audit(actor,target,dealership_id,action) values(actor,target,store,operation);
end $$;
revoke all on function service_private.manage_user(uuid,text,text,text,text) from public,anon;
grant execute on function service_private.manage_user(uuid,text,text,text,text) to authenticated;
create function public.sc_manage_user(store uuid,target_email text,display_name text,store_role text,operation text) returns void language sql security invoker set search_path='' as $$select service_private.manage_user(store,target_email,display_name,store_role,operation);$$;
revoke all on function public.sc_manage_user(uuid,text,text,text,text) from public,anon;
grant execute on function public.sc_manage_user(uuid,text,text,text,text) to authenticated;
create function service_private.set_user_stores(target_email text,grants jsonb) returns void language plpgsql security definer set search_path='' as $$
declare target text:=lower(trim(target_email));g record;
begin
 if auth.uid() is null or not service_private.group_admin() then raise exception 'Group administrator access is required.';end if;
 if not exists(select 1 from public.sc_staff where email=target and active) then raise exception 'User must be an active approved account.';end if;
 if exists(select 1 from public.sc_staff where email=target and is_group_admin) then raise exception 'Group administrators already have access to every dealership.';end if;
 if grants is null or jsonb_typeof(grants)<>'array' or jsonb_array_length(grants)>100 then raise exception 'Invalid dealership access selection.';end if;
 delete from public.sc_store_access where staff_email=target;
 for g in select * from jsonb_to_recordset(grants) as x(dealership_id uuid,role text)
 loop
 if g.role is null or g.role not in('employee','manager') then raise exception 'Choose a role for each dealership.';end if;
 insert into public.sc_store_access(dealership_id,staff_email,role) values(g.dealership_id,target,g.role);
 end loop;
 insert into service_private.sc_access_audit(actor,target,action) values(service_private.staff_email(),target,'set dealership permissions');
end $$;
revoke all on function service_private.set_user_stores(text,jsonb) from public,anon;
grant execute on function service_private.set_user_stores(text,jsonb) to authenticated;
create function public.sc_set_user_stores(target_email text,grants jsonb) returns void language sql security invoker set search_path='' as $$select service_private.set_user_stores(target_email,grants);$$;
revoke all on function public.sc_set_user_stores(text,jsonb) from public,anon;
grant execute on function public.sc_set_user_stores(text,jsonb) to authenticated;
create function service_private.add_dealership(dealership_name text) returns uuid language plpgsql security definer set search_path='' as $$
declare new_store uuid;
begin
 if auth.uid() is null or not service_private.group_admin() then raise exception 'Group administrator access is required.';end if;
 if dealership_name is null or length(trim(dealership_name)) not between 1 and 100 then raise exception 'Enter a dealership name (1–100 characters).';end if;
 insert into public.sc_dealerships(name) values(trim(dealership_name)) returning id into new_store;
 insert into public.sc_store_access(dealership_id,staff_email,role) values(new_store,service_private.staff_email(),'manager');
 insert into service_private.sc_access_audit(actor,dealership_id,action) values(service_private.staff_email(),new_store,'add dealership');
 return new_store;
end $$;
revoke all on function service_private.add_dealership(text) from public,anon;
grant execute on function service_private.add_dealership(text) to authenticated;
create function public.sc_add_dealership(dealership_name text) returns uuid language sql security invoker set search_path='' as $$select service_private.add_dealership(dealership_name);$$;
revoke all on function public.sc_add_dealership(text) from public,anon;
grant execute on function public.sc_add_dealership(text) to authenticated;

create unique index sc_dealerships_name_normalized on public.sc_dealerships(lower(trim(name)));
