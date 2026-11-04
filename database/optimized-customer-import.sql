CREATE OR REPLACE FUNCTION service_private.import_dealership_list(dealership uuid, list_name text, owner_email text, records jsonb, update_existing boolean DEFAULT false)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare new_list uuid; r record; ids uuid[]; target uuid; added integer:=0; refreshed integer:=0; skipped integer:=0; ambiguous integer:=0;
begin
 if auth.uid() is null or service_private.store_role(dealership) is distinct from 'manager' then raise exception 'Only managers can import lists.';end if;
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
revoke all on function service_private.import_dealership_list(uuid,text,text,jsonb,boolean) from public,anon;
grant execute on function service_private.import_dealership_list(uuid,text,text,jsonb,boolean) to authenticated;
create or replace function public.sc_import_dealership_list(dealership uuid,list_name text,owner_email text,records jsonb,update_existing boolean default false) returns jsonb language sql security invoker set search_path='' as $$
 select service_private.import_dealership_list(dealership,list_name,owner_email,records,update_existing);
$$;
revoke all on function public.sc_import_dealership_list(uuid,text,text,jsonb,boolean) from public,anon;
grant execute on function public.sc_import_dealership_list(uuid,text,text,jsonb,boolean) to authenticated;
