-- ============================================================================
-- Giới hạn quyền SỬA theo từng NGÀNH (Plumbing/HVAC/Mechanical Piping/Fire
-- Protection/Electrical) cho NHÂN VIÊN trong một dự án.
--
--   • Trưởng dự án / Admin: KHÔNG bị giới hạn — luôn sửa được mọi ngành
--     trong dự án của mình, như hiện tại.
--   • Nhân viên: mặc định KHÔNG bị giới hạn (giữ nguyên hành vi hiện tại,
--     an toàn cho tất cả nhân viên đang dùng). Chỉ khi Trưởng dự án/Admin
--     chủ động chọn ít nhất 1 ngành cho một nhân viên (ở màn hình
--     "✅ Duyệt thành viên") thì người đó mới bị giới hạn CHỈ sửa được
--     đúng (các) ngành đã chọn — mọi ngành khác trong dự án tự chuyển
--     sang chỉ xem (nhìn thấy tiến độ nhưng không tích/chọn được).
--
-- AN TOÀN CHO NGƯỜI ĐANG DÙNG: không ai bị mất quyền khi chạy file này —
-- vì "chưa được gán ngành nào" = không giới hạn, giống hệt trước khi có
-- tính năng này.
--
-- Yêu cầu: đã chạy add_admin_lead_roles.sql trước đó (cần bảng app_admins,
-- cột project_members.role/status).
--
-- An toàn để chạy lại nhiều lần (idempotent). Chạy TOÀN BỘ file này trong
-- Supabase Dashboard → SQL Editor → New query → Run.
-- ============================================================================

-- 1) Bảng lưu (các) ngành mà 1 nhân viên được phép SỬA trong 1 dự án.
create table if not exists public.project_member_trades (
  project_id uuid not null references public.projects(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  trade text not null,
  granted_by uuid,
  granted_at timestamptz not null default now(),
  primary key (project_id, user_id, trade)
);
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'project_member_trades_trade_check') then
    alter table public.project_member_trades add constraint project_member_trades_trade_check
      check (trade in ('plumbing','hvac','mp','fp','el'));
  end if;
end $$;
alter table public.project_member_trades enable row level security;

do $$ begin execute (select coalesce(string_agg(format('drop policy %I on public.project_member_trades;', policyname), ' '), 'select 1;') from pg_policies where schemaname='public' and tablename='project_member_trades'); end $$;

create policy "project_member_trades_select_members" on public.project_member_trades
  for select to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = project_member_trades.project_id and m.user_id = auth.uid() and m.status = 'approved')
  );
create policy "project_member_trades_write_leads" on public.project_member_trades
  for insert to authenticated with check (
    exists (select 1 from public.app_admins a where a.user_id = auth.uid())
    or exists (select 1 from public.project_members m where m.project_id = project_member_trades.project_id and m.user_id = auth.uid() and m.status = 'approved' and m.role = 'lead')
  );
create policy "project_member_trades_delete_leads" on public.project_member_trades
  for delete to authenticated using (
    exists (select 1 from public.app_admins a where a.user_id = auth.uid())
    or exists (select 1 from public.project_members m where m.project_id = project_member_trades.project_id and m.user_id = auth.uid() and m.status = 'approved' and m.role = 'lead')
  );

-- 2) Suy ra ngành của 1 item_id từ tiền tố id — ĐÚNG theo quy ước
--    TRADE_ID_PREFIX trong build_phase_page.py: không tiền tố = plumbing,
--    'hv-' = hvac, 'mp-' = mp, 'fp-' = fp, 'el-' = el.
create or replace function public.item_trade(p_item_id text) returns text
language sql immutable as $$
  select case
    when p_item_id like 'hv-%' then 'hvac'
    when p_item_id like 'mp-%' then 'mp'
    when p_item_id like 'fp-%' then 'fp'
    when p_item_id like 'el-%' then 'el'
    else 'plumbing'
  end;
$$;

-- 3) Dùng chung cho mọi policy bên dưới: được sửa item_id này trong dự án
--    này không? Đúng nếu là Lead/Admin, HOẶC người này chưa bị giới hạn
--    ngành nào cả (không có dòng nào trong project_member_trades), HOẶC có
--    1 dòng đúng khớp ngành của item_id đó.
create or replace function public.can_edit_item_trade(p_project_id uuid, p_user_id uuid, p_item_id text) returns boolean
language sql stable as $$
  select
    exists (select 1 from public.app_admins a where a.user_id = p_user_id)
    or exists (select 1 from public.project_members m where m.project_id = p_project_id and m.user_id = p_user_id and m.status = 'approved' and m.role = 'lead')
    or not exists (select 1 from public.project_member_trades t where t.project_id = p_project_id and t.user_id = p_user_id)
    or exists (select 1 from public.project_member_trades t where t.project_id = p_project_id and t.user_id = p_user_id and t.trade = public.item_trade(p_item_id));
$$;

-- 4) Trưởng dự án/Admin thay TOÀN BỘ danh sách ngành của 1 nhân viên trong 1
--    lần gọi (dùng cả lúc duyệt thành viên mới lẫn chỉnh lại sau này).
--    Truyền mảng rỗng = bỏ hết giới hạn (về lại "không giới hạn").
create or replace function public.set_member_trades(p_project_id uuid, p_user_id uuid, p_trades text[])
returns void language plpgsql security definer set search_path = public as $$
begin
  if not (
    exists (select 1 from public.app_admins a where a.user_id = auth.uid())
    or exists (select 1 from public.project_members m where m.project_id = p_project_id and m.user_id = auth.uid() and m.status = 'approved' and m.role = 'lead')
  ) then
    raise exception 'NOT_AUTHORIZED';
  end if;
  delete from public.project_member_trades where project_id = p_project_id and user_id = p_user_id;
  insert into public.project_member_trades (project_id, user_id, trade, granted_by)
    select p_project_id, p_user_id, t, auth.uid() from unnest(p_trades) as t
    on conflict do nothing;
end;
$$;
grant execute on function public.set_member_trades(uuid, uuid, text[]) to authenticated;

-- 5) Thêm điều kiện can_edit_item_trade(...) vào các policy GHI (insert/
--    update/delete) trên progress / item_confirmations / item_extra_checks /
--    item_check2 — CHỈ SIẾT CHẶT thêm, không nới lỏng gì so với trước
--    (mọi điều kiện approved-status/ownership cũ đều giữ nguyên).

do $$ begin execute (select coalesce(string_agg(format('drop policy %I on public.progress;', policyname), ' '), 'select 1;') from pg_policies where schemaname='public' and tablename='progress'); end $$;
create policy "progress_select_members" on public.progress
  for select to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = progress.project_id and m.user_id = auth.uid() and m.status = 'approved')
  );
create policy "progress_write_members" on public.progress
  for insert to authenticated with check (
    exists (select 1 from public.project_members m where m.project_id = progress.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and public.can_edit_item_trade(progress.project_id, auth.uid(), progress.item_id)
  );
create policy "progress_update_members" on public.progress
  for update to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = progress.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and public.can_edit_item_trade(progress.project_id, auth.uid(), progress.item_id)
  );
create policy "progress_delete_members" on public.progress
  for delete to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = progress.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and public.can_edit_item_trade(progress.project_id, auth.uid(), progress.item_id)
  );

do $$ begin execute (select coalesce(string_agg(format('drop policy %I on public.item_confirmations;', policyname), ' '), 'select 1;') from pg_policies where schemaname='public' and tablename='item_confirmations'); end $$;
create policy "item_confirmations_select_members" on public.item_confirmations
  for select to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = item_confirmations.project_id and m.user_id = auth.uid() and m.status = 'approved')
  );
create policy "item_confirmations_write_own" on public.item_confirmations
  for insert to authenticated with check (
    user_id = auth.uid()
    and exists (select 1 from public.project_members m where m.project_id = item_confirmations.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and exists (select 1 from public.item_assignees a where a.project_id = item_confirmations.project_id and a.item_id = item_confirmations.item_id and a.user_id = auth.uid())
    and public.can_edit_item_trade(item_confirmations.project_id, auth.uid(), item_confirmations.item_id)
  );
create policy "item_confirmations_update_own" on public.item_confirmations
  for update to authenticated
  using (user_id = auth.uid())
  with check (
    user_id = auth.uid()
    and exists (select 1 from public.project_members m where m.project_id = item_confirmations.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and exists (select 1 from public.item_assignees a where a.project_id = item_confirmations.project_id and a.item_id = item_confirmations.item_id and a.user_id = auth.uid())
    and public.can_edit_item_trade(item_confirmations.project_id, auth.uid(), item_confirmations.item_id)
  );
create policy "item_confirmations_delete_members" on public.item_confirmations
  for delete to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = item_confirmations.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and public.can_edit_item_trade(item_confirmations.project_id, auth.uid(), item_confirmations.item_id)
  );

do $$ begin execute (select coalesce(string_agg(format('drop policy %I on public.item_extra_checks;', policyname), ' '), 'select 1;') from pg_policies where schemaname='public' and tablename='item_extra_checks'); end $$;
create policy "item_extra_checks_select_members" on public.item_extra_checks
  for select to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = item_extra_checks.project_id and m.user_id = auth.uid() and m.status = 'approved')
  );
create policy "item_extra_checks_write_members" on public.item_extra_checks
  for insert to authenticated with check (
    exists (select 1 from public.project_members m where m.project_id = item_extra_checks.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and public.can_edit_item_trade(item_extra_checks.project_id, auth.uid(), item_extra_checks.item_id)
  );
create policy "item_extra_checks_update_members" on public.item_extra_checks
  for update to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = item_extra_checks.project_id and m.user_id = auth.uid() and m.status = 'approved')
  ) with check (
    exists (select 1 from public.project_members m where m.project_id = item_extra_checks.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and public.can_edit_item_trade(item_extra_checks.project_id, auth.uid(), item_extra_checks.item_id)
  );
create policy "item_extra_checks_delete_members" on public.item_extra_checks
  for delete to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = item_extra_checks.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and public.can_edit_item_trade(item_extra_checks.project_id, auth.uid(), item_extra_checks.item_id)
  );

do $$ begin execute (select coalesce(string_agg(format('drop policy %I on public.item_check2;', policyname), ' '), 'select 1;') from pg_policies where schemaname='public' and tablename='item_check2'); end $$;
create policy "item_check2_select_members" on public.item_check2
  for select to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = item_check2.project_id and m.user_id = auth.uid() and m.status = 'approved')
  );
create policy "item_check2_write_members" on public.item_check2
  for insert to authenticated with check (
    exists (select 1 from public.project_members m where m.project_id = item_check2.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and public.can_edit_item_trade(item_check2.project_id, auth.uid(), item_check2.item_id)
  );
create policy "item_check2_update_members" on public.item_check2
  for update to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = item_check2.project_id and m.user_id = auth.uid() and m.status = 'approved')
  ) with check (
    exists (select 1 from public.project_members m where m.project_id = item_check2.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and public.can_edit_item_trade(item_check2.project_id, auth.uid(), item_check2.item_id)
  );
create policy "item_check2_delete_members" on public.item_check2
  for delete to authenticated using (
    exists (select 1 from public.project_members m where m.project_id = item_check2.project_id and m.user_id = auth.uid() and m.status = 'approved')
    and public.can_edit_item_trade(item_check2.project_id, auth.uid(), item_check2.item_id)
  );

-- Kiểm tra nhanh sau khi chạy: phải thấy đúng 3 policy trên bảng mới.
select tablename, policyname, cmd
from pg_policies
where schemaname = 'public' and tablename = 'project_member_trades'
order by cmd;
