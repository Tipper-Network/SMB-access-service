-- 004_rls_and_grants.sql
-- Row-level security, per-role policies and least-privilege grants.
--
-- Pattern for every tenant table:
--   1. ENABLE ROW LEVEL SECURITY (not FORCE: the migration owner and SECURITY DEFINER
--      functions must still be able to work across tenants. The owner is never used at runtime.)
--   2. A RESTRICTIVE policy "tenant_guard" that pins every row to app.tenant_id.
--      Restrictive policies are ANDed with all others, so a permissive policy added later
--      by mistake can never reach across tenants.
--   3. PERMISSIVE policies that say which ROLE inside the tenant may do what.
--
-- The test suite fails if any table with a tenant_id column lacks RLS + tenant_guard.

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'access.partners', 'access.content_items', 'access.campaigns', 'access.keywords',
    'access.customers', 'access.visitors', 'access.events', 'access.entitlements', 'access.processed_events',
    'payments.gateway_accounts', 'payments.orders', 'payments.payment_events', 'payments.commissions', 'payments.outbox',
    'platform.memberships', 'platform.sites', 'platform.api_keys', 'platform.subscriptions', 'platform.audit_log'
  ] LOOP
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_guard ON %s AS RESTRICTIVE FOR ALL USING (tenant_id = platform.current_tenant()) WITH CHECK (tenant_id = platform.current_tenant())',
      t
    );
  END LOOP;
END $$;

-- =============================================================== platform policies

CREATE POLICY staff_read   ON platform.memberships   FOR SELECT USING (platform.is_staff());
CREATE POLICY admin_write  ON platform.memberships   FOR ALL    USING (platform.is_admin()) WITH CHECK (platform.is_admin());

CREATE POLICY staff_all    ON platform.sites         FOR ALL    USING (platform.is_staff()) WITH CHECK (platform.is_staff());
CREATE POLICY admin_all    ON platform.api_keys      FOR ALL    USING (platform.is_admin()) WITH CHECK (platform.is_admin());
CREATE POLICY staff_read   ON platform.subscriptions FOR SELECT USING (platform.is_staff());

CREATE POLICY any_insert   ON platform.audit_log     FOR INSERT WITH CHECK (platform.current_role_name() IS NOT NULL);
CREATE POLICY admin_read   ON platform.audit_log     FOR SELECT USING (platform.is_admin());

-- =============================================================== access policies

CREATE POLICY staff_all     ON access.partners FOR ALL    USING (platform.is_staff()) WITH CHECK (platform.is_staff());
CREATE POLICY partner_self  ON access.partners FOR SELECT USING (platform.current_role_name() = 'partner' AND id = platform.current_partner());

CREATE POLICY staff_all       ON access.content_items FOR ALL    USING (platform.is_staff()) WITH CHECK (platform.is_staff());
CREATE POLICY published_read  ON access.content_items FOR SELECT
  USING (status = 'published' AND platform.current_role_name() IN ('public', 'partner', 'business', 'system'));

CREATE POLICY staff_all      ON access.campaigns FOR ALL    USING (platform.is_staff()) WITH CHECK (platform.is_staff());
CREATE POLICY partner_own    ON access.campaigns FOR SELECT USING (platform.current_role_name() = 'partner' AND partner_id = platform.current_partner());

CREATE POLICY staff_all      ON access.keywords  FOR ALL    USING (platform.is_staff()) WITH CHECK (platform.is_staff());
-- (no other role reads keywords; the public path uses access.lookup_keyword())

CREATE POLICY staff_all      ON access.customers FOR ALL USING (platform.is_staff()) WITH CHECK (platform.is_staff());
CREATE POLICY system_rw      ON access.customers FOR ALL USING (platform.current_role_name() = 'system') WITH CHECK (platform.current_role_name() = 'system');
-- partners and business users have NO policy here: they can never read customer emails.

CREATE POLICY staff_read     ON access.visitors  FOR SELECT USING (platform.is_staff());
CREATE POLICY public_rw      ON access.visitors  FOR ALL USING (platform.current_role_name() = 'public') WITH CHECK (platform.current_role_name() = 'public');

CREATE POLICY staff_read     ON access.events    FOR SELECT USING (platform.is_staff());
CREATE POLICY partner_read   ON access.events    FOR SELECT USING (platform.current_role_name() = 'partner' AND partner_id = platform.current_partner());
CREATE POLICY writers_insert ON access.events    FOR INSERT WITH CHECK (platform.current_role_name() IN ('public', 'system'));
-- no UPDATE/DELETE policy and no UPDATE/DELETE grant: events are append-only.

CREATE POLICY staff_all      ON access.entitlements FOR ALL    USING (platform.is_staff()) WITH CHECK (platform.is_staff());
CREATE POLICY system_rw      ON access.entitlements FOR ALL    USING (platform.current_role_name() = 'system') WITH CHECK (platform.current_role_name() = 'system');
CREATE POLICY business_read  ON access.entitlements FOR SELECT USING (platform.current_role_name() = 'business' AND business_id = platform.current_business());

CREATE POLICY system_rw      ON access.processed_events FOR ALL USING (platform.current_role_name() = 'system') WITH CHECK (platform.current_role_name() = 'system');

-- =============================================================== payments policies

CREATE POLICY admin_all      ON payments.gateway_accounts FOR ALL    USING (platform.is_admin()) WITH CHECK (platform.is_admin());
CREATE POLICY system_read    ON payments.gateway_accounts FOR SELECT USING (platform.current_role_name() = 'system');

CREATE POLICY staff_read     ON payments.orders FOR SELECT USING (platform.is_staff());
CREATE POLICY system_rw      ON payments.orders FOR ALL    USING (platform.current_role_name() = 'system') WITH CHECK (platform.current_role_name() = 'system');
-- partners have NO access to orders (they contain customer emails); they see commissions only.

CREATE POLICY staff_read     ON payments.payment_events FOR SELECT USING (platform.is_staff());
CREATE POLICY system_rw      ON payments.payment_events FOR ALL    USING (platform.current_role_name() = 'system') WITH CHECK (platform.current_role_name() = 'system');

CREATE POLICY staff_all      ON payments.commissions FOR ALL    USING (platform.is_staff()) WITH CHECK (platform.is_staff());
CREATE POLICY system_rw      ON payments.commissions FOR ALL    USING (platform.current_role_name() = 'system') WITH CHECK (platform.current_role_name() = 'system');
CREATE POLICY partner_own    ON payments.commissions FOR SELECT USING (platform.current_role_name() = 'partner' AND partner_id = platform.current_partner());

CREATE POLICY system_insert  ON payments.outbox FOR INSERT WITH CHECK (platform.current_role_name() = 'system');

-- =============================================================== grants (least privilege)
-- Two runtime roles. Each product's role sees only its own schema, plus a small slice of
-- "platform". Neither can read users, sessions, login attempts or licences directly.

REVOKE ALL ON SCHEMA platform, access, payments FROM PUBLIC;
GRANT USAGE ON SCHEMA platform TO hp_access, hp_payments;
GRANT USAGE ON SCHEMA access   TO hp_access;
GRANT USAGE ON SCHEMA payments TO hp_payments;

-- platform: global plans plus tenant-scoped tables (rows limited by RLS)
GRANT SELECT ON platform.plans, platform.subscriptions, platform.sites, platform.memberships, platform.tenants TO hp_access, hp_payments;
GRANT SELECT ON platform.api_keys TO hp_access;
GRANT INSERT, UPDATE, DELETE ON platform.sites, platform.memberships, platform.api_keys TO hp_access;
GRANT SELECT, INSERT ON platform.audit_log TO hp_access, hp_payments;   -- no UPDATE/DELETE: append-only
GRANT USAGE ON SEQUENCE platform.audit_log_id_seq TO hp_access, hp_payments;

-- access product
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA access TO hp_access;
REVOKE UPDATE, DELETE ON access.events FROM hp_access;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA access TO hp_access;

-- payments product
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA payments TO hp_payments;
REVOKE UPDATE, DELETE ON payments.payment_events FROM hp_payments;
REVOKE DELETE ON payments.orders, payments.commissions FROM hp_payments;
REVOKE ALL ON payments.outbox FROM hp_payments;
GRANT INSERT ON payments.outbox TO hp_payments;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA payments TO hp_payments;

-- definer functions: nobody by default, then name each caller
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA platform, access, payments FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform.current_tenant(), platform.current_role_name(), platform.current_partner(),
  platform.current_business(), platform.is_staff(), platform.is_admin() TO hp_access, hp_payments;

GRANT EXECUTE ON FUNCTION platform.resolve_session(text) TO hp_access, hp_payments;
GRANT EXECUTE ON FUNCTION
  platform.get_user_for_login(text),
  platform.accept_twofa_step(uuid, bigint),
  platform.login_failures(text, text, interval),
  platform.record_login_attempt(text, text, boolean),
  platform.list_memberships(uuid),
  platform.create_session(uuid, uuid, text, interval, text, text),
  platform.revoke_session(text),
  platform.resolve_api_key(text)
TO hp_access;
GRANT EXECUTE ON FUNCTION platform.resolve_api_key(text) TO hp_payments;

GRANT EXECUTE ON FUNCTION access.lookup_keyword(text) TO hp_access;
GRANT EXECUTE ON FUNCTION payments.claim_outbox(integer), payments.mark_outbox_delivered(bigint), payments.promote_commissions() TO hp_payments;
