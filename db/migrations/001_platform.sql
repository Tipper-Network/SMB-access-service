-- 001_platform.sql
-- Identity, tenancy, sessions, API keys, plans, licences, audit.
-- Run as the MIGRATION OWNER role. Runtime services never connect as the owner.
--
-- Isolation model, in one paragraph:
--   * Every tenant table carries tenant_id and has a RESTRICTIVE row-level-security
--     policy ("tenant_guard") comparing it to the transaction-local setting
--     app.tenant_id. Restrictive policies are ANDed with everything else, so no later
--     permissive policy can accidentally open a table across tenants.
--   * Tables that must be read BEFORE a tenant is known (users, sessions, login
--     attempts, licences) have NO grants for runtime roles at all. They are reachable
--     only through SECURITY DEFINER functions that do one narrow job each.

CREATE SCHEMA IF NOT EXISTS platform;
CREATE SCHEMA IF NOT EXISTS access;
CREATE SCHEMA IF NOT EXISTS payments;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hp_access')   THEN CREATE ROLE hp_access   NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hp_payments') THEN CREATE ROLE hp_payments NOLOGIN; END IF;
END $$;

-- ---------------------------------------------------------------- context helpers
-- Read the settings that Db.withTenant() sets. NULL when unset, which makes every
-- policy comparison false (fail closed).

CREATE OR REPLACE FUNCTION platform.current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;

CREATE OR REPLACE FUNCTION platform.current_role_name() RETURNS text
LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.role', true), '') $$;

CREATE OR REPLACE FUNCTION platform.current_partner() RETURNS uuid
LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.partner_id', true), '')::uuid $$;

CREATE OR REPLACE FUNCTION platform.current_business() RETURNS uuid
LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.business_id', true), '')::uuid $$;

CREATE OR REPLACE FUNCTION platform.is_staff() RETURNS boolean
LANGUAGE sql STABLE AS $$ SELECT COALESCE(platform.current_role_name() IN ('owner', 'admin', 'staff'), false) $$;

CREATE OR REPLACE FUNCTION platform.is_admin() RETURNS boolean
LANGUAGE sql STABLE AS $$ SELECT COALESCE(platform.current_role_name() IN ('owner', 'admin'), false) $$;

-- ---------------------------------------------------------------- tenants & users

CREATE TABLE platform.tenants (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,38}$'),
  name        text NOT NULL,
  status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE platform.users (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email              text NOT NULL CHECK (email = lower(btrim(email))),
  password_hash      text,
  twofa_enabled      boolean NOT NULL DEFAULT false,
  twofa_secret_enc   text,                 -- AES-GCM, AAD "user:<id>:twofa"
  twofa_last_step    bigint,               -- replay protection
  is_platform_admin  boolean NOT NULL DEFAULT false,
  status             text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_key ON platform.users (email);

CREATE TABLE platform.memberships (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES platform.tenants (id),
  user_id      uuid NOT NULL REFERENCES platform.users (id),
  role         text NOT NULL CHECK (role IN ('owner', 'admin', 'staff', 'partner', 'business')),
  partner_id   uuid,   -- access.partners.id; no FK so the two products stay separable
  business_id  uuid,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, user_id),
  CHECK ((role = 'partner')  = (partner_id  IS NOT NULL)),
  CHECK ((role = 'business') = (business_id IS NOT NULL))
);

CREATE TABLE platform.sessions (
  token_hash   text PRIMARY KEY,           -- SHA-256 of the cookie value; the raw token is never stored
  user_id      uuid NOT NULL REFERENCES platform.users (id) ON DELETE CASCADE,
  tenant_id    uuid REFERENCES platform.tenants (id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  ip_hash      text,
  user_agent   text
);
CREATE INDEX sessions_user_idx ON platform.sessions (user_id);

CREATE TABLE platform.login_attempts (
  id            bigserial PRIMARY KEY,
  email_hash    text NOT NULL,
  ip_hash       text NOT NULL,
  success       boolean NOT NULL,
  attempted_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_email_idx ON platform.login_attempts (email_hash, attempted_at);
CREATE INDEX login_attempts_ip_idx    ON platform.login_attempts (ip_hash, attempted_at);

-- ---------------------------------------------------------------- sites & keys

CREATE TABLE platform.sites (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES platform.tenants (id),
  domain      text NOT NULL CHECK (domain = lower(domain)),
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, domain)
);

CREATE TABLE platform.api_keys (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES platform.tenants (id),
  site_id          uuid NOT NULL,
  kind             text NOT NULL CHECK (kind IN ('public', 'secret')),
  key_prefix       text NOT NULL,          -- shown in the admin UI so keys can be recognised
  key_hash         text NOT NULL UNIQUE,   -- SHA-256 of the full key
  allowed_origins  text[] NOT NULL DEFAULT '{}',
  created_at       timestamptz NOT NULL DEFAULT now(),
  revoked_at       timestamptz,
  FOREIGN KEY (tenant_id, site_id) REFERENCES platform.sites (tenant_id, id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------- plans, subscriptions, licences

CREATE TABLE platform.plans (
  code                 text PRIMARY KEY,
  name                 text NOT NULL,
  monthly_price_minor  integer NOT NULL CHECK (monthly_price_minor >= 0),
  currency             text NOT NULL DEFAULT 'USD',
  limits               jsonb NOT NULL
);

INSERT INTO platform.plans (code, name, monthly_price_minor, limits) VALUES
  ('starter', 'Starter', 0,     '{"sites": 1,  "content_items": 50,   "monthly_visitors": 5000,   "partners": 5}'),
  ('growth',  'Growth',  4900,  '{"sites": 3,  "content_items": 500,  "monthly_visitors": 50000,  "partners": 50}'),
  ('scale',   'Scale',   14900, '{"sites": 10, "content_items": 5000, "monthly_visitors": 500000, "partners": 500}')
ON CONFLICT (code) DO NOTHING;
-- Prices above are placeholders for the scaffold; set your own.

CREATE TABLE platform.subscriptions (
  tenant_id           uuid PRIMARY KEY REFERENCES platform.tenants (id),
  plan_code           text NOT NULL REFERENCES platform.plans (code),
  status              text NOT NULL DEFAULT 'trialing' CHECK (status IN ('trialing', 'active', 'past_due', 'canceled')),
  current_period_end  timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now()
);

-- Self-install licences you have issued. Platform-admin tooling only: no runtime grants.
CREATE TABLE platform.licenses (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id      text NOT NULL UNIQUE,
  customer_name   text NOT NULL,
  customer_email  text,
  product         text NOT NULL CHECK (product IN ('access', 'payments', 'bundle')),
  plan_code       text NOT NULL,
  features        jsonb NOT NULL DEFAULT '[]',
  max_sites       integer NOT NULL CHECK (max_sites > 0),
  issued_at       timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  revoked_at      timestamptz,
  notes           text
);

-- ---------------------------------------------------------------- audit log (append-only)

CREATE TABLE platform.audit_log (
  id             bigserial PRIMARY KEY,
  tenant_id      uuid NOT NULL REFERENCES platform.tenants (id),
  actor_user_id  uuid,
  actor_role     text,
  action         text NOT NULL,
  target         text,
  details        jsonb,
  at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_tenant_idx ON platform.audit_log (tenant_id, at DESC);

CREATE FUNCTION platform.deny_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'table %.% is append-only', TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER audit_no_update_delete BEFORE UPDATE OR DELETE ON platform.audit_log
  FOR EACH ROW EXECUTE FUNCTION platform.deny_mutation();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON platform.audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION platform.deny_mutation();

-- ---------------------------------------------------------------- pre-auth functions (SECURITY DEFINER)
-- Each does one narrow job, pins search_path, and is granted to named roles only (see 004).

CREATE FUNCTION platform.get_user_for_login(p_email text)
RETURNS TABLE (id uuid, password_hash text, twofa_enabled boolean, twofa_secret_enc text, twofa_last_step bigint, status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT u.id, u.password_hash, u.twofa_enabled, u.twofa_secret_enc, u.twofa_last_step, u.status
  FROM platform.users u
  WHERE u.email = lower(btrim(p_email))
$$;

-- Atomic replay protection: succeeds only if p_step is newer than the last accepted step.
CREATE FUNCTION platform.accept_twofa_step(p_user uuid, p_step bigint) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH u AS (
    UPDATE platform.users SET twofa_last_step = p_step
    WHERE id = p_user AND (twofa_last_step IS NULL OR twofa_last_step < p_step)
    RETURNING 1
  )
  SELECT EXISTS (SELECT 1 FROM u)
$$;

CREATE FUNCTION platform.login_failures(p_email_hash text, p_ip_hash text, p_window interval)
RETURNS TABLE (by_email integer, by_ip integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT (count(*) FILTER (WHERE email_hash = p_email_hash))::integer,
         (count(*) FILTER (WHERE ip_hash = p_ip_hash))::integer
  FROM platform.login_attempts
  WHERE success = false AND attempted_at > now() - p_window
$$;

CREATE FUNCTION platform.record_login_attempt(p_email_hash text, p_ip_hash text, p_success boolean) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO platform.login_attempts (email_hash, ip_hash, success) VALUES (p_email_hash, p_ip_hash, p_success)
$$;

CREATE FUNCTION platform.list_memberships(p_user uuid)
RETURNS TABLE (tenant_id uuid, tenant_slug text, role text, partner_id uuid, business_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT m.tenant_id, t.slug, m.role, m.partner_id, m.business_id
  FROM platform.memberships m
  JOIN platform.tenants t ON t.id = m.tenant_id
  WHERE m.user_id = p_user AND t.status = 'active'
  ORDER BY t.slug
$$;

CREATE FUNCTION platform.create_session(p_user uuid, p_tenant uuid, p_token_hash text, p_ttl interval, p_ip_hash text, p_ua text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF p_tenant IS NULL THEN
    IF NOT EXISTS (SELECT 1 FROM platform.users WHERE id = p_user AND is_platform_admin AND status = 'active') THEN
      RETURN false;
    END IF;
  ELSE
    IF NOT EXISTS (
      SELECT 1 FROM platform.memberships m JOIN platform.tenants t ON t.id = m.tenant_id
      WHERE m.user_id = p_user AND m.tenant_id = p_tenant AND t.status = 'active'
    ) THEN
      RETURN false;
    END IF;
  END IF;
  INSERT INTO platform.sessions (token_hash, user_id, tenant_id, expires_at, ip_hash, user_agent)
  VALUES (p_token_hash, p_user, p_tenant, now() + p_ttl, p_ip_hash, left(p_ua, 300));
  RETURN true;
END $$;

CREATE FUNCTION platform.resolve_session(p_token_hash text)
RETURNS TABLE (user_id uuid, tenant_id uuid, role text, partner_id uuid, business_id uuid, is_platform_admin boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT s.user_id, s.tenant_id, COALESCE(m.role, 'platform_admin'), m.partner_id, m.business_id, u.is_platform_admin
  FROM platform.sessions s
  JOIN platform.users u ON u.id = s.user_id
  LEFT JOIN platform.memberships m ON m.user_id = s.user_id AND m.tenant_id = s.tenant_id
  LEFT JOIN platform.tenants t ON t.id = s.tenant_id
  WHERE s.token_hash = p_token_hash
    AND s.revoked_at IS NULL
    AND s.expires_at > now()
    AND u.status = 'active'
    AND ((s.tenant_id IS NULL AND u.is_platform_admin) OR (m.id IS NOT NULL AND t.status = 'active'))
$$;

CREATE FUNCTION platform.revoke_session(p_token_hash text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE platform.sessions SET revoked_at = now() WHERE token_hash = p_token_hash AND revoked_at IS NULL
$$;

CREATE FUNCTION platform.resolve_api_key(p_key_hash text)
RETURNS TABLE (tenant_id uuid, site_id uuid, kind text, allowed_origins text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT k.tenant_id, k.site_id, k.kind, k.allowed_origins
  FROM platform.api_keys k
  JOIN platform.tenants t ON t.id = k.tenant_id
  WHERE k.key_hash = p_key_hash AND k.revoked_at IS NULL AND t.status = 'active'
$$;
