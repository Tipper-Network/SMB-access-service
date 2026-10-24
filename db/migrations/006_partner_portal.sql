-- Partner portal: email + portal code + email OTP (Access service)

ALTER TABLE access.partners
  ADD COLUMN IF NOT EXISTS email text CHECK (email IS NULL OR email = lower(btrim(email))),
  ADD COLUMN IF NOT EXISTS portal_code_hash text;

CREATE UNIQUE INDEX IF NOT EXISTS partners_tenant_email_key
  ON access.partners (tenant_id, email)
  WHERE email IS NOT NULL;

CREATE TABLE IF NOT EXISTS access.partner_otp (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL,
  partner_id   uuid NOT NULL,
  otp_hash     text NOT NULL,
  expires_at   timestamptz NOT NULL,
  consumed_at  timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, partner_id) REFERENCES access.partners (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS partner_otp_active_idx
  ON access.partner_otp (tenant_id, partner_id, expires_at DESC)
  WHERE consumed_at IS NULL;

-- Pre-auth lookup (RLS would block a bare SELECT on access.partners).
CREATE OR REPLACE FUNCTION access.find_partner_for_portal(p_tenant_slug text, p_email text)
RETURNS TABLE (tenant_id uuid, partner_id uuid, portal_code_hash text, display_name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp, access, platform AS $$
  SELECT p.tenant_id, p.id, p.portal_code_hash, p.display_name
  FROM access.partners p
  JOIN platform.tenants t ON t.id = p.tenant_id
  WHERE t.slug = lower(btrim(p_tenant_slug))
    AND t.status = 'active'
    AND p.status = 'active'
    AND p.email IS NOT NULL
    AND p.portal_code_hash IS NOT NULL
    AND lower(p.email) = lower(btrim(p_email))
$$;

CREATE OR REPLACE FUNCTION platform.ensure_partner_membership(p_tenant uuid, p_partner uuid, p_email text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp, platform, access AS $$
DECLARE v_user uuid;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM access.partners
    WHERE tenant_id = p_tenant AND id = p_partner AND status = 'active' AND email = lower(btrim(p_email))
  ) THEN
    RETURN NULL;
  END IF;

  INSERT INTO platform.users (email) VALUES (lower(btrim(p_email)))
  ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
  RETURNING id INTO v_user;

  INSERT INTO platform.memberships (tenant_id, user_id, role, partner_id)
  VALUES (p_tenant, v_user, 'partner', p_partner)
  ON CONFLICT (tenant_id, user_id) DO UPDATE
    SET role = 'partner', partner_id = EXCLUDED.partner_id;

  RETURN v_user;
END;
$$;

REVOKE ALL ON FUNCTION access.find_partner_for_portal(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.find_partner_for_portal(text, text) TO hp_access;

REVOKE ALL ON FUNCTION platform.ensure_partner_membership(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform.ensure_partner_membership(uuid, uuid, text) TO hp_access;

GRANT SELECT, INSERT, UPDATE ON access.partner_otp TO hp_access;

ALTER TABLE access.partner_otp ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_guard ON access.partner_otp AS RESTRICTIVE FOR ALL
  USING (tenant_id = platform.current_tenant()) WITH CHECK (tenant_id = platform.current_tenant());
CREATE POLICY system_rw ON access.partner_otp FOR ALL
  USING (platform.current_role_name() = 'system') WITH CHECK (platform.current_role_name() = 'system');
