-- 002_access.sql  (Product 1: content, keywords, campaigns, partners, tracking, access)
--
-- Cross-tenant references are impossible by construction: every child table points
-- at its parent with a COMPOSITE foreign key (tenant_id, id). A keyword in tenant A
-- cannot reference a content item in tenant B even if application code tries.

CREATE TABLE access.partners (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL REFERENCES platform.tenants (id),
  display_name        text NOT NULL,
  kind                text NOT NULL DEFAULT 'influencer' CHECK (kind IN ('influencer', 'business', 'other')),
  commission_pct      numeric(5, 2) NOT NULL DEFAULT 0 CHECK (commission_pct BETWEEN 0 AND 100),
  payout_details_enc  text,    -- AES-GCM, AAD "partner:<id>:payout"
  status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused')),
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id)
);

CREATE TABLE access.content_items (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES platform.tenants (id),
  slug          text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,80}$'),
  title         text NOT NULL,
  summary       text,
  kind          text NOT NULL CHECK (kind IN ('guide', 'part', 'video', 'session', 'ebook', 'download')),
  parent_id     uuid,
  sort_order    integer NOT NULL DEFAULT 0,
  access_mode   text NOT NULL DEFAULT 'keyword_first' CHECK (access_mode IN ('open', 'keyword_first', 'paid')),
  free_from     timestamptz,
  body_ref      text,
  booking_url   text,
  price_minor   integer CHECK (price_minor IS NULL OR price_minor >= 0),
  currency      text,
  status        text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
  published_at  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, slug),
  FOREIGN KEY (tenant_id, parent_id) REFERENCES access.content_items (tenant_id, id)
);

CREATE TABLE access.campaigns (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES platform.tenants (id),
  platform      text CHECK (platform IN ('youtube', 'short', 'tiktok', 'instagram', 'x', 'other')),
  title         text NOT NULL,
  post_url      text,
  trigger_word  text,
  partner_id    uuid,
  published_on  date,
  notes         text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, partner_id) REFERENCES access.partners (tenant_id, id)
);

CREATE TABLE access.keywords (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL REFERENCES platform.tenants (id),
  word              text NOT NULL CHECK (word ~ '^[a-z0-9_-]{2,40}$'),
  content_id        uuid NOT NULL,
  campaign_id       uuid,
  discount_code_ref text,    -- opaque reference; discount codes belong to the Payments product
  is_active         boolean NOT NULL DEFAULT true,
  starts_at         timestamptz,
  expires_at        timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, word),   -- unique PER TENANT: two businesses can both use "guide"
  FOREIGN KEY (tenant_id, content_id)  REFERENCES access.content_items (tenant_id, id),
  FOREIGN KEY (tenant_id, campaign_id) REFERENCES access.campaigns (tenant_id, id)
);

CREATE TABLE access.customers (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES platform.tenants (id),
  email       text NOT NULL,
  name        text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX customers_email_key ON access.customers (tenant_id, lower(email));

CREATE TABLE access.visitors (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL REFERENCES platform.tenants (id),
  anon_id            text NOT NULL CHECK (length(anon_id) BETWEEN 16 AND 64),
  first_campaign_id  uuid,
  last_campaign_id   uuid,
  customer_id        uuid,
  first_seen_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, anon_id),
  FOREIGN KEY (tenant_id, first_campaign_id) REFERENCES access.campaigns (tenant_id, id),
  FOREIGN KEY (tenant_id, last_campaign_id)  REFERENCES access.campaigns (tenant_id, id),
  FOREIGN KEY (tenant_id, customer_id)       REFERENCES access.customers (tenant_id, id)
);

-- Append-only. partner_id is denormalised from the campaign so row-level security can
-- scope a partner to their own events without a join.
CREATE TABLE access.events (
  id            bigserial PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES platform.tenants (id),
  visitor_id    uuid,
  type          text NOT NULL CHECK (type IN ('keyword_lookup', 'page_view', 'content_open', 'email_captured', 'download', 'checkout_start')),
  keyword_text  text CHECK (length(keyword_text) <= 60),
  matched       boolean,
  content_id    uuid,
  campaign_id   uuid,
  partner_id    uuid,
  created_at    timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, visitor_id)  REFERENCES access.visitors (tenant_id, id),
  FOREIGN KEY (tenant_id, content_id)  REFERENCES access.content_items (tenant_id, id),
  FOREIGN KEY (tenant_id, campaign_id) REFERENCES access.campaigns (tenant_id, id),
  FOREIGN KEY (tenant_id, partner_id)  REFERENCES access.partners (tenant_id, id)
);
CREATE INDEX events_campaign_idx ON access.events (tenant_id, campaign_id, created_at);
CREATE INDEX events_partner_idx  ON access.events (tenant_id, partner_id, created_at);
CREATE INDEX events_type_idx     ON access.events (tenant_id, type, created_at);

CREATE TABLE access.entitlements (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES platform.tenants (id),
  customer_id  uuid,
  business_id  uuid,
  content_id   uuid NOT NULL,
  source       text NOT NULL CHECK (source IN ('purchase', 'free_keyword', 'business_assign', 'admin_grant')),
  order_ref    text,
  revoked_at   timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  CHECK (customer_id IS NOT NULL OR business_id IS NOT NULL),
  FOREIGN KEY (tenant_id, customer_id) REFERENCES access.customers (tenant_id, id),
  FOREIGN KEY (tenant_id, content_id)  REFERENCES access.content_items (tenant_id, id)
);
CREATE UNIQUE INDEX entitlements_customer_active_key ON access.entitlements (tenant_id, customer_id, content_id)
  WHERE revoked_at IS NULL AND customer_id IS NOT NULL;
CREATE UNIQUE INDEX entitlements_business_active_key ON access.entitlements (tenant_id, business_id, content_id)
  WHERE revoked_at IS NULL AND business_id IS NOT NULL;

-- Inbox for events from the Payments product: makes delivery idempotent.
CREATE TABLE access.processed_events (
  tenant_id     uuid NOT NULL REFERENCES platform.tenants (id),
  event_id      text NOT NULL,
  processed_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, event_id)
);

-- Public keyword lookup. The public role has NO access to the keywords table; it can
-- only call this function, which returns the minimum and reads the tenant from the
-- transaction setting (never from an argument), so it cannot be pointed at another tenant.
CREATE FUNCTION access.lookup_keyword(p_word text)
RETURNS TABLE (content_id uuid, content_slug text, campaign_id uuid, partner_id uuid, discount_code_ref text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT k.content_id, c.slug, k.campaign_id, camp.partner_id, k.discount_code_ref
  FROM access.keywords k
  JOIN access.content_items c ON c.tenant_id = k.tenant_id AND c.id = k.content_id AND c.status = 'published'
  LEFT JOIN access.campaigns camp ON camp.tenant_id = k.tenant_id AND camp.id = k.campaign_id
  WHERE k.tenant_id = platform.current_tenant()
    AND k.word = p_word
    AND k.is_active
    AND (k.starts_at  IS NULL OR k.starts_at  <= now())
    AND (k.expires_at IS NULL OR k.expires_at >  now())
$$;
