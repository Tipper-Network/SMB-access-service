-- 003_payments.sql  (Product 2: gateway accounts, orders, commissions, outbox)
--
-- The Payments product never holds money. Each tenant brings their OWN gateway
-- credentials (their bank, their CyberSource merchant account). This product records
-- orders, verifies gateway notifications, and tells the Access product to grant access.

CREATE TABLE payments.gateway_accounts (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES platform.tenants (id),
  provider         text NOT NULL CHECK (provider IN ('cybersource', 'fake')),
  mode             text NOT NULL DEFAULT 'test' CHECK (mode IN ('test', 'live')),
  merchant_id      text NOT NULL,
  credentials_enc  text NOT NULL,   -- AES-GCM JSON, AAD "gw:<tenant>:<provider>:<mode>"
  status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, provider, mode)
);

CREATE TABLE payments.orders (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL REFERENCES platform.tenants (id),
  external_ref      text NOT NULL,      -- caller's idempotency key (e.g. cart id)
  customer_email    text NOT NULL,
  item_ref          text NOT NULL,      -- content slug in the Access product
  item_title        text NOT NULL,
  list_price_minor  integer NOT NULL CHECK (list_price_minor >= 0),
  discount_minor    integer NOT NULL DEFAULT 0 CHECK (discount_minor >= 0),
  total_minor       integer NOT NULL CHECK (total_minor >= 0),
  currency          text NOT NULL CHECK (length(currency) = 3),
  partner_id        uuid,
  commission_pct    numeric(5, 2) NOT NULL DEFAULT 0 CHECK (commission_pct BETWEEN 0 AND 100),  -- snapshot at order time
  code_ref          text,
  status            text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'paid', 'declined', 'abandoned', 'refunded', 'disputed')),
  gateway_txn_id    text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  paid_at           timestamptz,
  CHECK (total_minor = list_price_minor - discount_minor),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, external_ref)
);

-- Every gateway notification, stored once. The unique key makes processing idempotent.
CREATE TABLE payments.payment_events (
  id                  bigserial PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES platform.tenants (id),
  provider            text NOT NULL,
  provider_event_id   text NOT NULL,
  order_id            uuid,
  decision            text,
  payload             jsonb NOT NULL,
  received_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, provider, provider_event_id)
);

CREATE TABLE payments.commissions (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES platform.tenants (id),
  partner_id     uuid NOT NULL,
  order_id       uuid NOT NULL,
  amount_minor   integer NOT NULL CHECK (amount_minor >= 0),
  currency       text NOT NULL,
  status         text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'payable', 'paid', 'void')),
  payable_after  timestamptz NOT NULL,
  paid_at        timestamptz,
  payout_ref     text,
  UNIQUE (tenant_id, order_id),
  FOREIGN KEY (tenant_id, order_id) REFERENCES payments.orders (tenant_id, id)
);
CREATE INDEX commissions_partner_idx ON payments.commissions (tenant_id, partner_id, status);

-- Transactional outbox: events are written in the same transaction as the state change,
-- then delivered (signed) to the Access product with retries. At-least-once delivery;
-- the receiver de-duplicates by event id.
CREATE TABLE payments.outbox (
  id               bigserial PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES platform.tenants (id),
  type             text NOT NULL,
  payload          jsonb NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  delivered_at     timestamptz,
  attempts         integer NOT NULL DEFAULT 0,
  next_attempt_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX outbox_due_idx ON payments.outbox (next_attempt_at) WHERE delivered_at IS NULL;

-- Cross-tenant background jobs run through narrow definer functions, not broad table access.

CREATE FUNCTION payments.claim_outbox(p_limit integer)
RETURNS TABLE (id bigint, tenant_id uuid, type text, payload jsonb, attempts integer)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE payments.outbox o
  SET attempts = o.attempts + 1,
      next_attempt_at = now() + (interval '30 seconds' * power(2, least(o.attempts, 8)))
  WHERE o.id IN (
    SELECT i.id FROM payments.outbox i
    WHERE i.delivered_at IS NULL AND i.next_attempt_at <= now()
    ORDER BY i.id LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  )
  RETURNING o.id, o.tenant_id, o.type, o.payload, o.attempts
$$;

CREATE FUNCTION payments.mark_outbox_delivered(p_id bigint) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE payments.outbox SET delivered_at = now() WHERE id = p_id AND delivered_at IS NULL
$$;

CREATE FUNCTION payments.promote_commissions() RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH u AS (
    UPDATE payments.commissions SET status = 'payable'
    WHERE status = 'pending' AND payable_after <= now()
    RETURNING 1
  )
  SELECT count(*)::integer FROM u
$$;
