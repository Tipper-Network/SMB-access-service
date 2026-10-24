-- Microform v2 does not redirect away from the site. The capture context is stored
-- with the order so the transient token can be verified against that session's key.
-- `processing` means a charge has been sent to the gateway and must not be sent again.

DO $$
DECLARE cname text;
BEGIN
  SELECT con.conname INTO cname
  FROM pg_constraint con
  JOIN pg_class rel ON rel.oid = con.conrelid
  JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
  WHERE nsp.nspname = 'payments'
    AND rel.relname = 'orders'
    AND con.contype = 'c'
    AND pg_get_constraintdef(con.oid) ILIKE '%status%';
  IF cname IS NOT NULL THEN
    EXECUTE format('ALTER TABLE payments.orders DROP CONSTRAINT %I', cname);
  END IF;
END $$;

ALTER TABLE payments.orders
  ADD CONSTRAINT orders_status_check
  CHECK (status IN ('pending', 'processing', 'paid', 'declined', 'abandoned', 'refunded', 'disputed'));

ALTER TABLE payments.orders ADD COLUMN checkout_context text;
