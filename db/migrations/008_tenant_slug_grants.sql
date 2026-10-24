-- GET /auth/session reads platform.tenants.slug for the BFF; hp_access had no SELECT grant.

GRANT SELECT ON platform.tenants TO hp_access, hp_payments;
