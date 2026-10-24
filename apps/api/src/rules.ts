// Pure business rules. No database, no HTTP: easy to test and to reuse in the self-install edition.

export interface GatedItem {
  access_mode: 'open' | 'keyword_first' | 'paid';
  free_from: Date | string | null;
}

export interface AccessContext {
  hasEntitlement: boolean;
  hasKeywordSession: boolean;
}

/**
 * Decides whether this visitor may read the item.
 * `open` is always allowed. `keyword_first` needs a keyword session or an entitlement until `free_from`, then it opens on its own.
 * `paid` needs an entitlement and never opens by date.
 *
 * Called by the public content routes. The date check is computed here. No job flips rows.
 * @param item - Access mode and optional free-from timestamp
 * @param ctx - Whether this visitor already has an entitlement or a keyword session
 * @param now - Clock, injectable in tests
 */
export function canAccess(item: GatedItem, ctx: AccessContext, now: Date = new Date()): boolean {
  if (item.access_mode === 'open') return true;
  if (item.access_mode === 'keyword_first') {
    if (item.free_from && now >= new Date(item.free_from)) return true;
    return ctx.hasKeywordSession || ctx.hasEntitlement;
  }
  return ctx.hasEntitlement;
}

/**
 * Turns a typed keyword into the form stored on the campaign. Capitals, a leading `#`, and spaces are ignored.
 * Returns null when the result is not 2–40 characters of letters, digits, `_`, or `-`.
 * Called by keyword redemption and by the admin campaign routes.
 * @param raw - What the visitor typed
 */
export function normalizeKeyword(raw: string): string | null {
  const w = raw.normalize('NFKC').toLowerCase().replace(/^#/, '').replace(/\s+/g, '');
  return /^[a-z0-9_-]{2,40}$/.test(w) ? w : null;
}
