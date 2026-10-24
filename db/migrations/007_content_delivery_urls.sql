-- Extra delivery / attribution URLs on product pages (per content_items row).

ALTER TABLE access.content_items
  ADD COLUMN IF NOT EXISTS youtube_url text,
  ADD COLUMN IF NOT EXISTS substack_url text,
  ADD COLUMN IF NOT EXISTS source_label text,
  ADD COLUMN IF NOT EXISTS source_url text;

COMMENT ON COLUMN access.content_items.youtube_url IS 'Primary YouTube watch or embed URL for kind=video (public product page).';
COMMENT ON COLUMN access.content_items.substack_url IS 'Substack (or similar) article URL when the page points off-site.';
COMMENT ON COLUMN access.content_items.source_label IS 'Human label for attribution, e.g. Originally on Substack.';
COMMENT ON COLUMN access.content_items.source_url IS 'Link for source_label (channel, newsletter, partner post).';
