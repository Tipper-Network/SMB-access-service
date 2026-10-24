import { randomUUID } from 'node:crypto';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

export type S3UploadConfig = {
  bucket: string;
  region: string;
  publicBaseUrl: string;
  prefix: string;
  tenantSlug: string;
  presignExpiresSec: number;
};

function joinKey(...parts: string[]): string {
  return parts
    .map((p) => p.replace(/^\/+|\/+$/g, ''))
    .filter(Boolean)
    .join('/');
}

function parseS3Uri(uri: string | undefined): { bucket?: string; keyRoot?: string } {
  if (!uri?.trim()) return {};
  const m = uri.trim().match(/^s3:\/\/([^/]+)\/?(.*)$/i);
  if (!m) return {};
  return { bucket: m[1], keyRoot: m[2]?.replace(/\/$/, '') || undefined };
}

function publicOrigin(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url.replace(/\/$/, '');
  }
}

/**
 * Reads S3 presign settings from the Access process environment (not the Next.js BFF).
 */
export function loadS3UploadConfig(tenantSlug: string): S3UploadConfig | null {
  const fromUri = parseS3Uri(process.env.HP_S3_URI ?? process.env.S3_URI);
  const bucket = (process.env.HP_S3_BUCKET ?? process.env.S3_BUCKET ?? fromUri.bucket ?? '').trim();
  const region = (process.env.HP_S3_REGION ?? process.env.AWS_REGION ?? '').trim();
  const contentPrefix = (process.env.HP_S3_PREFIX ?? process.env.S3_PREFIX ?? 'content').replace(/^\/+|\/+$/g, '');

  let keyRoot = fromUri.keyRoot ?? '';
  const publicUrlRaw = (process.env.HP_S3_PUBLIC_BASE_URL ?? process.env.S3_PUBLIC_BASE_URL ?? '').trim();
  if (!keyRoot && publicUrlRaw) {
    try {
      keyRoot = new URL(publicUrlRaw).pathname.replace(/^\/+|\/+$/g, '');
    } catch {
      /* ignore */
    }
  }

  const prefix = joinKey(keyRoot, contentPrefix);

  let publicBaseUrl = publicUrlRaw ? publicOrigin(publicUrlRaw) : '';
  if (!publicBaseUrl && bucket && region) {
    publicBaseUrl = `https://${bucket}.s3.${region}.amazonaws.com`;
  }

  const rawExpires = Number(process.env.S3_PRESIGN_EXPIRES ?? process.env.HP_S3_PRESIGN_EXPIRES ?? 900);
  const presignExpiresSec =
    Number.isFinite(rawExpires) && rawExpires >= 60 && rawExpires <= 86_400 ? rawExpires : 900;
  if (!bucket || !region || !publicBaseUrl) return null;
  return { bucket, region, publicBaseUrl, prefix, tenantSlug, presignExpiresSec };
}

function safeFilename(name: string): string {
  const base = name.replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  return base.slice(0, 120) || 'file';
}

export async function createPresignedUpload(
  config: S3UploadConfig,
  input: { slug: string; filename: string; contentType: string },
): Promise<{ uploadUrl: string; publicUrl: string; key: string }> {
  const key = joinKey(config.prefix, config.tenantSlug, input.slug, `${randomUUID()}-${safeFilename(input.filename)}`);
  const client = new S3Client({ region: config.region });
  const command = new PutObjectCommand({
    Bucket: config.bucket,
    Key: key,
    ContentType: input.contentType || 'application/octet-stream',
  });
  const uploadUrl = await getSignedUrl(client, command, { expiresIn: config.presignExpiresSec });
  const publicUrl = `${config.publicBaseUrl}/${key}`;
  return { uploadUrl, publicUrl, key };
}
