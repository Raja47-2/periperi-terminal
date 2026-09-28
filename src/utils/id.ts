import { randomBytes } from 'node:crypto';

/** Sequential, human friendly scan id: `SCAN-<yyyymmdd>-<counter>`. */
export function createScanId(counter = 1, now: Date = new Date()): string {
  const stamp = now.toISOString().slice(0, 10).replace(/-/g, '');
  return `SCAN-${stamp}-${String(counter).padStart(3, '0')}`;
}

export function createRequestId(): string {
  return `req-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`;
}

/** Deterministic id assignment so CBOMs are reproducible for a given scan. */
export function assetId(index: number): string {
  return `PARI-${String(index + 1).padStart(4, '0')}`;
}
