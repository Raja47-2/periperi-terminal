import * as path from 'node:path';
import * as fs from 'node:fs';

/** Convert any path to a POSIX-style relative path for stable, portable output. */
export function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}

/** Workspace-relative label used in the UI, CBOM and CSV export. */
export function relativeLabel(root: string, file: string): string {
  const rel = path.relative(root, file);
  if (!rel || rel.startsWith('..')) {
    return toPosix(file);
  }
  return toPosix(rel);
}

export function isPathInside(parent: string, child: string): boolean {
  const rel = path.relative(path.resolve(parent), path.resolve(child));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * Resolve `candidate` and refuse anything that escapes `root`.
 * This is the single guard used by every write path (CBOM, reports, exports).
 */
export function safeResolveInside(root: string, ...segments: string[]): string {
  const resolvedRoot = path.resolve(root);
  for (const segment of segments) {
    if (segment.includes('\0')) {
      throw new Error('Path contains a null byte.');
    }
  }
  const target = path.resolve(resolvedRoot, ...segments);
  if (!isPathInside(resolvedRoot, target)) {
    throw new Error('Refused to write outside the permitted directory (path traversal blocked).');
  }
  return target;
}

export function ensureDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
}

export function fileExists(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

export function dirExists(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

export function shortPath(p: string, segments = 3): string {
  const parts = toPosix(p).split('/');
  if (parts.length <= segments) {
    return toPosix(p);
  }
  return `…/${parts.slice(-segments).join('/')}`;
}
