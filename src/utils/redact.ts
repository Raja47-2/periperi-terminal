/**
 * Context redaction.
 *
 * Scan output is shown in the UI, printed to a terminal and written to CBOM
 * files. None of those destinations may ever receive key material, so every
 * context line passes through `redactContext` first.
 */

const PEM_BLOCK = /-----BEGIN[^-]{0,80}-----[\s\S]*?-----END[^-]{0,80}-----/g;
const LONG_BASE64 = /\b[A-Za-z0-9+/]{60,}={0,2}\b/g;
const SECRET_ASSIGNMENT =
  /((?:pass(?:word|wd)?|secret|api[_-]?key|token|private[_-]?key|access[_-]?key|client[_-]?secret)\s*[:=]\s*)(["']?)([^\s"',;]{3,})/gi;
const BEARER = /\b(Bearer\s+)[A-Za-z0-9._-]{8,}/gi;
const URL_CREDENTIALS = /\b([a-z][a-z0-9+.-]*:\/\/)([^:/\s]+):([^@/\s]+)@/gi;

export const REDACTED = '[REDACTED]';

/** Hard cap so a single minified line cannot flood the UI or the CBOM. */
const MAX_CONTEXT_LENGTH = 240;

export function redactContext(line: string): string {
  let out = line.replace(PEM_BLOCK, `[REDACTED PEM ${REDACTED}]`);
  out = out.replace(URL_CREDENTIALS, (_m, scheme) => `${scheme}${REDACTED}:${REDACTED}@`);
  out = out.replace(BEARER, (_m, prefix) => `${prefix}${REDACTED}`);
  out = out.replace(SECRET_ASSIGNMENT, (_m, prefix, quote) => `${prefix}${quote}${REDACTED}${quote}`);
  out = out.replace(LONG_BASE64, REDACTED);
  out = out.replace(/\s+/g, ' ').trim();
  if (out.length > MAX_CONTEXT_LENGTH) {
    out = `${out.slice(0, MAX_CONTEXT_LENGTH)}…`;
  }
  return out;
}

/** Count 1-based column of a 0-based regex index. */
export function columnFromIndex(_line: string, index: number): number {
  return index + 1;
}
