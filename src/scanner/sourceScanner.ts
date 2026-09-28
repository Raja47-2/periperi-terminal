/**
 * File discovery + line-oriented pattern matching.
 *
 * Security contract
 * -----------------
 * - Files are opened read-only, as UTF-8 text.
 * - Nothing in this module imports, evaluates or executes project code.
 * - A hard byte cap (`maxFileSize`) prevents accidental reads of huge blobs.
 * - Every context line is redacted before it leaves this module.
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';

import {
  ALL_RULES,
  CRYPTO_CONTEXT_TOKENS,
  CryptoPatternRule,
  PRIVATE_KEY_FILE_PATTERNS,
  isSupportedFile,
} from './cryptoPatterns';
import type {
  CancellationLike,
  Confidence,
  Detection,
  ScanError,
  SourceType,
} from './types';
import { relativeLabel, toPosix } from '../utils/paths';
import { columnFromIndex, redactContext } from '../utils/redact';
import { describeError } from '../utils/errors';
import { logger } from '../utils/log';

export interface DiscoverResult {
  files: string[];
  skipped: string[];
  errors: ScanError[];
  bytesDiscovered: number;
}

export interface DiscoverOptions {
  root: string;
  exclude: string[];
  maxFileSize: number;
  maxFiles: number;
  token?: CancellationLike;
  targets?: string[];
  signal?: (cancel: boolean) => void;
}

export interface SourceScanResult {
  detections: Detection[];
  errors: ScanError[];
  filesScanned: number;
  linesScanned: number;
  bytesScanned: number;
  privateKeyFiles: string[];
}

const DEFAULT_EXCLUDE = ['node_modules', '.git', 'dist', 'build', '.venv', 'out', 'target', '.next'];

function isExcluded(name: string, exclude: string[]): boolean {
  return exclude.some((pattern) => name === pattern || name.startsWith(`${pattern}.`));
}

/** Recursively list scannable files, honouring exclusions, size caps and cancellation. */
export async function discoverFiles(options: DiscoverOptions): Promise<DiscoverResult> {
  const exclude = [...DEFAULT_EXCLUDE, ...(options.exclude ?? [])];
  const files: string[] = [];
  const skipped: string[] = [];
  const errors: ScanError[] = [];
  let bytesDiscovered = 0;
  let truncated = false;

  const queue: string[] = [];

  if (options.targets && options.targets.length > 0) {
    queue.push(...options.targets);
  } else {
    queue.push(options.root);
  }

  while (queue.length > 0) {
    if (options.token?.isCancellationRequested) {
      options.signal?.(true);
      break;
    }

    const current = queue.shift() as string;
    let stat;
    try {
      stat = await fs.stat(current);
    } catch (err) {
      const { reason, code } = describeError(err);
      errors.push({ file: relativeLabel(options.root, current), reason, code });
      continue;
    }

    if (stat.isFile()) {
      if (!isSupportedFile(path.basename(current))) {
        skipped.push(relativeLabel(options.root, current));
        continue;
      }
      if (stat.size > options.maxFileSize) {
        skipped.push(relativeLabel(options.root, current));
        continue;
      }
      if (files.length >= options.maxFiles) {
        truncated = true;
        break;
      }
      bytesDiscovered += stat.size;
      files.push(current);
      continue;
    }

    if (!stat.isDirectory()) {
      skipped.push(relativeLabel(options.root, current));
      continue;
    }

    let entries;
    try {
      entries = await fs.readdir(current, { withFileTypes: true });
    } catch (err) {
      const { reason, code } = describeError(err);
      errors.push({ file: relativeLabel(options.root, current), reason, code });
      continue;
    }

    for (const entry of entries) {
      if (isExcluded(entry.name, exclude)) {
        continue;
      }
      if (entry.isSymbolicLink()) {
        // Symlinks are ignored on purpose: they are a common way to escape the workspace.
        continue;
      }
      queue.push(path.join(current, entry.name));
    }
  }

  if (truncated) {
    logger.warn(
      `File limit of ${options.maxFiles} reached; remaining files were not scanned. Increase pariPari.maxFiles to widen coverage.`,
    );
  }

  files.sort((a, b) => a.localeCompare(b));
  return { files, skipped, errors, bytesDiscovered };
}

function sourceTypeFor(file: string): SourceType {
  const base = path.basename(file).toLowerCase();
  if (
    base === 'package.json' ||
    base === 'package-lock.json' ||
    base === 'yarn.lock' ||
    base === 'pnpm-lock.yaml' ||
    base === 'requirements.txt' ||
    base === 'pyproject.toml' ||
    base === 'pipfile' ||
    base === 'pom.xml' ||
    base === 'build.gradle' ||
    base === 'build.gradle.kts' ||
    base === 'cargo.toml' ||
    base === 'go.mod' ||
    base === 'composer.json' ||
    base === 'gemfile'
  ) {
    return 'manifest';
  }
  if (base === 'npm-shrinkwrap.json') {
    return 'lockfile';
  }
  if (/\.(ya?ml|json|xml|conf|ini|cfg|properties|toml|env)$/.test(base) || base.includes('dockerfile')) {
    return 'config';
  }
  if (/\.(pem|crt|cer|der|csr)$/.test(base)) {
    return 'certificate';
  }
  if (/\.(key|p12|pfx|jks|keystore)$/.test(base)) {
    return 'keyfile';
  }
  if (/\.(ts|tsx|js|jsx|mjs|cjs|py|java|c|cc|cpp|h|hpp|go|rs|php|cs|rb|kt|kts|swift|sh|ps1|sql)$/.test(base)) {
    return 'source';
  }
  return 'unknown';
}

const PEM_HEADER = /-----BEGIN\s+([A-Z0-9 ]+)-----/;

function bumpConfidence(
  base: Confidence,
  _rule: CryptoPatternRule,
  line: string,
  sourceType: SourceType,
): Confidence {
  if (base === 'HIGH') {
    return 'HIGH';
  }
  const hasCryptoContext = CRYPTO_CONTEXT_TOKENS.some((token) => token.test(line));
  if (!hasCryptoContext) {
    return base === 'MEDIUM' ? 'LOW' : base;
  }
  if (sourceType === 'source' && hasCryptoContext) {
    return 'HIGH';
  }
  return base === 'LOW' ? 'MEDIUM' : 'HIGH';
}

function matchLine(
  line: string,
  lineNumber: number,
  file: string,
  sourceType: SourceType,
): Detection[] {
  const results: Detection[] = [];
  for (const rule of ALL_RULES) {
    const match = rule.pattern.exec(line);
    if (!match) {
      continue;
    }
    results.push({
      id: '',
      algorithm: rule.name,
      assetType: rule.assetType,
      file,
      line: lineNumber,
      column: columnFromIndex(line, match.index),
      context: redactContext(line),
      sourceType,
      detectionMethod: rule.detectionMethod,
      confidence: bumpConfidence(rule.baseConfidence, rule, line, sourceType),
      risk: rule.risk,
      keySize: rule.keySize,
      rationale: rule.rationale,
    });
  }
  return results;
}

const YIELD_EVERY = 200;

/** Read one file and produce its detections. Never throws for expected IO errors. */
export async function scanTextContent(
  content: string,
  file: string,
  root: string,
): Promise<Detection[]> {
  const label = relativeLabel(root, file);
  const sourceType = sourceTypeFor(file);
  const detections: Detection[] = [];
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.length === 0) {
      continue;
    }
    const header = PEM_HEADER.exec(line);
    if (header) {
      const kind = header[1];
      detections.push({
        id: '',
        algorithm: kind.includes('PRIVATE KEY') ? 'Private key material' : 'X.509 certificate',
        assetType: kind.includes('PRIVATE KEY') ? 'private_key_material' : 'certificate',
        file: label,
        line: i + 1,
        column: 1,
        context: `[file header] ${kind} — body not read`,
        sourceType: kind.includes('PRIVATE KEY') ? 'keyfile' : 'certificate',
        detectionMethod: 'CONTENT_HEADER',
        confidence: 'HIGH',
        risk: kind.includes('PRIVATE KEY') ? 'HIGH' : 'INFO',
        rationale: `PEM "${kind}" header detected. The key/certificate body is never read or displayed.`,
      });
    }
    for (const detection of matchLine(line, i + 1, label, sourceType)) {
      detections.push(detection);
    }
  }

  return detections;
}

export interface ScanFilesOptions {
  root: string;
  files: string[];
  maxFileSize: number;
  token?: CancellationLike;
  onFileProcessed?: (processed: number, total: number, file: string) => void;
  signal?: (cancel: boolean) => void;
}

export async function scanFiles(options: ScanFilesOptions): Promise<SourceScanResult> {
  const detections: Detection[] = [];
  const errors: ScanError[] = [];
  const privateKeyFiles: string[] = [];
  let filesScanned = 0;
  let linesScanned = 0;
  let bytesScanned = 0;

  for (let i = 0; i < options.files.length; i += 1) {
    if (options.token?.isCancellationRequested) {
      options.signal?.(true);
      break;
    }

    const file = options.files[i];
    const label = relativeLabel(options.root, file);

    if (PRIVATE_KEY_FILE_PATTERNS.some((pattern) => pattern.test(path.basename(file)))) {
      // Signal only. The file is never opened.
      privateKeyFiles.push(label);
      detections.push({
        id: '',
        algorithm: 'Potential private-key file',
        assetType: 'private_key_material',
        file: label,
        line: 0,
        column: 0,
        context: 'Potential private-key file detected (file name signal only; contents not read)',
        sourceType: 'keyfile',
        detectionMethod: 'FILENAME_SIGNAL',
        confidence: 'MEDIUM',
        risk: 'HIGH',
        rationale:
          'File name matches a private-key container. PARI PARI does not open, parse or display key material.',
      });
      filesScanned += 1;
      options.onFileProcessed?.(i + 1, options.files.length, toPosix(file));
      continue;
    }

    try {
      const stat = await fs.stat(file);
      if (stat.size > options.maxFileSize) {
        errors.push({
          file: label,
          reason: `Skipped: larger than maxFileSize (${options.maxFileSize} bytes)`,
          code: 'TOO_LARGE',
        });
        options.onFileProcessed?.(i + 1, options.files.length, toPosix(file));
        continue;
      }

      const buffer = await fs.readFile(file);
      bytesScanned += buffer.byteLength;
      const content = buffer.toString('utf8');
      if (content.includes('\u0000')) {
        errors.push({ file: label, reason: 'Skipped: binary content detected', code: 'BINARY' });
        options.onFileProcessed?.(i + 1, options.files.length, toPosix(file));
        continue;
      }

      linesScanned += content.split(/\r?\n/).length;
      const found = await scanTextContent(content, file, options.root);
      detections.push(...found);
      filesScanned += 1;
    } catch (err) {
      const { reason, code } = describeError(err);
      errors.push({ file: label, reason, code });
      logger.warn(`Skipped ${label}: ${reason}`);
    }

    options.onFileProcessed?.(i + 1, options.files.length, toPosix(file));

    if (i % YIELD_EVERY === 0) {
      // Keep the extension host responsive during large scans.
      await new Promise((resolve) => setImmediate(resolve));
    }
  }

  return { detections, errors, filesScanned, linesScanned, bytesScanned, privateKeyFiles };
}
