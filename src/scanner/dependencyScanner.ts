/**
 * Dependency manifest inspection.
 *
 * Reads manifest files as text only. It never runs `npm install`, never
 * resolves transitive packages and never executes lifecycle scripts.
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';

import type { Detection, LibraryUsage, ScanError } from './types';
import { relativeLabel } from '../utils/paths';
import { redactContext } from '../utils/redact';
import { describeError } from '../utils/errors';

export interface KnownDependency {
  /** Canonical library name. */
  name: string;
  /** Lower-case tokens that identify the package in a manifest. */
  tokens: string[];
  category: LibraryUsage['category'];
  risk: Detection['risk'];
  rationale: string;
}

export const CRYPTO_DEPENDENCIES: readonly KnownDependency[] = [
  {
    name: 'OpenSSL',
    tokens: ['openssl', 'libssl', 'node-openssl', 'openssl-sys'],
    category: 'tls_library',
    risk: 'MEDIUM',
    rationale: 'OpenSSL is the dominant native TLS/crypto provider; its version drives most CVEs.',
  },
  {
    name: 'BoringSSL',
    tokens: ['boringssl', 'boringssl-sys'],
    category: 'tls_library',
    risk: 'MEDIUM',
    rationale: 'BoringSSL is a Chromium/Fork TLS provider used in Node.js and other runtimes.',
  },
  {
    name: 'LibreSSL',
    tokens: ['libressl'],
    category: 'tls_library',
    risk: 'MEDIUM',
    rationale: 'LibreSSL is an OpenSSL fork maintained by the OpenBSD project.',
  },
  {
    name: 'libsodium',
    tokens: ['libsodium', 'libsodium-wrappers', 'sodium-native', 'jose'],
    category: 'crypto_library',
    risk: 'LOW',
    rationale: 'libsodium provides modern, high-usage-resistance primitives.',
  },
  {
    name: 'Bouncy Castle',
    tokens: ['bcprov', 'bcpkix', 'bouncycastle', 'bc-fips', 'spongycastle'],
    category: 'crypto_library',
    risk: 'MEDIUM',
    rationale: 'Bouncy Castle is the standard JCE provider for Java cryptography.',
  },
  {
    name: 'Node.js crypto',
    tokens: ['node:crypto', 'crypto-js', 'node-forge', 'browserify-sign'],
    category: 'crypto_library',
    risk: 'LOW',
    rationale: 'Platform or JS crypto provider used by the application.',
  },
  {
    name: 'Web Crypto API',
    tokens: ['isomorphic-webcrypto', 'webcrypto-core', '@peculiar/webcrypto'],
    category: 'crypto_library',
    risk: 'LOW',
    rationale: 'Web Crypto (SubtleCrypto) usage indicator for browser or edge runtimes.',
  },
  {
    name: 'cryptography (PyCA)',
    tokens: ['cryptography', 'pyopenssl'],
    category: 'crypto_library',
    risk: 'LOW',
    rationale: 'PyCA cryptography is the reference Python TLS/crypto library.',
  },
  {
    name: 'PyCryptodome',
    tokens: ['pycryptodome', 'pycryptodomex', 'pycrypto'],
    category: 'crypto_library',
    risk: 'MEDIUM',
    rationale: 'PyCryptodome exposes low-level primitives; it is frequently used with legacy ciphers.',
  },
  {
    name: 'JCA / JCE',
    tokens: ['bouncycastle', 'jose4j', 'nimbus-jose-jwt', 'jjwt'],
    category: 'crypto_library',
    risk: 'LOW',
    rationale: 'Java JWT/JCE provider; algorithm choice is configured in code.',
  },
  {
    name: 'RustCrypto',
    tokens: ['rustcrypto', 'ring', 'aws-lc-rs', 'aws-lc-sys', 'sha2', 'hmac', 'hkdf', 'pbkdf2', 'argon2', 'chacha20poly1305'],
    category: 'crypto_library',
    risk: 'LOW',
    rationale: 'RustCrypto/ring provide audited Rust implementations of standard primitives.',
  },
  {
    name: 'Go crypto stdlib',
    tokens: ['golang.org/x/crypto', 'crypto/tls'],
    category: 'crypto_library',
    risk: 'LOW',
    rationale: 'Go extended crypto packages (x/crypto, cloudflare-go, etc.).',
  },
  {
    name: 'JWT libraries',
    tokens: ['jsonwebtoken', 'pyjwt', 'jose', 'jwt-go', 'auth0', 'nimbus-jose-jwt'],
    category: 'other',
    risk: 'MEDIUM',
    rationale: 'JWT libraries pin signature algorithms; `alg: none` and RS256->ES256 mismatches are common risks.',
  },
  {
    name: 'Randomness helpers',
    tokens: ['secure-random', 'randombytes', 'nanoid', 'uuid', 'csprng'],
    category: 'randomness',
    risk: 'LOW',
    rationale: 'Randomness helper; verify it is backed by a CSPRNG for key or nonce generation.',
  },
];

export interface ManifestFormat {
  file: string;
  ecosystem: string;
  kind: 'json' | 'text' | 'lockfile' | 'xml' | 'gradle' | 'toml' | 'gomod';
}

export function identifyManifest(file: string): ManifestFormat | undefined {
  const base = path.basename(file).toLowerCase();
  const dir = path.dirname(file).toLowerCase();
  if (base === 'package.json' || base === 'composer.json') {
    return { file, ecosystem: base === 'composer.json' ? 'php' : 'npm', kind: 'json' };
  }
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') {
    return { file, ecosystem: 'npm', kind: 'lockfile' };
  }
  if (base === 'yarn.lock' || base === 'pnpm-lock.yaml') {
    return { file, ecosystem: base === 'yarn.lock' ? 'yarn' : 'pnpm', kind: 'lockfile' };
  }
  if (base === 'requirements.txt' || base === 'pipfile') {
    return { file, ecosystem: 'python', kind: 'text' };
  }
  if (base === 'pyproject.toml') {
    return { file, ecosystem: 'python', kind: 'toml' };
  }
  if (base === 'pom.xml') {
    return { file, ecosystem: 'maven', kind: 'xml' };
  }
  if (base === 'build.gradle' || base === 'build.gradle.kts') {
    return { file, ecosystem: 'gradle', kind: 'gradle' };
  }
  if (base === 'cargo.toml') {
    return { file, ecosystem: 'cargo', kind: 'toml' };
  }
  if (base === 'go.mod') {
    return { file, ecosystem: 'go', kind: 'gomod' };
  }
  if (base === 'gemfile') {
    return { file, ecosystem: 'rubygems', kind: 'text' };
  }
  if (base === 'gemfile.lock') {
    return { file, ecosystem: 'rubygems', kind: 'lockfile' };
  }
  if (dir.endsWith('.m2') || base.endsWith('.pom')) {
    return { file, ecosystem: 'maven', kind: 'xml' };
  }
  return undefined;
}

export interface ExtractResult {
  libraries: LibraryUsage[];
  detections: Detection[];
}

function addLibrary(
  result: ExtractResult,
  known: KnownDependency,
  version: string | undefined,
  manifest: ManifestFormat,
  root: string,
  line: number,
  token: string,
): void {
  const existing = result.libraries.find(
    (lib) => lib.name === known.name && lib.file === relativeLabel(root, manifest.file),
  );
  if (existing) {
    if (!existing.version && version) {
      existing.version = version;
    }
    return;
  }
  result.libraries.push({
    name: known.name,
    version,
    ecosystem: manifest.ecosystem,
    category: known.category,
    file: relativeLabel(root, manifest.file),
    line,
    manifest: path.basename(manifest.file),
  });
  result.detections.push({
    id: '',
    algorithm: known.name,
    assetType: 'cryptographic_library',
    file: relativeLabel(root, manifest.file),
    line,
    column: 1,
    context: redactContext(`dependency "${token}"${version ? `@${version}` : ''} in ${manifest.ecosystem} manifest`),
    sourceType: 'manifest',
    detectionMethod: 'MANIFEST_DECLARATION',
    confidence: 'HIGH',
    risk: known.risk,
    library: known.name,
    rationale: known.rationale,
  });
}

function matchKnown(name: string): KnownDependency | undefined {
  const lower = name.toLowerCase();
  return CRYPTO_DEPENDENCIES.find((known) => known.tokens.some((token) => lower === token));
}

function looseMatch(line: string): { token: string; known: KnownDependency }[] {
  const lower = line.toLowerCase();
  const out: { token: string; known: KnownDependency }[] = [];
  for (const known of CRYPTO_DEPENDENCIES) {
    for (const token of known.tokens) {
      if (token.length < 4) {
        continue;
      }
      if (lower.includes(token)) {
        out.push({ token, known });
        break;
      }
    }
  }
  return out;
}

function findLine(content: string, needle: string): number {
  const lines = content.split(/\r?\n/);
  const target = needle.toLowerCase();
  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i].toLowerCase().includes(target)) {
      return i + 1;
    }
  }
  return 1;
}

/** Parse a manifest and report crypto-relevant dependencies. Pure text analysis. */
export function parseManifest(content: string, manifest: ManifestFormat, root: string): ExtractResult {
  const result: ExtractResult = { libraries: [], detections: [] };

  if (manifest.kind === 'json') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      // Malformed JSON: fall back to a tolerant line scan.
      scanLines(content, manifest, root, result);
      return result;
    }
    collectJson(parsed, manifest, root, result, content);
    return result;
  }

  scanLines(content, manifest, root, result);
  return result;
}

function collectJson(
  node: unknown,
  manifest: ManifestFormat,
  root: string,
  result: ExtractResult,
  text: string,
): void {
  if (Array.isArray(node)) {
    for (const item of node) {
      collectJson(item, manifest, root, result, text);
    }
    return;
  }
  if (!node || typeof node !== 'object') {
    return;
  }

  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    if (
      key === 'dependencies' ||
      key === 'devDependencies' ||
      key === 'peerDependencies' ||
      key === 'optionalDependencies'
    ) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        for (const [depName, depVersion] of Object.entries(value as Record<string, unknown>)) {
          const known = matchKnown(depName);
          if (known) {
            addLibrary(
              result,
              known,
              typeof depVersion === 'string' ? depVersion : undefined,
              manifest,
              root,
              findLine(text, `"${depName}"`),
              depName,
            );
          }
        }
      }
      continue;
    }
    collectJson(value, manifest, root, result, text);
  }
}

function scanLines(
  text: string,
  manifest: ManifestFormat,
  root: string,
  result: ExtractResult,
): void {
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#') || trimmed.startsWith('//')) {
      continue;
    }

    if (manifest.kind === 'json' || manifest.kind === 'toml') {
      const jsonMatch = /"([^"]+)"\s*:\s*"([^"]+)"/.exec(trimmed);
      if (jsonMatch) {
        const known = matchKnown(jsonMatch[1]);
        if (known) {
          addLibrary(result, known, jsonMatch[2], manifest, root, i + 1, jsonMatch[1]);
          continue;
        }
      }
      const tomlMatch = /^\s*([A-Za-z0-9_.-]+)\s*=\s*(?:"([^"]*)"|\{[^}]*version\s*=\s*"([^"]*)")/.exec(raw);
      if (tomlMatch) {
        const known = matchKnown(tomlMatch[1]);
        if (known) {
          addLibrary(result, known, tomlMatch[2] ?? tomlMatch[3], manifest, root, i + 1, tomlMatch[1]);
          continue;
        }
      }
    }

    if (manifest.kind === 'gomod' || manifest.kind === 'text' || manifest.kind === 'lockfile' || manifest.kind === 'gradle') {
      const reqMatch = /^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|>|<|\[|@|\s)\s*([0-9][^,\s]*)?/.exec(trimmed);
      const candidateName = reqMatch?.[1];
      if (candidateName) {
        const known = matchKnown(candidateName) ?? looseMatch(trimmed)[0]?.known;
        if (known) {
          addLibrary(result, known, reqMatch?.[2], manifest, root, i + 1, candidateName);
          continue;
        }
      }
      const loose = looseMatch(trimmed);
      if (loose.length > 0) {
        addLibrary(result, loose[0].known, undefined, manifest, root, i + 1, loose[0].token);
        continue;
      }
    }

    if (manifest.kind === 'xml') {
      const depMatch = /<artifactId>([^<]+)<\/artifactId>/.exec(trimmed);
      if (depMatch) {
        const known = matchKnown(depMatch[1]) ?? looseMatch(depMatch[1])[0]?.known;
        if (known) {
          addLibrary(result, known, undefined, manifest, root, i + 1, depMatch[1]);
        }
      }
    }
  }
}

export interface DependencyScanResult {
  libraries: LibraryUsage[];
  detections: Detection[];
  errors: ScanError[];
}

export interface DependencyScanOptions {
  root: string;
  files: string[];
  maxFileSize: number;
}

/** Inspect every manifest in the discovered file set. */
export async function scanDependencies(
  options: DependencyScanOptions,
): Promise<DependencyScanResult> {
  const libraries: LibraryUsage[] = [];
  const detections: Detection[] = [];
  const errors: ScanError[] = [];

  for (const file of options.files) {
    const manifest = identifyManifest(file);
    if (!manifest) {
      continue;
    }
    try {
      const stat = await fs.stat(file);
      if (stat.size > options.maxFileSize) {
        errors.push({
          file: relativeLabel(options.root, file),
          reason: `Skipped manifest: larger than maxFileSize (${options.maxFileSize} bytes)`,
          code: 'TOO_LARGE',
        });
        continue;
      }
      const text = (await fs.readFile(file)).toString('utf8');
      const extracted = parseManifest(text, manifest, options.root);
      libraries.push(...extracted.libraries);
      detections.push(...extracted.detections);
    } catch (err) {
      const { reason, code } = describeError(err);
      errors.push({ file: relativeLabel(options.root, file), reason, code });
    }
  }

  return { libraries, detections, errors };
}
