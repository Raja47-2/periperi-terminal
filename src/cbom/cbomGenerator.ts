/**
 * Local CBOM generator.
 *
 * Pure function: `ScanResult` in, `Cbom` out. No I/O, no network.
 */

import type { Detection, RiskLevel, ScanResult } from '../scanner/types';
import { summarizeRisk } from '../scanner/scanner';
import { assetId } from '../utils/id';
import { CBOM_VERSION, CONFIDENCE_NOTE, DISCLAIMER, EXTENSION_VERSION } from '../version';
import type { Cbom, CbomAlgorithm, CbomAsset, CbomLibrary, CbomProtocol } from './types';

export interface GenerateOptions {
  project?: string;
  projectVersion?: string;
}

const ALGORITHM_CATEGORIES: readonly { name: string; pattern: RegExp }[] = [
  { name: 'asymmetric', pattern: /^(RSA|DSA|ECDSA|ECDH|ECC|Ed25519|Diffie-Hellman)$/i },
  { name: 'symmetric', pattern: /^(AES|DES|3DES|Blowfish|RC4|ChaCha20)$/i },
  { name: 'hash', pattern: /^(SHA|MD|CRC)/i },
  { name: 'mac', pattern: /^(HMAC|CMAC|Poly1305)$/i },
  { name: 'kdf', pattern: /^(PBKDF2|HKDF|Argon2|bcrypt|scrypt)$/i },
  { name: 'protocol', pattern: /^(TLS|SSL|DTLS|QUIC|HTTPS|SSH|IPsec)$/i },
  { name: 'post-quantum-candidate', pattern: /^(ML-KEM|ML-DSA|SLH-DSA|CRYSTALS)/i },
];

export function categorizeAlgorithm(name: string): string {
  for (const category of ALGORITHM_CATEGORIES) {
    if (category.pattern.test(name)) {
      return category.name;
    }
  }
  return 'unclassified';
}

function severity(risk: RiskLevel): number {
  switch (risk) {
    case 'CRITICAL':
      return 0;
    case 'HIGH':
      return 1;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 3;
    default:
      return 4;
  }
}

function groupAlgorithms(detections: Detection[]): CbomAlgorithm[] {
  const map = new Map<string, CbomAlgorithm>();

  for (const d of detections) {
    if (d.assetType !== 'cryptographic_algorithm' && d.assetType !== 'protocol') {
      continue;
    }
    const key = d.algorithm;
    const entry = map.get(key) ?? {
      name: key,
      category: categorizeAlgorithm(key),
      key_sizes: [],
      risk: d.risk,
      occurrences: 0,
    };
    entry.occurrences += 1;
    if (typeof d.keySize === 'number' && !entry.key_sizes.includes(d.keySize)) {
      entry.key_sizes.push(d.keySize);
    }
    if (severity(d.risk) < severity(entry.risk)) {
      entry.risk = d.risk;
    }
    map.set(key, entry);
  }

  return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function groupLibraries(result: ScanResult): CbomLibrary[] {
  const map = new Map<string, CbomLibrary>();

  for (const d of result.detections) {
    if (d.assetType !== 'cryptographic_library') {
      continue;
    }
    const name = d.library ?? d.algorithm;
    const entry =
      map.get(name) ??
      ({ name, ecosystem: 'unknown', category: 'crypto_library', declared_in: [] } as CbomLibrary);
    if (!entry.declared_in.includes(d.file)) {
      entry.declared_in.push(d.file);
    }
    map.set(name, entry);
  }

  for (const lib of result.libraries) {
    const entry =
      map.get(lib.name) ??
      ({
        name: lib.name,
        version: lib.version,
        ecosystem: lib.ecosystem,
        category: lib.category,
        declared_in: [],
      } as CbomLibrary);
    if (lib.version && !entry.version) {
      entry.version = lib.version;
    }
    if (!entry.declared_in.includes(lib.file)) {
      entry.declared_in.push(lib.file);
    }
    map.set(lib.name, entry);
  }

  return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function groupProtocols(result: ScanResult): CbomProtocol[] {
  const map = new Map<string, CbomProtocol>();
  for (const d of result.detections) {
    if (d.assetType !== 'protocol') {
      continue;
    }
    const entry = map.get(d.algorithm) ?? { name: d.algorithm, occurrences: 0 };
    entry.occurrences += 1;
    map.set(d.algorithm, entry);
  }
  return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function generateCbom(result: ScanResult, options: GenerateOptions = {}): Cbom {
  const assets: CbomAsset[] = result.detections.map((d, index) => {
    const asset: CbomAsset = {
      asset_id: assetId(index),
      type: d.assetType as CbomAsset['type'],
      algorithm: d.algorithm,
      file: d.file,
      line: d.line,
      column: d.column,
      confidence: d.confidence,
      risk: d.risk,
      source_type: d.sourceType,
      detection_method: d.detectionMethod,
      context: d.context,
      rationale: d.rationale,
    };
    if (typeof d.keySize === 'number') {
      asset.key_size = d.keySize;
    }
    if (d.library) {
      asset.library = d.library;
    }
    return asset;
  });

  const risk = summarizeRisk(result.detections);

  const certificates = result.detections
    .filter((d) => d.assetType === 'certificate')
    .map((d) => ({ file: d.file, line: d.line, metadata_only: true }));

  return {
    cbom_version: CBOM_VERSION,
    bom_format: 'PARI_PARI_CBOM',
    project: options.project ?? result.rootLabel,
    version: options.projectVersion ?? '0.0.0',
    generated_at: new Date().toISOString(),
    scan_id: result.scanId,
    scan_mode: result.mode,
    root: result.rootLabel,
    scope: 'local-static-analysis',
    assets,
    algorithms: groupAlgorithms(result.detections),
    libraries: groupLibraries(result),
    protocols: groupProtocols(result),
    certificates,
    risk_summary: {
      total: risk.total,
      critical: risk.critical,
      high: risk.high,
      medium: risk.medium,
      low: risk.low,
      info: risk.info,
    },
    private_key_files: result.privateKeyFiles,
    stats: {
      files_discovered: result.stats.filesDiscovered,
      files_scanned: result.stats.filesScanned,
      files_skipped: result.stats.filesSkipped,
      bytes_scanned: result.stats.bytesScanned,
      duration_ms: result.stats.durationMs,
    },
    errors: result.errors.map((e) => ({ file: e.file, reason: e.reason })),
    metadata: {
      generator: 'PARI PARI Terminal',
      generator_version: EXTENSION_VERSION,
      analysis_type: 'static',
      disclaimer: DISCLAIMER,
      confidence_note: CONFIDENCE_NOTE,
      extension_points: ['x_quantum_risk', 'x_pqc_mapping', 'x_confirmed_usage'],
      // Phase 3 (quantum risk) and Phase 4 (PQC mapping) placeholders.
      x_quantum_risk: {},
      x_pqc_mapping: {},
    },
  };
}
