/**
 * Core data contracts for the PARI PARI Terminal scanner.
 *
 * Design rule: a detection is an *indicator* found in static text. It is never
 * proof of real cryptographic usage. The distinction is modelled explicitly by
 * `Detection.confidence` plus `Detection.detectionMethod`.
 */

export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH';

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AssetType =
  | 'cryptographic_algorithm'
  | 'cryptographic_api'
  | 'cryptographic_library'
  | 'protocol'
  | 'certificate'
  | 'key_reference'
  | 'private_key_material'
  | 'configuration';

export type DetectionMethod =
  | 'PATTERN_MATCH'
  | 'API_PATTERN'
  | 'MANIFEST_DECLARATION'
  | 'CONFIG_PATTERN'
  | 'FILENAME_SIGNAL'
  | 'CONTENT_HEADER';

export type SourceType =
  | 'source'
  | 'manifest'
  | 'lockfile'
  | 'config'
  | 'certificate'
  | 'keyfile'
  | 'unknown';

export type ScanMode = 'workspace' | 'folder' | 'file';

export interface Detection {
  /** Stable, human readable identifier, e.g. `PARI-0001`. Assigned at CBOM build time. */
  id: string;
  /** Canonical name, e.g. `RSA`, `AES-256`, `crypto.createHash`. */
  algorithm: string;
  assetType: AssetType;
  /** Workspace-relative POSIX path. */
  file: string;
  /** 1-based line number, 0 when the signal came from the file name. */
  line: number;
  /** 1-based column, 0 when unknown. */
  column: number;
  /** Trimmed, redacted source context. Never contains secret material. */
  context: string;
  sourceType: SourceType;
  detectionMethod: DetectionMethod;
  confidence: Confidence;
  /** Preliminary static-analysis risk. Not a security verdict. */
  risk: RiskLevel;
  keySize?: number;
  /** Library the indicator was attributed to, when known. */
  library?: string;
  /** Why the engine believes this indicator, shown in the UI. */
  rationale?: string;
}

export interface LibraryUsage {
  name: string;
  version?: string;
  ecosystem: string;
  category: 'crypto_library' | 'tls_library' | 'hashing' | 'randomness' | 'other';
  file: string;
  line: number;
  manifest: string;
}

export interface CertificateInfo {
  subject?: string;
  issuer?: string;
  notBefore?: string;
  notAfter?: string;
  serialNumber?: string;
  signatureAlgorithm?: string;
  publicKeyAlgorithm?: string;
  file: string;
  /** True when only a PEM/ASN.1 header was observed and the body was not read. */
  metadataOnly: boolean;
}

export interface ProtocolUsage {
  protocol: string;
  version?: string;
  file: string;
  line: number;
  context: string;
  confidence: Confidence;
}

export interface ConfigSignal {
  setting: string;
  value: string;
  file: string;
  line: number;
  risk: RiskLevel;
  note: string;
}

export interface ScanError {
  file: string;
  reason: string;
  code?: string;
}

export interface ScanStats {
  filesDiscovered: number;
  filesScanned: number;
  filesSkipped: number;
  bytesScanned: number;
  linesScanned: number;
  durationMs: number;
}

export interface ScanResult {
  scanId: string;
  mode: ScanMode;
  root: string;
  rootLabel: string;
  startedAt: string;
  completedAt: string;
  cancelled: boolean;
  detections: Detection[];
  libraries: LibraryUsage[];
  certificates: CertificateInfo[];
  protocols: ProtocolUsage[];
  configSignals: ConfigSignal[];
  privateKeyFiles: string[];
  errors: ScanError[];
  stats: ScanStats;
}

export type ScanStage =
  | 'discover'
  | 'source'
  | 'dependencies'
  | 'config'
  | 'build'
  | 'done';

export interface ScanProgress {
  stage: ScanStage;
  /** 1-based stage index out of `totalStages`. */
  step: number;
  totalSteps: number;
  message: string;
  filesProcessed?: number;
  filesTotal?: number;
}

export interface ScanRequest {
  root: string;
  mode: ScanMode;
  /** Restrict the scan to these absolute paths (file / folder modes). */
  targets?: string[];
  exclude?: string[];
  maxFileSize?: number;
  maxFiles?: number;
  label?: string;
}

/** Minimal cancellation contract so the engine stays independent of the VS Code API. */
export interface CancellationLike {
  isCancellationRequested: boolean;
  onCancellationRequested?: (listener: () => void) => { dispose(): void };
}
