/**
 * Cryptographic Bill of Materials (CBOM) schema types.
 *
 * The schema is deliberately extensible: `metadata` and `x_*` extension slots
 * absorb future ECDAT phases (quantum risk, PQC mapping) without breaking
 * existing consumers.
 */

import type { Confidence, RiskLevel, SourceType } from '../scanner/types';

export interface CbomAsset {
  asset_id: string;
  type: CbomAssetType;
  algorithm?: string;
  key_size?: number;
  library?: string;
  file: string;
  line: number;
  column: number;
  confidence: Confidence;
  risk: RiskLevel;
  source_type: SourceType;
  detection_method: string;
  context?: string;
  rationale?: string;
}

export type CbomAssetType =
  | 'cryptographic_algorithm'
  | 'cryptographic_api'
  | 'cryptographic_library'
  | 'protocol'
  | 'certificate'
  | 'private_key_material'
  | 'configuration';

export interface CbomAlgorithm {
  name: string;
  category: string;
  key_sizes: number[];
  risk: RiskLevel;
  occurrences: number;
}

export interface CbomLibrary {
  name: string;
  version?: string;
  ecosystem: string;
  category: string;
  declared_in: string[];
}

export interface CbomProtocol {
  name: string;
  version?: string;
  occurrences: number;
}

export interface CbomCertificate {
  file: string;
  line: number;
  metadata_only: boolean;
}

export interface CbomScanStats {
  files_discovered: number;
  files_scanned: number;
  files_skipped: number;
  bytes_scanned: number;
  duration_ms: number;
}

export interface Cbom {
  cbom_version: string;
  bom_format: 'PARI_PARI_CBOM';
  project: string;
  version: string;
  generated_at: string;
  scan_id: string;
  scan_mode: string;
  root: string;
  scope: 'local-static-analysis';
  assets: CbomAsset[];
  algorithms: CbomAlgorithm[];
  libraries: CbomLibrary[];
  protocols: CbomProtocol[];
  certificates: CbomCertificate[];
  risk_summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  private_key_files: string[];
  stats: CbomScanStats;
  errors: { file: string; reason: string }[];
  metadata: CbomMetadata;
}

export interface CbomMetadata {
  generator: string;
  generator_version: string;
  /** Confirms the detection is static-analysis-only. */
  analysis_type: 'static';
  disclaimer: string;
  confidence_note: string;
  extension_points: string[];
  /** Reserved for future quantum-risk analysis (Phase 3). */
  x_quantum_risk?: Record<string, unknown>;
  /** Reserved for future PQC mapping (Phase 4). */
  x_pqc_mapping?: Record<string, unknown>;
}
