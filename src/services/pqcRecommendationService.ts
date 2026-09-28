/**
 * Post-quantum migration abstraction (Phase 4 placeholder).
 *
 * Phase 1 ships the *interface only*. No authoritative recommendations are
 * produced: `evaluate` always returns `status: 'not-implemented'` with an
 * explanation. Future phases will fill in standards-based candidate mapping
 * (ML-KEM / ML-DSA / SLH-DSA) driven by ECDAT quantum-risk analysis.
 */

import type { RiskLevel } from '../scanner/types';

export interface PqcEvaluationContext {
  /** Current algorithm, e.g. `RSA`, `AES`, `ECC`. */
  currentAlgorithm?: string;
  /** Current key size in bits, e.g. `2048`. */
  currentKeySize?: number;
  /** What the primitive protects. */
  useCase?: 'authentication' | 'confidentiality' | 'integrity' | 'key-establishment' | 'signing';
  /** Throughput or latency sensitivity. */
  performanceRequirement?: 'low' | 'medium' | 'high';
  /** How long the protected data must remain confidential. */
  dataLifetime?: 'ephemeral' | 'short' | 'medium' | 'long' | 'permanent';
  /** Estimated engineering effort to migrate. */
  migrationComplexity?: 'small' | 'standard' | 'legacy' | 'complex';
}

export interface PqcRecommendation {
  currentAlgorithm: string;
  currentKeySize?: number;
  useCase?: string;
  performanceRequirement?: string;
  dataLifetime?: string;
  migrationComplexity?: string;
  /** Placeholder — populated by a future ECDAT phase. */
  recommendedOption?: string;
  /** Placeholder — e.g. hybrid classical + PQC construction. */
  hybridOption?: string;
  status: 'not-implemented' | 'available';
  note: string;
  candidates: string[];
  risk?: RiskLevel;
}

export interface PqcRecommendationService {
  evaluate(context: PqcEvaluationContext): PqcRecommendation;
}

/**
 * Candidate names reserved for the future implementation. Listing them here is
 * documentation, not a claim that PARI PARI can select them today.
 */
export const FUTURE_CANDIDATES: readonly string[] = [
  'ML-KEM (FIPS 203) — key establishment',
  'ML-DSA (FIPS 204) — digital signatures',
  'SLH-DSA (FIPS 205) — hash-based signatures',
];

export class StubPqcRecommendationService implements PqcRecommendationService {
  evaluate(context: PqcEvaluationContext): PqcRecommendation {
    return {
      currentAlgorithm: context.currentAlgorithm ?? 'unknown',
      currentKeySize: context.currentKeySize,
      useCase: context.useCase,
      performanceRequirement: context.performanceRequirement,
      dataLifetime: context.dataLifetime,
      migrationComplexity: context.migrationComplexity,
      status: 'not-implemented',
      candidates: [...FUTURE_CANDIDATES],
      note:
        'PARI PARI Terminal v0.1.0 does not determine production migration choices. ' +
        'Quantum-risk analysis and authoritative PQC/hybrid guidance are delivered by the ' +
        'PARI PARI ECDAT platform in a later phase.',
    };
  }
}

export const pqcRecommendationService: PqcRecommendationService = new StubPqcRecommendationService();
