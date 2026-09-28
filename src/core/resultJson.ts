/**
 * Machine-readable scan output.
 *
 * `periperi scan --json` emits this shape. It is a stable, documented contract
 * for CI and scripting, so field names are explicit rather than derived.
 *
 * Free of any `vscode` import.
 */

import type { ScanResult, RiskLevel } from '../scanner/types';
import { rollupAssets, summarizeRisk, type RiskSummary } from '../scanner/scanner';
import { assetId } from '../utils/id';
import { DISCLAIMER, EXTENSION_VERSION } from '../version';

export const TOOL_NAME = 'periperi';

/** Severity ordering used by every gate and threshold check. Lower is worse. */
export const RISK_ORDER: Record<RiskLevel, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

/** Lower-case severity names accepted on the command line. */
export type ThresholdName = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** `none` disables the gate entirely. */
export type Threshold = ThresholdName | 'none';

export const THRESHOLDS: readonly Threshold[] = ['critical', 'high', 'medium', 'low', 'info', 'none'];

export function isThreshold(value: string): value is Threshold {
  return THRESHOLDS.includes(value.toLowerCase() as Threshold);
}

export function normalizeThreshold(value: string): Threshold {
  return value.toLowerCase() as Threshold;
}

/**
 * True when at least one detection is at or above `threshold`.
 * `none` never trips the gate.
 */
export function exceedsThreshold(summary: RiskSummary, threshold: Threshold): boolean {
  if (threshold === 'none') {
    return false;
  }
  const limit = RISK_ORDER[threshold.toUpperCase() as RiskLevel];
  return (Object.keys(RISK_ORDER) as RiskLevel[]).some((level) => {
    if (RISK_ORDER[level] > limit) {
      return false;
    }
    return summary[level.toLowerCase() as keyof Omit<RiskSummary, 'total'>] > 0;
  });
}

export interface ScanJsonOutput {
  tool: { name: string; version: string; analysis: 'static' };
  scope: 'local-static-analysis';
  scan: {
    id: string;
    mode: string;
    root: string;
    rootLabel: string;
    startedAt: string;
    completedAt: string;
    cancelled: boolean;
    durationMs: number;
  };
  summary: RiskSummary;
  rollup: {
    algorithms: string[];
    libraries: string[];
    protocols: string[];
    files: string[];
    certificates: number;
    privateKeys: number;
  };
  stats: ScanResult['stats'];
  detections: ScanResult['detections'];
  privateKeyFiles: string[];
  errors: ScanResult['errors'];
  disclaimer: string;
}

export function toScanJson(result: ScanResult): ScanJsonOutput {
  const rollup = rollupAssets(result);
  return {
    tool: { name: TOOL_NAME, version: EXTENSION_VERSION, analysis: 'static' },
    scope: 'local-static-analysis',
    scan: {
      id: result.scanId,
      mode: result.mode,
      root: result.root,
      rootLabel: result.rootLabel,
      startedAt: result.startedAt,
      completedAt: result.completedAt,
      cancelled: result.cancelled,
      durationMs: result.stats.durationMs,
    },
    summary: summarizeRisk(result.detections),
    rollup: {
      algorithms: rollup.algorithms,
      libraries: rollup.libraries,
      protocols: rollup.protocols,
      files: rollup.files,
      certificates: rollup.certificates,
      privateKeys: rollup.privateKeys,
    },
    stats: result.stats,
    // Ids are assigned here with the same deterministic scheme the CBOM and
    // SARIF exporters use, so all three documents refer to the same asset.
    detections: result.detections.map((detection, index) => ({
      ...detection,
      id: assetId(index),
    })),
    privateKeyFiles: result.privateKeyFiles,
    errors: result.errors,
    disclaimer: DISCLAIMER,
  };
}

export function renderScanJson(result: ScanResult): string {
  return `${JSON.stringify(toScanJson(result), null, 2)}\n`;
}
