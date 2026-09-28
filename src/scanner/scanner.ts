/**
 * Scan orchestrator.
 *
 * Runs the five real stages advertised to the user and reports progress that
 * corresponds to actual work (no fake progress bars).
 *
 * Stage 1 discover  – enumerate files under the root (or the given targets)
 * Stage 2 source    – line-by-line pattern matching
 * Stage 3 deps      – dependency manifests
 * Stage 4 config    – configuration / certificate / protocol signals
 * Stage 5 build     – assemble and rank the final ScanResult
 */

import * as path from 'node:path';

import type {
  CancellationLike,
  Detection,
  ScanProgress,
  ScanRequest,
  ScanResult,
} from './types';
import { discoverFiles, scanFiles } from './sourceScanner';
import { scanDependencies } from './dependencyScanner';
import { scanConfiguration } from './configScanner';
import { createScanId } from '../utils/id';
import { logger } from '../utils/log';
import { dirExists, relativeLabel } from '../utils/paths';

export interface ScanHooks {
  onProgress?: (progress: ScanProgress) => void;
  token?: CancellationLike;
}

const TOTAL_STEPS = 5;

function report(
  hooks: ScanHooks,
  stage: ScanProgress['stage'],
  step: number,
  message: string,
  extra: Partial<ScanProgress> = {},
): void {
  hooks.onProgress?.({ stage, step, totalSteps: TOTAL_STEPS, message, ...extra });
}

/** Ranking used for the dashboard buckets. Deterministic. */
const RISK_ORDER: Record<ScanResult['detections'][number]['risk'], number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function sortDetections(detections: Detection[]): Detection[] {
  return [...detections].sort((a, b) => {
    const riskDelta = RISK_ORDER[a.risk] - RISK_ORDER[b.risk];
    if (riskDelta !== 0) {
      return riskDelta;
    }
    const fileDelta = a.file.localeCompare(b.file);
    if (fileDelta !== 0) {
      return fileDelta;
    }
    return a.line - b.line;
  });
}

/** Collapse duplicate findings (same algorithm, file and line). */
function dedupe(detections: Detection[]): Detection[] {
  const seen = new Set<string>();
  const out: Detection[] = [];
  for (const d of detections) {
    const key = `${d.algorithm}|${d.assetType}|${d.file}|${d.line}|${d.column}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(d);
  }
  return out;
}

let scanCounter = 0;

export function resetScanCounter(): void {
  scanCounter = 0;
}

/** Execute a full scan. Resolves with a complete, deterministic result object. */
export async function runScan(request: ScanRequest, hooks: ScanHooks = {}): Promise<ScanResult> {
  const startedAt = new Date();
  const root = path.resolve(request.root);
  const exclude = request.exclude ?? [];
  const maxFileSize = request.maxFileSize ?? 1048576;
  const maxFiles = request.maxFiles ?? 20000;
  const cancelled = () => hooks.token?.isCancellationRequested === true;

  scanCounter += 1;
  const scanId = createScanId(scanCounter, startedAt);

  logger.info(
    `Scan started (${scanId}) mode=${request.mode} root=${relativeLabel(root, root) || '.'}`,
  );

  report(hooks, 'discover', 1, 'Discovering supported files…');
  const discovery = await discoverFiles({
    root,
    exclude,
    maxFileSize,
    maxFiles,
    targets: request.targets,
    token: hooks.token,
  });

  logger.info(
    `Files discovered=${discovery.files.length} skipped=${discovery.skipped.length} errors=${discovery.errors.length}`,
  );

  report(hooks, 'source', 2, 'Analysing source files…', {
    filesProcessed: 0,
    filesTotal: discovery.files.length,
  });

  const sourceResult = await scanFiles({
    root,
    files: discovery.files,
    maxFileSize,
    token: hooks.token,
    onFileProcessed: (processed, total) => {
      report(hooks, 'source', 2, 'Analysing source files…', {
        filesProcessed: processed,
        filesTotal: total,
      });
    },
  });
  logger.info(`Source scan complete: ${sourceResult.detections.length} indicators`);

  report(hooks, 'dependencies', 3, 'Analysing dependencies…', {
    filesProcessed: 0,
    filesTotal: discovery.files.length,
  });
  const dependencyResult = await scanDependencies({
    root,
    files: discovery.files,
    maxFileSize,
  });
  logger.info(`Dependency scan complete: ${dependencyResult.libraries.length} libraries`);

  report(hooks, 'config', 4, 'Detecting cryptographic artefacts…', {
    filesProcessed: 0,
    filesTotal: discovery.files.length,
  });
  const configResult = await scanConfiguration({ root, files: discovery.files });
  logger.info(
    `Config scan complete: ${configResult.configSignals.length} signals, ${configResult.protocols.length} protocol references`,
  );

  report(hooks, 'build', 5, 'Preparing results…');

  const detections = dedupe(
    sortDetections([
      ...sourceResult.detections,
      ...dependencyResult.detections,
      ...configResult.detections,
    ]),
  );

  const errors = [
    ...discovery.errors,
    ...sourceResult.errors,
    ...dependencyResult.errors,
    ...configResult.errors,
  ];

  const completedAt = new Date();
  const result: ScanResult = {
    scanId,
    mode: request.mode,
    root,
    rootLabel: request.label ?? (dirExists(root) ? path.basename(root) : relativeLabel(root, root)),
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    cancelled: cancelled(),
    detections,
    libraries: dependencyResult.libraries,
    certificates: [],
    protocols: configResult.protocols,
    configSignals: configResult.configSignals,
    privateKeyFiles: sourceResult.privateKeyFiles,
    errors,
    stats: {
      filesDiscovered: discovery.files.length,
      filesScanned: sourceResult.filesScanned,
      filesSkipped: discovery.skipped.length,
      bytesScanned: sourceResult.bytesScanned,
      linesScanned: sourceResult.linesScanned,
      durationMs: completedAt.getTime() - startedAt.getTime(),
    },
  };

  logger.info(
    `Scan completed (${scanId}): assets=${detections.length} libraries=${result.libraries.length} errors=${errors.length} cancelled=${result.cancelled}`,
  );

  report(hooks, 'done', TOTAL_STEPS, 'Scan completed');
  return result;
}

export interface RiskSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export function summarizeRisk(detections: Detection[]): RiskSummary {
  const summary: RiskSummary = {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const d of detections) {
    summary.total += 1;
    if (d.risk === 'CRITICAL') {
      summary.critical += 1;
    } else if (d.risk === 'HIGH') {
      summary.high += 1;
    } else if (d.risk === 'MEDIUM') {
      summary.medium += 1;
    } else if (d.risk === 'LOW') {
      summary.low += 1;
    } else {
      summary.info += 1;
    }
  }
  return summary;
}

export interface AssetRollup {
  algorithms: string[];
  libraries: string[];
  protocols: string[];
  certificates: number;
  privateKeys: number;
  files: string[];
}

export function rollupAssets(result: ScanResult): AssetRollup {
  const algorithms = new Set<string>();
  const libraries = new Set<string>();
  const protocols = new Set<string>();
  const files = new Set<string>();
  let certificates = 0;
  let privateKeys = 0;

  for (const d of result.detections) {
    if (d.assetType === 'cryptographic_algorithm' || d.assetType === 'cryptographic_api') {
      algorithms.add(d.algorithm);
    } else if (d.assetType === 'cryptographic_library') {
      libraries.add(d.library ?? d.algorithm);
    } else if (d.assetType === 'protocol') {
      protocols.add(d.algorithm);
    } else if (d.assetType === 'certificate') {
      certificates += 1;
    } else if (d.assetType === 'private_key_material') {
      privateKeys += 1;
    }
    files.add(d.file);
  }

  for (const lib of result.libraries) {
    libraries.add(lib.name);
  }
  for (const proto of result.protocols) {
    protocols.add(proto.version ? `${proto.protocol} ${proto.version}` : proto.protocol);
  }

  return {
    algorithms: [...algorithms].sort(),
    libraries: [...libraries].sort(),
    protocols: [...protocols].sort(),
    certificates,
    privateKeys,
    files: [...files].sort(),
  };
}
