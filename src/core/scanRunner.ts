/**
 * Shared scan execution.
 *
 * Extracted from the VS Code command layer so the CLI and the extension run the
 * exact same pipeline: run the scan, store the state, persist locally, build the
 * human-readable report.
 *
 * Deliberately free of any `vscode` import: progress, cancellation and output are
 * injected by the caller.
 */

import { rollupAssets, runScan, summarizeRisk, type AssetRollup, type RiskSummary } from '../scanner/scanner';
import type { CancellationLike, ScanProgress, ScanRequest, ScanResult } from '../scanner/types';
import { results, type ScanState } from '../store';
import { exportCbom, writeScan } from '../cbom/cbomExporter';
import { renderFooter, renderSummary } from '../terminal/output';
import { describeError } from '../utils/errors';
import { logger } from '../utils/log';
import type { PariPariSettings } from './config';

/** Merge resolved settings into a scan request. Settings always win over request defaults. */
export function applySettings(request: ScanRequest, settings: PariPariSettings): ScanRequest {
  return {
    ...request,
    exclude: settings.scanExclude,
    maxFileSize: settings.maxFileSize,
    maxFiles: settings.maxFiles,
  };
}

export interface ScanRunOptions {
  settings: PariPariSettings;
  /** Called for every real stage transition reported by the engine. */
  onProgress?: (progress: ScanProgress) => void;
  token?: CancellationLike;
  /**
   * Where the scan and its CBOM are written. Persistence is skipped when this is
   * omitted or when `settings.writeResultsToWorkspace` is false.
   */
  persistRoot?: string;
  /** Project name recorded in the CBOM. Defaults to the request label. */
  project?: string;
  /** Receives a human-readable reason when persistence fails. Never throws. */
  onPersistError?: (reason: string) => void;
}

export interface ScanRunOutcome {
  result: ScanResult;
  state: ScanState;
  risk: RiskSummary;
  rollup: AssetRollup;
  /** Formatted summary plus disclaimer, ready to print. */
  report: string;
  /** Paths written during persistence, when enabled. */
  written: { scanPath?: string; jsonPath?: string; csvPath?: string };
}

/**
 * Execute a scan end to end and return everything a front-end needs to render.
 * Does not throw for persistence problems — a failed write must not lose a
 * successful scan.
 */
export async function runScanToState(
  request: ScanRequest,
  options: ScanRunOptions,
): Promise<ScanRunOutcome> {
  const { settings } = options;
  const project = options.project ?? request.label ?? request.root;

  const result = await runScan(applySettings(request, settings), {
    onProgress: options.onProgress,
    token: options.token,
  });

  const state = results.set(result, { project });
  const written: ScanRunOutcome['written'] = {};

  const persistRoot = options.persistRoot;
  if (persistRoot && settings.writeResultsToWorkspace) {
    try {
      const scanPath = await writeScan(result, persistRoot);
      const exported = await exportCbom({
        cbom: state.cbom,
        scan: result,
        workspaceRoot: persistRoot,
        formats: { json: true, csv: true },
      });
      written.scanPath = scanPath;
      written.jsonPath = exported.jsonPath;
      written.csvPath = exported.csvPath;
    } catch (err) {
      const { reason } = describeError(err);
      logger.warn(`Could not persist results: ${reason}`);
      options.onPersistError?.(reason);
    }
  }

  const risk = summarizeRisk(result.detections);
  const rollup = rollupAssets(result);
  const report = `${renderSummary(result, risk, rollup)}\n${renderFooter()}`;

  return { result, state, risk, rollup, report, written };
}

/** Ensure a scan exists, running `scan` when the store is still empty. */
export async function ensureScan(
  run: () => Promise<ScanRunOutcome>,
): Promise<ScanRunOutcome | undefined> {
  const existing = results.get();
  if (existing) {
    const risk = summarizeRisk(existing.result.detections);
    const rollup = rollupAssets(existing.result);
    return {
      result: existing.result,
      state: existing,
      risk,
      rollup,
      report: `${renderSummary(existing.result, risk, rollup)}\n${renderFooter()}`,
      written: {},
    };
  }
  return run();
}
