/**
 * VS Code scan execution: progress notification, cancellation, status bar and
 * terminal mirroring.
 *
 * The pipeline itself lives in `core/scanRunner.ts` so the CLI runs byte-for-byte
 * the same scan, store and persistence steps. Progress is driven by real stage
 * transitions from the scanner engine — the extension never reports progress
 * that did not happen.
 */

import * as vscode from 'vscode';

import type { ScanProgress, ScanRequest, ScanResult } from '../scanner/types';
import { renderFooter, renderProgress, renderScope, renderSummary } from '../terminal/output';
import { logger } from '../utils/log';
import { describeError, UserFacingError } from '../utils/errors';
import { readSettings } from '../config/configuration';
import { workspaceRoot, type PariContext } from './context';
import { runScanToState } from '../core/scanRunner';
import { updateStatusBar } from '../ui/statusBar';

export interface RunScanOptions {
  /** Also print the formatted report into the dedicated PARI PARI terminal. */
  mirrorToTerminal?: boolean;
  /** Open the dashboard when the scan completes (honours settings). */
  openDashboard?: boolean;
}

/** Handle for the scan currently in flight, if any. */
let activeScan: (() => void) | undefined;

export function cancelActiveScan(): boolean {
  if (!activeScan) {
    return false;
  }
  activeScan();
  logger.info('Scan cancellation requested by user');
  return true;
}

export function isScanRunning(): boolean {
  return activeScan !== undefined;
}

/** Adapts a VS Code cancellation token to the engine's token contract. */
function cancellationFrom(token: vscode.CancellationToken): {
  isCancellationRequested: boolean;
} {
  return {
    get isCancellationRequested(): boolean {
      return token.isCancellationRequested;
    },
  };
}

export async function executeScan(
  ctx: PariContext,
  request: ScanRequest,
  options: RunScanOptions = {},
): Promise<ScanResult | undefined> {
  const settings = readSettings();
  const root = request.root;
  const label = request.label ?? root;

  ctx.output.appendLine('');
  ctx.output.appendLine(renderScope(request.mode, label));
  logger.info(`Scan requested: mode=${request.mode} target=${label}`);

  let lastStage = '';
  const onProgress = (progress: ScanProgress): string => {
    const key = `${progress.stage}:${progress.step}`;
    const line = renderProgress(progress);
    // The output channel gets one line per stage; per-file progress goes to the
    // notification instead so the log stays readable.
    if (key !== lastStage) {
      lastStage = key;
      ctx.output.appendLine(line);
    }
    return line;
  };

  try {
    const outcome = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `PARI PARI: scanning ${label}`,
        cancellable: true,
      },
      async (progress, token) => {
        const source = new vscode.CancellationTokenSource();
        const bridge = token.onCancellationRequested(() => source.cancel());
        activeScan = () => source.cancel();
        try {
          return await runScanToState(
            request,
            {
              settings,
              token: cancellationFrom(source.token),
              persistRoot: workspaceRoot(),
              project: label,
              onPersistError: (reason) => ctx.output.appendLine(`[WARN] Could not persist results: ${reason}`),
              onProgress: (p) => {
                const line = onProgress(p);
                const suffix =
                  typeof p.filesTotal === 'number' && p.filesTotal > 0
                    ? ` (${p.filesProcessed ?? 0}/${p.filesTotal})`
                    : '';
                progress.report({ message: `${line}${suffix}` });
              },
            },
          );
        } finally {
          activeScan = undefined;
          bridge.dispose();
          source.dispose();
        }
      },
    );

    const { result, risk } = outcome;
    const report = renderSummary(result, risk, outcome.rollup);
    ctx.output.appendLine(report);
    ctx.output.appendLine(renderFooter());
    logger.info(
      `Scan completed: assets=${risk.total} high=${risk.high} medium=${risk.medium} low=${risk.low}`,
    );

    updateStatusBar(risk.total, result.cancelled);
    ctx.tree.refresh();

    if (options.mirrorToTerminal ?? true) {
      // Only mirror when the user already has the PARI PARI terminal open —
      // never force a terminal to appear as a side effect of scanning.
      ctx.terminal.writeIfExists(`${report}\n${renderFooter()}`);
    }

    if (options.openDashboard ?? settings.openDashboardAfterScan) {
      const { DashboardPanel } = await import('../ui/dashboard.js');
      DashboardPanel.show();
    }

    if (result.cancelled) {
      void vscode.window.showWarningMessage(
        'PARI PARI: scan cancelled. The results shown are partial.',
      );
    } else if (result.errors.length > 0) {
      void vscode.window.setStatusBarMessage(
        `PARI PARI: ${risk.total} assets — ${result.errors.length} file(s) skipped (see Output)`,
        8000,
      );
    } else {
      void vscode.window.setStatusBarMessage(
        `PARI PARI: ${risk.total} cryptographic assets detected`,
        5000,
      );
    }

    return result;
  } catch (err) {
    if (err instanceof UserFacingError) {
      void vscode.window.showErrorMessage(`PARI PARI: ${err.message}`, err.detail ?? '');
      ctx.output.appendLine(`[ERROR] ${err.message}${err.detail ? ` — ${err.detail}` : ''}`);
      return undefined;
    }
    const { reason, code } = describeError(err);
    logger.error(`Scan failed: ${reason}${code ? ` (${code})` : ''}`);
    ctx.output.appendLine(`[ERROR] Scan failed: ${reason}`);
    void vscode.window
      .showErrorMessage(`PARI PARI Scan Failed — ${reason}`, 'Show Output')
      .then((choice) => {
        if (choice === 'Show Output') {
          ctx.output.show(true);
        }
      });
    return undefined;
  }
}
