import * as vscode from 'vscode';

import type { PariContext } from './context';
import { workspaceRoot } from './context';
import { results } from '../store';
import { summarizeRisk } from '../scanner/scanner';
import { renderStatus } from '../terminal/output';
import { readSettings } from '../config/configuration';
import { EXTENSION_VERSION } from '../version';

/** `PARI PARI: Check Status` — local/backend/status-bar overview. */
export async function status(ctx: PariContext): Promise<void> {
  const settings = readSettings();
  const state = results.get();

  const text = renderStatus({
    surface: 'extension',
    workspaceRoot: workspaceRoot(),
    lastScan: state?.result,
    risk: state ? summarizeRisk(state.result.detections) : undefined,
    settings: {
      serverUrl: settings.serverUrl,
      projectId: settings.projectId,
      enableTelemetry: settings.enableTelemetry,
      writeResultsToWorkspace: settings.writeResultsToWorkspace,
    },
    version: EXTENSION_VERSION,
  });

  ctx.output.appendLine('');
  ctx.output.appendLine(text);

  const backend = ctx.service.isConfigured() ? 'configured' : 'not configured (local only)';
  const headline = state
    ? `PARI PARI v${EXTENSION_VERSION} — ${state.result.stats.filesScanned} files, ${state.result.detections.length} assets · backend ${backend}`
    : `PARI PARI v${EXTENSION_VERSION} — no scan yet · backend ${backend}`;

  const choice = await vscode.window.showInformationMessage(headline, 'Show Full Status');
  if (choice === 'Show Full Status') {
    ctx.output.show(true);
  }
}
