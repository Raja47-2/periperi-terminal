import * as vscode from 'vscode';

import type { PariContext } from './context';
import { results } from '../store';

/** `PARI PARI: Connect to ECDAT` — optional backend handshake. */
export async function connectEcdat(ctx: PariContext): Promise<void> {
  if (!ctx.service.isConfigured()) {
    const choice = await vscode.window.showInformationMessage(
      'PARI PARI: no ECDAT server configured. The extension runs fully local by default.',
      'Open Settings',
    );
    if (choice === 'Open Settings') {
      await vscode.commands.executeCommand(
        'workbench.action.openSettings',
        'pariPari.serverUrl',
      );
    }
    return;
  }

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'PARI PARI: connecting to ECDAT…' },
    async () => {
      const result = await ctx.service.connect();
      if (result.ok) {
        void vscode.window.showInformationMessage('PARI PARI: ECDAT server reachable.');
        ctx.output.appendLine('[INFO] ECDAT health check succeeded.');
      } else {
        void vscode.window
          .showErrorMessage(`PARI PARI: could not reach ECDAT — ${result.reason}`, 'Show Output')
          .then((choice) => {
            if (choice === 'Show Output') {
              ctx.output.show(true);
            }
          });
        ctx.output.appendLine(`[WARN] ECDAT health check failed: ${result.reason}`);
      }
    },
  );
}

/** `PARI PARI: Sync Scan` — explicit, user-confirmed upload of the latest CBOM. */
export async function syncScan(ctx: PariContext): Promise<void> {
  const state = results.get();
  if (!state) {
    void vscode.window.showWarningMessage('PARI PARI: run a scan before synchronising.');
    return;
  }

  if (!ctx.service.isConfigured()) {
    void vscode.window.showErrorMessage(
      'PARI PARI: set pariPari.serverUrl before syncing. Nothing has been uploaded.',
    );
    return;
  }

  const confirm = async (): Promise<boolean> => {
    const choice = await vscode.window.showWarningMessage(
      `Upload CBOM ${state.cbom.scan_id} (${state.cbom.assets.length} asset records, file paths and line numbers) to ${ctx.service.serverUrl}? Source code is never uploaded.`,
      { modal: true },
      'Upload',
    );
    return choice === 'Upload';
  };

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'PARI PARI: syncing CBOM…' },
    async () => {
      const result = await ctx.service.syncScan(state.cbom, confirm);
      if (result.ok) {
        void vscode.window.showInformationMessage(
          `PARI PARI: CBOM synchronised${result.remoteId ? ` (${result.remoteId})` : ''}.`,
        );
        ctx.output.appendLine(`[INFO] CBOM synced: ${state.cbom.scan_id}`);
      } else {
        void vscode.window.showWarningMessage(`PARI PARI: sync not completed — ${result.reason}`);
        ctx.output.appendLine(`[INFO] Sync skipped: ${result.reason}`);
      }
    },
  );
}
