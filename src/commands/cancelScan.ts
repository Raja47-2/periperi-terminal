import * as vscode from 'vscode';

import type { PariContext } from './context';
import { cancelActiveScan, isScanRunning } from './executeScan';

/** `PARI PARI: Cancel Scan` — cancels the scan currently in flight. */
export async function cancelScan(ctx: PariContext): Promise<void> {
  if (!isScanRunning()) {
    void vscode.window.setStatusBarMessage('PARI PARI: no scan is currently running.', 3000);
    ctx.output.appendLine('[INFO] Cancel requested but no scan is running.');
    return;
  }
  if (cancelActiveScan()) {
    void vscode.window.setStatusBarMessage('PARI PARI: cancelling scan…', 3000);
    ctx.output.appendLine('[INFO] Scan cancellation requested.');
  }
}
