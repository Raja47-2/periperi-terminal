import * as vscode from 'vscode';

import type { PariContext } from './context';
import { results } from '../store';

/** `PARI PARI: Show Security Dashboard` — opens the webview dashboard. */
export async function showDashboard(ctx: PariContext): Promise<void> {
  if (!results.get()) {
    const choice = await vscode.window.showInformationMessage(
      'PARI PARI: no scan results yet. Run a scan first?',
      'Scan Workspace',
      'Open Results',
    );
    if (choice === 'Scan Workspace') {
      await vscode.commands.executeCommand('pariPari.scanWorkspace');
      if (!results.get()) {
        return;
      }
    } else if (choice === 'Open Results') {
      await vscode.commands.executeCommand('pariPari.showResults');
      return;
    } else {
      return;
    }
  }

  const { DashboardPanel } = await import('../ui/dashboard.js');
  DashboardPanel.show();
  ctx.output.appendLine('[INFO] Security dashboard opened');
}
