import * as vscode from 'vscode';

import type { PariContext } from './context';
import { results } from '../store';

/** `PARI PARI: Show Scan Results` — focuses the results tree view. */
export async function showResults(ctx: PariContext): Promise<void> {
  if (!results.get()) {
    const choice = await vscode.window.showInformationMessage(
      'PARI PARI: no scan results yet.',
      'Scan Workspace',
    );
    if (choice === 'Scan Workspace') {
      await vscode.commands.executeCommand('pariPari.scanWorkspace');
    }
    return;
  }

  ctx.tree.refresh();
  await vscode.commands.executeCommand('pariPari.results.focus');
}
