import * as vscode from 'vscode';

import type { PariContext } from './context';
import { requireWorkspace } from './context';
import { executeScan } from './executeScan';

/** `PARI PARI: Scan Workspace` — scans the first open workspace folder. */
export async function scanWorkspace(ctx: PariContext): Promise<void> {
  let root: string;
  try {
    root = requireWorkspace();
  } catch {
    void vscode.window.showErrorMessage('PARI PARI: open a folder before running a workspace scan.');
    ctx.output.appendLine('[ERROR] Workspace scan requested with no folder open.');
    return;
  }

  await executeScan(
    ctx,
    {
      root,
      mode: 'workspace',
      label: vscode.workspace.workspaceFolders?.[0]?.name ?? 'workspace',
    },
    { mirrorToTerminal: false },
  );
}
