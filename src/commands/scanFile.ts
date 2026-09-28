import * as vscode from 'vscode';
import * as path from 'node:path';

import type { PariContext } from './context';
import { workspaceRoot } from './context';
import { executeScan } from './executeScan';

function activeFileUri(): vscode.Uri | undefined {
  const editor = vscode.window.activeTextEditor;
  if (editor?.document.uri.scheme === 'file') {
    return editor.document.uri;
  }
  return undefined;
}

function describeUnsupported(uri: vscode.Uri): string {
  const isUntitled = uri.scheme === 'untitled';
  if (isUntitled) {
    return 'Save the file before scanning it.';
  }
  if (uri.scheme !== 'file') {
    return 'Only local files on disk can be scanned.';
  }
  return 'That resource cannot be scanned by PARI PARI.';
}

/**
 * `PARI PARI: Scan Current File`.
 *
 * When invoked from the File Explorer context menu VS Code passes the selected
 * resource as `resource`; otherwise the active editor is used.
 */
export async function scanFile(ctx: PariContext, resource?: vscode.Uri): Promise<void> {
  const uri = resource ?? activeFileUri();

  if (!uri) {
    void vscode.window.showWarningMessage(
      'PARI PARI: open a file in the editor (or right-click a file) before scanning.',
    );
    ctx.output.appendLine('[WARN] Scan Current File: no file selected.');
    return;
  }

  if (uri.scheme !== 'file') {
    void vscode.window.showWarningMessage(`PARI PARI: ${describeUnsupported(uri)}`);
    return;
  }

  const root = workspaceRoot();
  if (!root) {
    void vscode.window.showWarningMessage(
      'PARI PARI: open a folder to give the scan a workspace root. Scanning the file anyway.',
    );
  }

  await executeScan(
    ctx,
    {
      root: root ?? path.dirname(uri.fsPath),
      mode: 'file',
      targets: [uri.fsPath],
      label: vscode.workspace.asRelativePath(uri),
    },
    { mirrorToTerminal: false },
  );
}
