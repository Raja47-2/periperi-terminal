import * as vscode from 'vscode';
import * as path from 'node:path';

import type { PariContext } from './context';
import { workspaceRoot } from './context';
import { executeScan } from './executeScan';

function folderFromEditor(): vscode.Uri | undefined {
  const editor = vscode.window.activeTextEditor;
  if (editor?.document.uri.scheme === 'file') {
    return vscode.Uri.file(path.dirname(editor.document.uri.fsPath));
  }
  return undefined;
}

/**
 * `PARI PARI: Scan Current Folder`.
 *
 * Order of preference: Explorer selection → active editor's folder → first
 * workspace folder.
 */
export async function scanFolder(ctx: PariContext, resource?: vscode.Uri): Promise<void> {
  const root = workspaceRoot();

  let folderUri: vscode.Uri | undefined;
  if (resource && resource.scheme === 'file') {
    folderUri = resource;
  } else {
    folderUri = folderFromEditor();
    if (!folderUri) {
      const first = vscode.workspace.workspaceFolders?.[0];
      if (first) {
        folderUri = first.uri;
      }
    }
  }

  if (!folderUri) {
    void vscode.window.showWarningMessage(
      'PARI PARI: open a folder or a file inside a folder before scanning.',
    );
    ctx.output.appendLine('[WARN] Scan Current Folder: no folder resolved.');
    return;
  }

  if (!root) {
    void vscode.window.showWarningMessage(
      'PARI PARI: no workspace folder open — using the selected folder as root.',
    );
  }

  await executeScan(
    ctx,
    {
      root: root ?? folderUri.fsPath,
      mode: 'folder',
      targets: [folderUri.fsPath],
      label: root ? path.relative(root, folderUri.fsPath) || path.basename(folderUri.fsPath) : path.basename(folderUri.fsPath),
    },
    { mirrorToTerminal: false },
  );
}
