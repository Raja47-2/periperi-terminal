import * as vscode from 'vscode';

import { TerminalManager } from '../terminal/terminalManager';
import { ResultsTreeProvider } from '../ui/resultsPanel';
import { PariPariService } from '../services/pariPariService';

/** Shared services handed to every command handler. */
export interface PariContext {
  output: vscode.OutputChannel;
  terminal: TerminalManager;
  tree: ResultsTreeProvider;
  service: PariPariService;
  /** Extension `storageUri` (already created). */
  storageUri: vscode.Uri;
}

export function workspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

export function requireWorkspace(): string {
  const root = workspaceRoot();
  if (!root) {
    throw new Error('NO_WORKSPACE');
  }
  return root;
}
