import * as vscode from 'vscode';

import type { PariContext } from './context';
import { workspaceRoot } from './context';
import { results } from '../store';
import { storageLayout } from '../cbom/cbomExporter';
import { resetStatusBar } from '../ui/statusBar';
import { logger } from '../utils/log';

/** `PARI PARI: Clear Scan Results` — clears memory and optional workspace files. */
export async function clearResults(ctx: PariContext): Promise<void> {
  const hadResults = results.get() !== undefined;
  results.clear();
  resetStatusBar();
  ctx.tree.refresh();

  const root = workspaceRoot();
  const writeInside = vscode.workspace
    .getConfiguration('pariPari')
    .get<boolean>('writeResultsToWorkspace', true);

  let removed = 0;
  if (root && writeInside) {
    const layout = storageLayout(root);
    for (const dir of [layout.scans, layout.cbom, layout.reports]) {
      const dirUri = vscode.Uri.file(dir);
      try {
        const entries = await vscode.workspace.fs.readDirectory(dirUri);
        for (const [name, type] of entries) {
          if (type === vscode.FileType.File) {
            await vscode.workspace.fs.delete(vscode.Uri.joinPath(dirUri, name));
            removed += 1;
          }
        }
      } catch {
        // Directory does not exist yet — nothing to clear.
      }
    }
  }

  ctx.output.appendLine(
    `[INFO] Results cleared (in-memory=${hadResults ? 'yes' : 'no'}, files removed=${removed})`,
  );
  logger.info(`Results cleared: removed=${removed}`);

  const choice = await vscode.window.showInformationMessage(
    removed > 0
      ? `PARI PARI: cleared in-memory results and ${removed} stored file(s).`
      : 'PARI PARI: cleared in-memory results.',
  );
  void choice;
}
