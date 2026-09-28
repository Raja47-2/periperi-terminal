import * as vscode from 'vscode';

import type { PariContext } from './context';
import { workspaceRoot } from './context';
import { executeScan } from './executeScan';
import { results } from '../store';
import { exportCbom } from '../cbom/cbomExporter';
import { logger } from '../utils/log';
import { describeError } from '../utils/errors';

/**
 * `PARI PARI: Generate CBOM`.
 *
 * Runs a workspace scan when none exists yet (so the command always produces a
 * CBOM), then writes `.pari-pari/cbom/cbom-<scanId>.json` and `.csv`.
 */
export async function generateCbom(ctx: PariContext): Promise<void> {
  let state = results.get();

  if (!state) {
    const root = workspaceRoot();
    if (!root) {
      void vscode.window.showErrorMessage('PARI PARI: open a folder before generating a CBOM.');
      return;
    }
    const scanned = await executeScan(ctx, {
      root,
      mode: 'workspace',
      label: vscode.workspace.workspaceFolders?.[0]?.name ?? 'workspace',
    });
    if (!scanned) {
      return;
    }
    state = results.get();
    if (!state) {
      return;
    }
  }

  const settings = vscode.workspace.getConfiguration('pariPari');
  const writeToWorkspace = settings.get<boolean>('writeResultsToWorkspace', true);
  const root = workspaceRoot();

  try {
    if (writeToWorkspace && root) {
      const written = await exportCbom({
        cbom: state.cbom,
        scan: state.result,
        workspaceRoot: root,
        formats: { json: true, csv: true },
      });
      const lines = [
        'CBOM generated successfully.',
        written.jsonPath ? `  JSON: ${written.jsonPath}` : undefined,
        written.csvPath ? `  CSV:  ${written.csvPath}` : undefined,
      ].filter(Boolean) as string[];
      ctx.output.appendLine(lines.join('\n'));
      void vscode.window.showInformationMessage(
        `PARI PARI: CBOM generated — ${state.cbom.assets.length} assets.`,
        'Open JSON',
      ).then((choice) => {
        if (choice === 'Open JSON' && written.jsonPath) {
          void vscode.workspace.openTextDocument(written.jsonPath).then((doc) => {
            void vscode.window.showTextDocument(doc);
          });
        }
      });
    } else {
      const choice = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(`cbom-${state.cbom.scan_id}.json`),
        filters: { 'PARI PARI CBOM': ['json'] },
      });
      if (!choice) {
        return;
      }
      const { renderExport } = await import('../cbom/cbomExporter.js');
      await vscode.workspace.fs.writeFile(choice, Buffer.from(renderExport(state.cbom, 'json'), 'utf8'));
      void vscode.window.showInformationMessage('PARI PARI: CBOM exported.');
    }
    logger.info(`CBOM generated for ${state.cbom.scan_id}`);
  } catch (err) {
    const { reason } = describeError(err);
    logger.error(`CBOM generation failed: ${reason}`);
    void vscode.window.showErrorMessage(`PARI PARI: CBOM generation failed — ${reason}`);
  }
}
