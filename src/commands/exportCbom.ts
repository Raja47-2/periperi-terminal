import * as vscode from 'vscode';

import type { PariContext } from './context';
import { workspaceRoot } from './context';
import { executeScan } from './executeScan';
import { results } from '../store';
import { exportCbom, renderExport } from '../cbom/cbomExporter';
import { logger } from '../utils/log';
import { describeError } from '../utils/errors';

type Format = 'json' | 'csv' | 'both';

async function pickFormat(): Promise<Format | undefined> {
  const choice = await vscode.window.showQuickPick(
    [
      { label: 'JSON', description: 'Full CBOM document', format: 'json' as const },
      { label: 'CSV', description: 'Flat asset table for spreadsheets', format: 'csv' as const },
      { label: 'Both', description: 'Write JSON and CSV', format: 'both' as const },
    ],
    { placeHolder: 'Select the export format' },
  );
  return choice?.format;
}

/** `PARI PARI: Export CBOM` — JSON and/or CSV, workspace or Save dialog. */
export async function exportCbomCommand(ctx: PariContext): Promise<void> {
  let state = results.get();
  if (!state) {
    const root = workspaceRoot();
    if (!root) {
      void vscode.window.showErrorMessage('PARI PARI: open a folder before exporting a CBOM.');
      return;
    }
    const scanned = await executeScan(ctx, { root, mode: 'workspace', label: 'workspace' });
    if (!scanned) {
      return;
    }
    state = results.get();
    if (!state) {
      return;
    }
  }

  const format = await pickFormat();
  if (!format) {
    return;
  }

  const root = workspaceRoot();
  const writeInside = vscode.workspace
    .getConfiguration('pariPari')
    .get<boolean>('writeResultsToWorkspace', true);

  try {
    if (root && writeInside) {
      const formats = { json: format !== 'csv', csv: format !== 'json' };
      const written = await exportCbom({
        cbom: state.cbom,
        scan: state.result,
        workspaceRoot: root,
        formats,
      });
      const target = written.jsonPath ?? written.csvPath;
      const choice = await vscode.window.showInformationMessage(
        `PARI PARI: CBOM exported to ${target ?? 'workspace'}`,
        'Open',
      );
      if (choice === 'Open' && target) {
        const doc = await vscode.workspace.openTextDocument(target);
        await vscode.window.showTextDocument(doc);
      }
      return;
    }

    // Fallback: explicit save dialog (also used when workspace writes are off).
    // A dialog can only name one file, so "both" falls back to the JSON document.
    const single: Format = format === 'csv' ? 'csv' : 'json';
    const uri = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(`cbom-${state.cbom.scan_id}.${single}`),
      filters:
        single === 'json'
          ? { 'PARI PARI CBOM': ['json'] }
          : { 'PARI PARI CBOM': ['csv'] },
    });
    if (!uri) {
      return;
    }
    await vscode.workspace.fs.writeFile(uri, Buffer.from(renderExport(state.cbom, single), 'utf8'));
    void vscode.window.showInformationMessage(`PARI PARI: CBOM exported to ${uri.fsPath}`);
    logger.info(`CBOM exported (${single})`);
  } catch (err) {
    const { reason } = describeError(err);
    logger.error(`CBOM export failed: ${reason}`);
    void vscode.window.showErrorMessage(`PARI PARI: export failed — ${reason}`);
  }
}
