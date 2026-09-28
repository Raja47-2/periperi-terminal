/**
 * Security dashboard webview.
 *
 * The markup itself lives in `core/reportHtml.ts` and is shared with the
 * standalone report written by `periperi report --html`. This module owns only
 * what the editor can do and the webview cannot: panel lifecycle, the
 * `reveal` message round-trip and opening a file at line:column.
 */

import * as vscode from 'vscode';

import { results, type ScanState } from '../store';
import { BASE_STYLES, renderWebviewHtml } from './webview';
import { renderEmptyReportBody, renderReportBody } from '../core/reportHtml';

export class DashboardPanel {
  static current: DashboardPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private readonly disposables: vscode.Disposable[] = [];

  static show(): DashboardPanel {
    if (DashboardPanel.current) {
      DashboardPanel.current.panel.reveal(vscode.ViewColumn.Beside);
      DashboardPanel.current.render();
      return DashboardPanel.current;
    }
    const panel = vscode.window.createWebviewPanel(
      'pariPariDashboard',
      'PARI PARI — Security Dashboard',
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true },
    );
    DashboardPanel.current = new DashboardPanel(panel);
    DashboardPanel.current.render();
    return DashboardPanel.current;
  }

  private constructor(panel: vscode.WebviewPanel) {
    this.panel = panel;
    this.disposables.push(
      this.panel.onDidDispose(() => this.dispose()),
      results.subscribe(() => this.render()),
      this.panel.webview.onDidReceiveMessage(
        (message: { command?: string; file?: string; line?: number; column?: number }) => {
          if (message.command === 'reveal' && message.file) {
            void revealLocation(message.file, message.line ?? 1, message.column ?? 1);
          } else if (message.command === 'refresh') {
            this.render();
          }
        },
      ),
    );
  }

  private render(): void {
    const state: ScanState | undefined = results.get();
    this.panel.webview.html = renderWebviewHtml({
      title: 'PARI PARI — Security Dashboard',
      styles: BASE_STYLES,
      body: state
        ? renderReportBody(state, { interactive: true, refresh: true })
        : `${renderEmptyReportBody()}<div class="actions"><button id="refresh">Refresh</button></div>`,
      script: `
        const vscode = acquireVsCodeApi();
        document.addEventListener('click', (event) => {
          const el = event.target.closest('[data-file]');
          if (!el) { return; }
          vscode.postMessage({
            command: 'reveal',
            file: el.getAttribute('data-file'),
            line: Number(el.getAttribute('data-line') || 1),
            column: Number(el.getAttribute('data-column') || 1)
          });
        });
        const refresh = document.getElementById('refresh');
        if (refresh) { refresh.addEventListener('click', () => vscode.postMessage({ command: 'refresh' })); }
      `,
    });
  }

  private dispose(): void {
    for (const d of this.disposables) {
      d.dispose();
    }
    this.panel.dispose();
    DashboardPanel.current = undefined;
  }
}

/** Open `file` at `line:column` in the active editor group. */
export async function revealLocation(
  file: string,
  line: number,
  column: number,
): Promise<void> {
  const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  const candidate =
    root && !file.startsWith('/') && !/^[a-zA-Z]:[\\/]/.test(file)
      ? vscode.Uri.joinPath(vscode.Uri.file(root), file)
      : vscode.Uri.file(file);

  try {
    const doc = await vscode.workspace.openTextDocument(candidate);
    const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.Active);
    const position = new vscode.Position(
      Math.max(0, Math.min(line - 1, doc.lineCount - 1)),
      Math.max(0, column - 1),
    );
    editor.selection = new vscode.Selection(position, position);
    editor.revealRange(
      new vscode.Range(position, position),
      vscode.TextEditorRevealType.InCenter,
    );
  } catch (err) {
    const reason = err instanceof Error ? err.message : 'Unknown error';
    void vscode.window.showWarningMessage(`PARI PARI could not open ${file}: ${reason}`);
  }
}
