/**
 * PARI PARI Terminal — extension entry point.
 *
 * Phase 1: local-first scanning, command palette, dedicated terminal, results
 * tree, dashboard, CBOM generation/export, status bar and settings.
 */

import * as vscode from 'vscode';

import { logger } from './utils/log';
import { results } from './store';
import { readSettings } from './config/configuration';
import { TerminalManager } from './terminal/terminalManager';
import { ResultsTreeProvider, REVEAL_COMMAND } from './ui/resultsPanel';
import { createStatusBarItem, disposeStatusBar } from './ui/statusBar';
import { PariPariService } from './services/pariPariService';
import { CLI_NAME } from './terminal/commands';
import { EXTENSION_VERSION } from './version';
import type { PariContext } from './commands/context';

import { scanWorkspace } from './commands/scanWorkspace';
import { scanFile } from './commands/scanFile';
import { scanFolder } from './commands/scanFolder';
import { generateCbom } from './commands/generateCbom';
import { showResults } from './commands/showResults';
import { showDashboard } from './commands/showDashboard';
import { exportCbomCommand } from './commands/exportCbom';
import { clearResults } from './commands/clearResults';
import { status } from './commands/status';
import { cancelScan } from './commands/cancelScan';
import { connectEcdat, syncScan } from './commands/connectEcdat';
import { openTerminal, revealAsset } from './commands/revealAsset';

let context: PariContext | undefined;
let terminalManager: TerminalManager | undefined;
let treeProvider: ResultsTreeProvider | undefined;
let service: PariPariService | undefined;

export function activate(extensionContext: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel('PARI PARI');
  logger.addSink((line) => output.appendLine(line));
  logger.info(`Extension activated — PARI PARI Terminal v${EXTENSION_VERSION}`);
  logger.info(`Bundled CLI: ${CLI_NAME} (dist/cli/periperi.js)`);
  logger.info(`Extension path: ${extensionContext.extensionPath}`);

  const settings = readSettings();
  logger.info(
    `Settings loaded: exclude=${settings.scanExclude.join(',')} maxFileSize=${settings.maxFileSize} telemetry=${settings.enableTelemetry ? 'on' : 'off'}`,
  );

  // Writable storage for the scoped CLI shim + settings snapshot.
  void extensionContext.globalStorageUri;

  terminalManager = new TerminalManager({
    extensionPath: extensionContext.extensionPath,
    globalStorageUri: extensionContext.globalStorageUri,
  });
  treeProvider = new ResultsTreeProvider();
  // `secretStorage` is a proposed API and is absent from @types/vscode 1.90.
  const secretStorage = (
    extensionContext as unknown as { secretStorage?: vscode.SecretStorage }
  ).secretStorage;
  service = new PariPariService({ secretStorage });

  context = {
    output,
    terminal: terminalManager,
    tree: treeProvider,
    service,
    storageUri: extensionContext.globalStorageUri,
  };

  extensionContext.subscriptions.push(
    output,
    terminalManager,
    treeProvider,
    service,
    createStatusBarItem(),
    vscode.window.registerTreeDataProvider('pariPari.results', treeProvider),
    results.subscribe(() => {
      treeProvider?.refresh();
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('pariPari')) {
        logger.info('Configuration changed');
      }
    }),
  );

  const register = (id: string, handler: (...args: never[]) => unknown): void => {
    extensionContext.subscriptions.push(
      vscode.commands.registerCommand(id, async (...args: unknown[]) => {
        try {
          await handler(...(args as never[]));
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          logger.error(`Command ${id} failed: ${message}`);
          void vscode.window.showErrorMessage(`PARI PARI: ${message}`);
        }
      }),
    );
  };

  register('pariPari.scanWorkspace', () => scanWorkspace(context as PariContext));
  register('pariPari.scanFile', (resource?: vscode.Uri) =>
    scanFile(context as PariContext, resource),
  );
  register('pariPari.scanFolder', (resource?: vscode.Uri) =>
    scanFolder(context as PariContext, resource),
  );
  register('pariPari.generateCbom', () => generateCbom(context as PariContext));
  register('pariPari.showResults', () => showResults(context as PariContext));
  register('pariPari.showDashboard', () => showDashboard(context as PariContext));
  register('pariPari.exportCbom', () => exportCbomCommand(context as PariContext));
  register('pariPari.clearResults', () => clearResults(context as PariContext));
  register('pariPari.status', () => status(context as PariContext));
  register('pariPari.cancelScan', () => cancelScan(context as PariContext));
  register('pariPari.connectEcdat', () => connectEcdat(context as PariContext));
  register('pariPari.syncScan', () => syncScan(context as PariContext));
  register('pariPari.openTerminal', () => openTerminal(context as PariContext));
  register(
    REVEAL_COMMAND,
    async (file?: string, line?: number, column?: number) =>
      revealAsset(file, line, column),
  );

  const folder = vscode.workspace.workspaceFolders?.[0];
  if (folder) {
    logger.info(`Workspace detected: ${folder.name}`);
  } else {
    logger.info('No workspace folder open');
  }

  output.appendLine(`PARI PARI Terminal v${EXTENSION_VERSION} ready.`);
  output.appendLine(
    `Run "PARI PARI: Scan Workspace", or open the PARI PARI terminal and type \`${CLI_NAME} help\`.`,
  );
}

export function deactivate(): void {
  logger.info('Extension deactivating');
  disposeStatusBar();
  context = undefined;
  terminalManager = undefined;
  treeProvider = undefined;
  service = undefined;
}
