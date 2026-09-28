/**
 * Dedicated PARI PARI terminal management.
 *
 * The extension never replaces a shell and never touches the user's existing
 * terminals. It creates at most one extra terminal named "PARI PARI Terminal"
 * and injects a *scoped* PATH entry so the bundled `periperi` CLI resolves only
 * inside that terminal.
 *
 * The CLI is the very same `dist/cli/periperi.js` bundle published to npm. It is
 * never copied to a system directory and never installed globally. Settings are
 * handed over through `PERIPERI_*` environment variables rather than a JSON
 * snapshot, so the CLI reads exactly the same precedence rules as a standalone
 * install.
 */

import * as vscode from 'vscode';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';

import { readSettings, type PariPariSettings } from '../config/configuration';
import { logger } from '../utils/log';
import { CLI_NAME } from '../terminal/commands';
import { EXTENSION_VERSION } from '../version';

const TERMINAL_NAME = 'PARI PARI Terminal';

export interface TerminalManagerOptions {
  /** Extension `context.extensionPath` — used to locate `dist/cli/periperi.js`. */
  extensionPath: string;
  /** `context.globalStorageUri` — writable location for the PATH shim. */
  globalStorageUri: vscode.Uri;
}

export class TerminalManager implements vscode.Disposable {
  private terminal: vscode.Terminal | undefined;
  private readonly options: TerminalManagerOptions;
  private readonly disposables: vscode.Disposable[] = [];

  constructor(options: TerminalManagerOptions) {
    this.options = options;
    this.disposables.push(
      vscode.window.onDidCloseTerminal((terminal) => {
        if (terminal === this.terminal) {
          this.terminal = undefined;
        }
      }),
    );
  }

  /** Path of the bundled CLI. */
  get shimEntry(): string {
    return path.join(this.options.extensionPath, 'dist', 'cli', 'periperi.js');
  }

  /**
   * Create a writable directory containing POSIX and Windows wrappers for the
   * CLI. Settings travel in the environment, so no settings file is written.
   */
  private async prepareShimDir(): Promise<string> {
    const shimDir = vscode.Uri.joinPath(this.options.globalStorageUri, 'periperi-bin').fsPath;
    await fs.mkdir(shimDir, { recursive: true });

    const shim = this.shimEntry;

    // POSIX wrapper (git-bash, WSL, macOS, Linux).
    await fs.writeFile(
      path.join(shimDir, CLI_NAME),
      `#!/bin/sh\nexec "${process.execPath}" "${shim}" "$@"\n`,
      'utf8',
    );
    await fs.chmod(path.join(shimDir, CLI_NAME), 0o755).catch(() => undefined);

    // Windows cmd / PowerShell wrapper.
    await fs.writeFile(
      path.join(shimDir, `${CLI_NAME}.cmd`),
      `@echo off\r\n"${process.execPath}" "${shim}" %*\r\n`,
      'utf8',
    );

    return shimDir;
  }

  private terminalEnv(shimDir: string, settings: PariPariSettings): Record<string, string> {
    const existingPath = process.env.PATH ?? process.env.Path ?? '';
    const sep = path.delimiter;
    const env: Record<string, string> = {
      PATH: `${shimDir}${sep}${existingPath}`,
      PERIPERI_VERSION: EXTENSION_VERSION,
    };

    if (settings.serverUrl) {
      env.PERIPERI_SERVER_URL = settings.serverUrl;
    }
    if (settings.apiKey) {
      env.PERIPERI_API_KEY = settings.apiKey;
    }
    if (settings.projectId) {
      env.PERIPERI_PROJECT_ID = settings.projectId;
    }
    if (settings.scanExclude.length > 0) {
      env.PERIPERI_EXCLUDE = settings.scanExclude.join(',');
    }
    env.PERIPERI_MAX_FILES = String(settings.maxFiles);
    env.PERIPERI_MAX_FILE_SIZE = String(settings.maxFileSize);
    if (!settings.writeResultsToWorkspace) {
      env.PERIPERI_NO_WRITE = '1';
    }

    return env;
  }

  /** Get or create the dedicated terminal. Existing terminals are never modified. */
  async ensureTerminal(options: { cwd?: string } = {}): Promise<vscode.Terminal> {
    const settings = readSettings();
    const shimDir = await this.prepareShimDir();

    if (this.terminal) {
      if (options.cwd) {
        this.terminal.sendText(
          /^win32$/i.test(process.platform) ? `cd /d "${options.cwd}"` : `cd "${options.cwd}"`,
        );
      }
      this.terminal.show();
      return this.terminal;
    }

    const cwd = options.cwd ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    this.terminal = vscode.window.createTerminal({
      name: TERMINAL_NAME,
      cwd,
      env: this.terminalEnv(shimDir, settings),
    });
    this.terminal.show();
    logger.info(`Dedicated PARI PARI terminal created with ${CLI_NAME} on PATH`);
    return this.terminal;
  }

  /** Print informational text into the dedicated terminal (creating it if needed). */
  async write(text: string): Promise<void> {
    const terminal = await this.ensureTerminal();
    for (const line of text.split('\n')) {
      terminal.sendText(line, false);
    }
  }

  /**
   * Print only when the dedicated terminal is already open. Used for scan
   * mirroring so we never pop a terminal the user did not ask for.
   */
  writeIfExists(text: string): boolean {
    if (!this.terminal) {
      return false;
    }
    for (const line of text.split('\n')) {
      this.terminal.sendText(line, false);
    }
    return true;
  }

  /** Run a `periperi …` invocation inside the dedicated terminal. */
  async runCli(commandLine: string): Promise<void> {
    const terminal = await this.ensureTerminal();
    terminal.sendText(`${CLI_NAME} ${commandLine}`);
  }

  isManaged(terminal: vscode.Terminal): boolean {
    return terminal === this.terminal;
  }

  dispose(): void {
    for (const disposable of this.disposables) {
      disposable.dispose();
    }
    this.terminal?.dispose();
    this.terminal = undefined;
  }
}
