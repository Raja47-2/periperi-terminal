/**
 * Minimal stand-in for the `vscode` module.
 *
 * The scanner, CBOM and report layers are deliberately free of editor
 * dependencies so they can run in the CLI and in tests. Only the thin
 * presentation adapters touch `vscode`, so this stub covers just the surface
 * those adapters use. If a test needs behaviour that is not modelled here it
 * should be a sign that too much logic lives behind the editor API.
 */

export interface Disposable {
  dispose(): void;
}

export interface Event<T> {
  (listener: (value: T) => void): Disposable;
}

export interface Uri {
  readonly scheme: string;
  readonly fsPath: string;
  readonly path: string;
  toString(): string;
}

function makeUri(scheme: string, fsPath: string): Uri {
  return {
    scheme,
    fsPath,
    get path(): string {
      return fsPath.replace(/\\/g, '/');
    },
    toString(): string {
      return `${scheme}://${fsPath.replace(/\\/g, '/')}`;
    },
  };
}

/** Mirrors the static surface of `vscode.Uri` that the adapters use. */
export const Uri = {
  file(fsPath: string): Uri {
    return makeUri('file', fsPath);
  },
  parse(value: string): Uri {
    const match = /^([a-z][a-z0-9+.-]*):\/\/?(.*)$/i.exec(value);
    return match ? makeUri(match[1], match[2] ?? '') : makeUri('file', value);
  },
};

export interface Disposable {
  dispose(): void;
}

function noopDisposable(): Disposable {
  return { dispose: () => undefined };
}

export const Disposable = {
  from(...items: Disposable[]): Disposable {
    return {
      dispose: () => {
        for (const item of items) {
          item.dispose();
        }
      },
    };
  },
  [Symbol.dispose]: noopDisposable,
};

function createEvent<T>(): Event<T> {
  return () => noopDisposable();
}

export interface OutputChannel {
  readonly name: string;
  append(value: string): void;
  appendLine(value: string): void;
  clear(): void;
  show(preserveFocus?: boolean): void;
  hide(): void;
  dispose(): void;
}

function createOutputChannel(name: string): OutputChannel {
  return {
    name,
    append: () => undefined,
    appendLine: () => undefined,
    clear: () => undefined,
    show: () => undefined,
    hide: () => undefined,
    dispose: () => undefined,
  };
}

export interface Webview {
  html: string;
  options: Record<string, unknown>;
  onDidReceiveMessage: Event<unknown>;
  postMessage(message: unknown): Promise<boolean>;
}

export interface WebviewPanel {
  readonly viewType: string;
  title: string;
  webview: Webview;
  reveal(viewColumn?: number, preserveFocus?: boolean): void;
  onDidDispose: Event<void>;
  onDidChangeViewState: Event<unknown>;
  dispose(): void;
}

export const window = {
  activeTextEditor: undefined as unknown as undefined,
  visibleTextEditors: [] as unknown[],
  createOutputChannel: createOutputChannel,
  showInformationMessage: async (): Promise<string | undefined> => undefined,
  showWarningMessage: async (): Promise<string | undefined> => undefined,
  showErrorMessage: async (): Promise<string | undefined> => undefined,
  showQuickPick: async (): Promise<unknown> => undefined,
  showOpenDialog: async (): Promise<unknown> => undefined,
  showSaveDialog: async (): Promise<Uri | undefined> => undefined,
  createWebviewPanel: (
    viewType: string,
    title: string,
    _column: number,
    _options?: Record<string, unknown>,
  ): WebviewPanel => {
    const onDidReceiveMessage = createEvent<unknown>();
    const onDidDispose = createEvent<void>();
    const onDidChangeViewState = createEvent<unknown>();
    return {
      viewType,
      title,
      webview: {
        html: '',
        options: {},
        onDidReceiveMessage,
        postMessage: async () => true,
      },
      reveal: () => undefined,
      onDidDispose,
      onDidChangeViewState,
      dispose: () => undefined,
    };
  },
  withProgress: async <T>(
    _options: unknown,
    task: (progress: { report: (value: unknown) => void }) => Promise<T>,
  ): Promise<T> =>
    task({
      report: () => undefined,
    }),
};

export const workspace = {
  workspaceFolders: undefined as unknown as undefined,
  getConfiguration: () => ({
    get: <T>(_section: string, fallback?: T): T | undefined => fallback,
    has: () => false,
    inspect: () => undefined,
    update: async () => undefined,
  }),
  openTextDocument: async (): Promise<unknown> => ({}),
  applyEdit: async (): Promise<boolean> => true,
  registerFileSystemProvider: () => noopDisposable(),
  onDidChangeConfiguration: createEvent<unknown>(),
  createFileSystemWatcher: () => ({
    onDidCreate: createEvent<unknown>(),
    onDidChange: createEvent<unknown>(),
    onDidDelete: createEvent<unknown>(),
    dispose: () => undefined,
  }),
  findFiles: async (): Promise<Uri[]> => [],
  asRelativePath: (target: string | Uri): string =>
    typeof target === 'string' ? target : target.fsPath,
};

export const commands = {
  registerCommand: (): Disposable => noopDisposable(),
  executeCommand: async (): Promise<unknown> => undefined,
  getCommands: async (): Promise<string[]> => [],
};

export const env = {
  appName: 'Visual Studio Code (test stub)',
  language: 'en',
  machineId: 'test-machine',
  sessionId: 'test-session',
  machineId_: 'test-machine',
  openExternal: async (): Promise<boolean> => true,
  clipboard: {
    writeText: async (): Promise<void> => undefined,
  },
};

export const extensions = {
  getExtension: () => undefined,
  all: [] as unknown[],
};

export const l10n = {
  t: (message: string, ...args: unknown[]): string =>
    args.length
      ? message.replace(/\{(\d+)\}/g, (match, index: string) => String(args[Number(index)] ?? match))
      : message,
};

export const ThemeColor = function ThemeColor(id: string): { id: string } {
  return { id };
} as unknown as new (id: string) => { id: string };

export const ViewColumn = { One: 1, Two: 2, Three: 3, Active: -1 };

export const ProgressLocation = { SourceControl: 1, Window: 10, Notification: 15 };

export const ConfigurationTarget = { Global: 1, Workspace: 2, WorkspaceFolder: 3 };

export const StatusBarAlignment = { Left: 1, Right: 2 };

export const ExtensionMode = { Production: 1, Development: 2, Test: 3 };

export const EventEmitter = class EventEmitter<T> {
  private readonly listeners = new Set<(value: T) => void>();

  readonly event: Event<T> = (listener: (value: T) => void) => {
    this.listeners.add(listener);
    return {
      dispose: () => {
        this.listeners.delete(listener);
      },
    };
  };

  fire(value: T): void {
    for (const listener of [...this.listeners]) {
      listener(value);
    }
  }

  dispose(): void {
    this.listeners.clear();
  }
};

export const version = '1.100.0-test';
