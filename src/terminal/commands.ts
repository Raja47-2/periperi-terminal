/**
 * The `periperi` command surface.
 *
 * One declarative table drives:
 *   - the standalone CLI bundled to `dist/cli/periperi.js`,
 *   - `periperi help` output,
 *   - the README command table.
 *
 * The VS Code extension injects the very same bundle into its dedicated
 * terminal, so both front-ends expose identical behaviour.
 */

export interface PariCommand {
  /** Verb typed after `periperi`, e.g. `scan`. */
  name: string;
  /** Argument hint shown in help. */
  usage: string;
  summary: string;
  /** `true` when the command performs real work (progress is shown). */
  heavier: boolean;
}

export const CLI_NAME = 'periperi';

export const PARI_COMMANDS: readonly PariCommand[] = [
  {
    name: 'scan',
    usage: 'periperi scan [path] [--file <file>]',
    summary: 'Scan a folder or the working directory for cryptographic indicators.',
    heavier: true,
  },
  {
    name: 'cbom',
    usage: 'periperi cbom [path] [--format json|csv|both] [--out <dir>]',
    summary: 'Scan and write a CBOM to .pari-pari/cbom/.',
    heavier: true,
  },
  {
    name: 'export',
    usage: 'periperi export [--format json|csv|both] [--to <dir>]',
    summary: 'Export the most recent scan as JSON and/or CSV.',
    heavier: false,
  },
  {
    name: 'report',
    usage: 'periperi report [--html] [--json] [--sarif] [--out <file>]',
    summary: 'Print a report for the most recent scan, or write it as HTML/JSON/SARIF.',
    heavier: false,
  },
  {
    name: 'risk',
    usage: 'periperi risk [--fail-on <severity>]',
    summary: 'Print the preliminary risk overview for the most recent scan.',
    heavier: false,
  },
  {
    name: 'status',
    usage: 'periperi status [--check-server]',
    summary: 'Show version, working directory, configuration and backend status.',
    heavier: false,
  },
  {
    name: 'sync',
    usage: 'periperi sync [--yes] [--dry-run]',
    summary: 'Upload the most recent CBOM to a configured ECDAT server.',
    heavier: false,
  },
  {
    name: 'clear',
    usage: 'periperi clear',
    summary: 'Delete stored scan results, CBOMs and reports for this directory.',
    heavier: false,
  },
  {
    name: 'help',
    usage: 'periperi help',
    summary: 'Show this help text.',
    heavier: false,
  },
];

export interface GlobalOption {
  flag: string;
  description: string;
}

export const GLOBAL_OPTIONS: readonly GlobalOption[] = [
  { flag: '--exclude <list>', description: 'Comma-separated directory and file names to skip.' },
  { flag: '--max-files <n>', description: 'Maximum number of files to read in one scan.' },
  { flag: '--max-file-size <n>', description: 'Maximum file size in bytes; larger files are skipped.' },
  { flag: '--no-write', description: 'Do not write anything into .pari-pari/.' },
  { flag: '--server-url <url>', description: 'ECDAT server URL. Omit to stay fully local.' },
  { flag: '--api-key <key>', description: 'ECDAT API key. Prefer the PERIPERI_API_KEY env var.' },
  { flag: '--project-id <id>', description: 'Project identifier sent with a sync.' },
  { flag: '--fail-on <severity>', description: 'Exit 3 when findings reach this severity: critical|high|medium|low|info.' },
  { flag: '--json / --sarif', description: 'Machine-readable output on stdout. Suppresses the human report.' },
  { flag: '--quiet, -q', description: 'Only print the findings the gate would trip on.' },
  { flag: '--version, -v', description: 'Print the version.' },
  { flag: '--help, -h', description: 'Show this help text.' },
];

export const PARI_UNKNOWN_COMMAND_HINT =
  'Unknown command. Run `periperi help` for the list of supported commands.';

export function findCommand(name: string): PariCommand | undefined {
  return PARI_COMMANDS.find((cmd) => cmd.name === name.toLowerCase());
}

export function renderHelp(): string {
  const lines: string[] = [
    '',
    'PARI PARI TERMINAL — cryptographic discovery from the terminal',
    '',
    'USAGE',
    `  ${CLI_NAME} <command> [options]`,
    '',
    'COMMANDS',
  ];
  const width = Math.max(...PARI_COMMANDS.map((c) => c.usage.length));
  for (const cmd of PARI_COMMANDS) {
    lines.push(`  ${cmd.usage.padEnd(width + 2)}${cmd.summary}`);
  }
  lines.push('', 'GLOBAL OPTIONS');
  for (const option of GLOBAL_OPTIONS) {
    lines.push(`  ${option.flag.padEnd(width + 2)}${option.description}`);
  }
  lines.push(
    '',
    'CONFIGURATION',
    '  Precedence: flags > environment > .periperirc > defaults.',
    '  Environment: PERIPERI_SERVER_URL, PERIPERI_API_KEY, PERIPERI_PROJECT_ID,',
    '               PERIPERI_EXCLUDE, PERIPERI_MAX_FILES, PERIPERI_MAX_FILE_SIZE,',
    '               PERIPERI_NO_WRITE.',
    '',
    'Examples:',
    '  periperi scan',
    '  periperi scan src/',
    '  periperi scan --file src/auth.ts',
    '  periperi scan --json > scan.json',
    '  periperi scan --sarif --fail-on high   # CI gate, exit 3 on findings',
    '  periperi cbom --format both',
    '  periperi report --html',
    '  periperi status --check-server',
    '',
    'EXIT CODES',
    '  0  clean          2  bad usage',
    '  1  error          3  findings at or above --fail-on',
    '',
    'Everything runs locally. Nothing leaves this machine unless you run `periperi sync`.',
    '',
  );
  return lines.join('\n');
}

/**
 * Flags that never take a value.
 *
 * Without this list `--json src/` would parse `src/` as the value of `--json`.
 * Anything not listed here may consume the following token when that token does
 * not start with `-`.
 */
export const BOOLEAN_FLAGS: ReadonlySet<string> = new Set([
  'json',
  'sarif',
  'html',
  'quiet',
  'q',
  'help',
  'h',
  'version',
  'v',
  'yes',
  'y',
  'dry-run',
  'no-write',
  'telemetry',
  'check-server',
  'open-dashboard',
]);

export function isBooleanFlag(name: string): boolean {
  return BOOLEAN_FLAGS.has(name);
}

/** Minimal, dependency-free argv parser shared by the CLI. */
export interface ParsedArgs {
  command: string;
  positionals: string[];
  flags: Record<string, string | boolean>;
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  let command = '';
  let endOfFlags = false;

  const setFlag = (key: string, value: string | boolean): void => {
    flags[key] = value;
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (endOfFlags) {
      positionals.push(arg);
      continue;
    }

    if (arg === '--') {
      endOfFlags = true;
      continue;
    }

    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq !== -1) {
        setFlag(arg.slice(2, eq), arg.slice(eq + 1));
        continue;
      }
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (!isBooleanFlag(key) && next !== undefined && !next.startsWith('-')) {
        setFlag(key, next);
        i += 1;
      } else {
        setFlag(key, true);
      }
      continue;
    }

    if (arg.startsWith('-') && arg.length > 1) {
      // Short flags never take a value; `-q` is treated as `q`.
      setFlag(arg.slice(1), true);
      continue;
    }

    if (!command) {
      command = arg;
    } else {
      positionals.push(arg);
    }
  }

  return { command, positionals, flags };
}
