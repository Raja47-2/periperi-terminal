/**
 * `periperi` — the PARI PARI command line interface.
 *
 * Bundled to `dist/cli/periperi.js` and exposed as the `periperi` bin. The same
 * bundle is injected into the VS Code extension's dedicated terminal, so both
 * front-ends share one implementation of every command.
 *
 * Security rules honoured here:
 *   - files are read as text, never executed,
 *   - npm/yarn/pip/cargo are never invoked,
 *   - private-key bodies are never read,
 *   - workspace writes are confined to `<root>/.pari-pari/`,
 *   - nothing leaves the machine unless `periperi sync` is invoked explicitly.
 */

import * as path from 'node:path';
import * as fs from 'node:fs';

import { rollupAssets, summarizeRisk } from '../scanner/scanner';
import type { ScanRequest, ScanResult } from '../scanner/types';
import { runScanToState, type ScanRunOutcome } from '../core/scanRunner';
import { resolveSettings, readLegacySettingsSnapshot, type PariPariSettings } from '../core/config';
import { EcClient } from '../core/ecClient';
import { renderSarif } from '../core/sarif';
import { renderStaticReport } from '../core/reportHtml';
import {
  exceedsThreshold,
  isThreshold,
  normalizeThreshold,
  renderScanJson,
  TOOL_NAME,
  type Threshold,
} from '../core/resultJson';
import { generateCbom } from '../cbom/cbomGenerator';
import {
  ensureStorage,
  exportCbom,
  readLatestScan,
  renderExport,
  storageLayout,
} from '../cbom/cbomExporter';
import {
  CLI_NAME,
  PARI_COMMANDS,
  PARI_UNKNOWN_COMMAND_HINT,
  findCommand,
  parseArgs,
  renderHelp,
  type ParsedArgs,
} from '../terminal/commands';
import {
  renderBanner,
  renderError,
  renderFindings,
  renderFooter,
  renderProgress,
  renderScope,
  renderStatus,
  renderSummary,
} from '../terminal/output';
import { ensureDir, relativeLabel, safeResolveInside } from '../utils/paths';
import { describeError } from '../utils/errors';
import { EXTENSION_VERSION } from '../version';

const EXIT_ERROR = 1;
const EXIT_USAGE = 2;
const EXIT_FINDINGS = 3;

const LOGS_HINT = 'rerun with --json for the full list';

/* ------------------------------------------------------------------- output */

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  prompt: (question: string) => Promise<string>;
  /** Flipped by SIGINT/SIGTERM so an in-flight scan stops at the next checkpoint. */
  cancelled: { current: boolean };
}

function defaultIo(): CliIo {
  return {
    stdout: (text) => process.stdout.write(`${text}\n`),
    stderr: (text) => process.stderr.write(`${text}\n`),
    prompt: promptFromStdin,
    cancelled: { current: false },
  };
}

function promptFromStdin(question: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(`${question} `);
    const stdin = process.stdin;
    stdin.setEncoding('utf8');
    stdin.resume();
    const finish = (chunk: string): void => {
      stdin.pause();
      resolve(chunk.trim());
    };
    stdin.once('data', finish);
    stdin.once('end', () => resolve(''));
  });
}

class Cli {
  private exitCode = 0;

  constructor(private readonly io: CliIo) {}

  out(text: string): void {
    this.io.stdout(text);
  }

  blank(): void {
    this.io.stdout('');
  }

  prompt(question: string): Promise<string> {
    return this.io.prompt(question);
  }

  isCancelled(): boolean {
    return this.io.cancelled.current;
  }

  setExit(code: number): void {
    this.exitCode = code;
  }

  get code(): number {
    return this.exitCode;
  }

  /** Report a failure and record the error exit code. Never throws. */
  fail(text: string, code = EXIT_ERROR): void {
    this.io.stderr(text);
    this.exitCode = code;
  }

  usageError(text: string): void {
    this.fail(`${text}\nRun \`${CLI_NAME} help\` for usage.`, EXIT_USAGE);
  }
}

/* ------------------------------------------------------------------- flags */

function flagString(args: ParsedArgs, name: string): string | undefined {
  const value = args.flags[name];
  return typeof value === 'string' && value.trim() !== '' ? value : undefined;
}

function flagBool(args: ParsedArgs, ...names: string[]): boolean {
  return names.some((name) => args.flags[name] === true);
}

function thresholdFrom(args: ParsedArgs): { threshold: Threshold; error?: string } {
  const raw = flagString(args, 'fail-on');
  if (raw === undefined) {
    return { threshold: 'none' };
  }
  if (!isThreshold(raw)) {
    return { threshold: 'none', error: `Unknown severity "${raw}". Use critical, high, medium, low, info or none.` };
  }
  return { threshold: normalizeThreshold(raw) };
}

/* --------------------------------------------------------------- config i/o */

/**
 * The VS Code terminal hands the CLI a JSON snapshot through `PARI_PARI_SETTINGS`.
 * Honour it so an older extension build keeps working, then layer flags on top.
 */
function loadSettings(args: ParsedArgs, cwd: string): PariPariSettings {
  const legacyDir = process.env.PARI_PARI_SETTINGS;
  if (!legacyDir) {
    return resolveSettings({ flags: args.flags, cwd });
  }

  const snapshot = readLegacySettingsSnapshot(legacyDir);
  const merged: Record<string, string | boolean> = {};
  const legacyFlags: Record<string, string | boolean> = {
    'max-file-size': typeof snapshot.maxFileSize === 'number' ? String(snapshot.maxFileSize) : '',
    'max-files': typeof snapshot.maxFiles === 'number' ? String(snapshot.maxFiles) : '',
    exclude: Array.isArray(snapshot.exclude) ? snapshot.exclude.join(',') : '',
    'server-url': typeof snapshot.serverUrl === 'string' ? snapshot.serverUrl : '',
    'project-id': typeof snapshot.projectId === 'string' ? snapshot.projectId : '',
  };
  for (const [key, value] of Object.entries(legacyFlags)) {
    if (value !== '') {
      merged[key] = value;
    }
  }
  for (const [key, value] of Object.entries(args.flags)) {
    merged[key] = value;
  }
  return resolveSettings({ flags: merged, cwd });
}

function defaultRoot(): string {
  // `PARI_PARI_ROOT` is the historical name; `PERIPERI_ROOT` is the CLI name.
  return process.env.PERIPERI_ROOT ?? process.env.PARI_PARI_ROOT ?? process.cwd();
}

/* ------------------------------------------------------------------ target */

interface Scope {
  root: string;
  mode: ScanRequest['mode'];
  targets?: string[];
  label: string;
}

function resolveTargets(cli: Cli, cwd: string, args: ParsedArgs): Scope | undefined {
  const explicitFile = flagString(args, 'file');
  if (explicitFile) {
    const abs = path.resolve(cwd, explicitFile);
    if (!fs.existsSync(abs)) {
      cli.fail(`File not found: ${explicitFile}`);
      return undefined;
    }
    if (!fs.statSync(abs).isFile()) {
      cli.fail(`Not a file: ${explicitFile}`);
      return undefined;
    }
    return { root: cwd, mode: 'file', targets: [abs], label: path.basename(abs) };
  }

  const targetArg = args.positionals[0];
  if (targetArg) {
    const abs = path.resolve(cwd, targetArg);
    if (!fs.existsSync(abs)) {
      cli.fail(`Path not found: ${targetArg}`);
      return undefined;
    }
    if (fs.statSync(abs).isDirectory()) {
      return { root: abs, mode: 'folder', label: relativeLabel(cwd, abs) || path.basename(abs) };
    }
    return { root: cwd, mode: 'file', targets: [abs], label: path.basename(abs) };
  }

  return { root: cwd, mode: 'workspace', label: path.basename(cwd) || cwd };
}

/* ------------------------------------------------------------------ running */

interface Ctx {
  cli: Cli;
  cwd: string;
  args: ParsedArgs;
  settings: PariPariSettings;
}

async function scan(
  cli: Cli,
  cwd: string,
  settings: PariPariSettings,
  scope: Scope,
  onProgress?: (text: string) => void,
): Promise<ScanRunOutcome | undefined> {
  const request: ScanRequest = {
    root: scope.root,
    mode: scope.mode,
    targets: scope.targets,
    exclude: settings.scanExclude,
    maxFileSize: settings.maxFileSize,
    maxFiles: settings.maxFiles,
    label: scope.label,
  };

  return runScanToState(request, {
    settings,
    token: {
      get isCancellationRequested(): boolean {
        return cli.isCancelled();
      },
    },
    persistRoot: cwd,
    project: scope.label,
    onProgress: onProgress ? (progress) => onProgress(renderProgress(progress)) : undefined,
    onPersistError: (reason) => cli.out(`[WARN] Could not persist results: ${reason}`),
  });
}

/** Wrap a stored scan so the same report/gate helpers work for both paths. */
function fromStored(scanResult: ScanResult): ScanRunOutcome {
  return {
    result: scanResult,
    state: { result: scanResult, cbom: generateCbom(scanResult) },
    risk: summarizeRisk(scanResult.detections),
    rollup: rollupAssets(scanResult),
    report: '',
    written: {},
  };
}

function requireStored(cli: Cli, cwd: string): Promise<ScanResult | undefined> {
  return readLatestScan(cwd).then((stored) => {
    if (!stored) {
      cli.fail(`No stored scan found for ${cwd}. Run \`${CLI_NAME} scan\` first.`);
    }
    return stored;
  });
}

/* ------------------------------------------------------------------ commands */

async function cmdScan(ctx: Ctx): Promise<void> {
  const { cli, cwd, args, settings } = ctx;

  // Validate before printing anything: a usage error should not be buried
  // under a banner, and the scan should not run at all.
  const { threshold, error } = thresholdFrom(args);
  if (error) {
    cli.usageError(error);
    return;
  }

  const scope = resolveTargets(cli, cwd, args);
  if (!scope) {
    return;
  }

  // Machine-readable output must own stdout, so the banner and progress lines
  // are suppressed entirely — `periperi scan --json | jq` has to work.
  const wantSarif = flagBool(args, 'sarif');
  const wantJson = flagBool(args, 'json');
  const quiet = flagBool(args, 'quiet', 'q');
  const machine = wantSarif || wantJson;

  if (!machine && !quiet) {
    cli.out(renderBanner());
    cli.out(renderScope(scope.mode, scope.label));
    cli.blank();
  }

  const outcome = await scan(
    cli,
    cwd,
    settings,
    scope,
    machine || quiet ? undefined : (text) => cli.out(text),
  );
  if (!outcome) {
    return;
  }

  if (wantSarif) {
    cli.out(renderSarif(outcome.result, { projectName: scope.label }).trimEnd());
  } else if (wantJson) {
    cli.out(renderScanJson(outcome.result).trimEnd());
  } else if (quiet) {
    cli.out(renderFindings(outcome.result));
  } else {
    cli.blank();
    cli.out(renderSummary(outcome.result, outcome.risk, outcome.rollup, { logsHint: LOGS_HINT }));
    cli.out(renderFooter());
  }

  if (exceedsThreshold(outcome.risk, threshold)) {
    cli.setExit(EXIT_FINDINGS);
  }
}

async function cmdCbom(ctx: Ctx): Promise<void> {
  const { cli, cwd, args, settings } = ctx;
  const scope = resolveTargets(cli, cwd, args);
  if (!scope) {
    return;
  }

  const format = flagString(args, 'format') ?? 'both';
  if (format !== 'json' && format !== 'csv' && format !== 'both') {
    cli.usageError(`Unknown --format "${format}". Use json, csv or both.`);
    return;
  }
  const formats = { json: format !== 'csv', csv: format !== 'json' };

  cli.out(renderBanner());
  cli.out(renderScope(scope.mode, scope.label));

  const outcome = await scan(cli, cwd, settings, scope, (text) => cli.out(text));
  if (!outcome) {
    return;
  }

  const outDir = flagString(args, 'out');
  const destination = outDir ? path.resolve(cwd, outDir) : cwd;

  if (outDir) {
    ensureDir(destination);
    const stamp = outcome.state.cbom.scan_id;
    const written: string[] = [];
    if (formats.json) {
      const file = safeResolveInside(destination, `cbom-${stamp}.json`);
      fs.writeFileSync(file, renderExport(outcome.state.cbom, 'json'), 'utf8');
      written.push(file);
    }
    if (formats.csv) {
      const file = safeResolveInside(destination, `cbom-${stamp}.csv`);
      fs.writeFileSync(file, renderExport(outcome.state.cbom, 'csv'), 'utf8');
      written.push(file);
    }
    cli.blank();
    cli.out('CBOM generated successfully.');
    for (const file of written) {
      cli.out(`  ${file}`);
    }
    cli.out(renderFooter());
    return;
  }

  if (!settings.writeResultsToWorkspace) {
    cli.fail('Refusing to write: --no-write is set. Drop it or choose a destination with --out <dir>.');
    return;
  }

  const layout = ensureStorage(cwd);
  const exported = await exportCbom({
    cbom: outcome.state.cbom,
    scan: outcome.result,
    workspaceRoot: cwd,
    formats,
  });

  cli.blank();
  cli.out(renderSummary(outcome.result, outcome.risk, outcome.rollup, { logsHint: LOGS_HINT }));
  cli.blank();
  cli.out('CBOM generated successfully.');
  if (exported.jsonPath) {
    cli.out(`  JSON: ${relativeLabel(cwd, exported.jsonPath)}`);
  }
  if (exported.csvPath) {
    cli.out(`  CSV:  ${relativeLabel(cwd, exported.csvPath)}`);
  }
  cli.out(`  Storage: ${relativeLabel(cwd, layout.base)}`);
  cli.out(renderFooter());
}

async function cmdExport(ctx: Ctx): Promise<void> {
  const { cli, cwd, args, settings } = ctx;

  // Validate the arguments before looking at stored state, so a typo is
  // reported as a usage error rather than as a missing scan.
  const format = flagString(args, 'format') ?? 'both';
  if (format !== 'json' && format !== 'csv' && format !== 'both') {
    cli.usageError(`Unknown --format "${format}". Use json, csv or both.`);
    return;
  }

  const stored = await requireStored(cli, cwd);
  if (!stored) {
    return;
  }

  const to = flagString(args, 'to');
  const explicitDir = to ? path.resolve(cwd, to) : undefined;
  if (explicitDir) {
    ensureDir(explicitDir);
  } else if (!settings.writeResultsToWorkspace) {
    cli.fail('Refusing to write: --no-write is set. Drop it or choose a destination with --to <dir>.');
    return;
  }

  const cbom = generateCbom(stored, { project: path.basename(cwd) });
  const exported = await exportCbom({
    cbom,
    scan: stored,
    workspaceRoot: explicitDir ? undefined : cwd,
    outputDir: explicitDir,
    formats: { json: format !== 'csv', csv: format !== 'json' },
  });

  cli.out(renderBanner());
  cli.blank();
  cli.out('Export complete.');
  if (exported.jsonPath) {
    cli.out(`  JSON: ${relativeLabel(cwd, exported.jsonPath)}`);
  }
  if (exported.csvPath) {
    cli.out(`  CSV:  ${relativeLabel(cwd, exported.csvPath)}`);
  }
  cli.out(renderFooter());
}

async function cmdReport(ctx: Ctx): Promise<void> {
  const { cli, cwd, args } = ctx;
  const stored = await requireStored(cli, cwd);
  if (!stored) {
    return;
  }

  const wantSarif = flagBool(args, 'sarif');
  const wantJson = flagBool(args, 'json');
  const outFile = flagString(args, 'out');
  const wantsFile = Boolean(outFile) || wantSarif || wantJson || flagBool(args, 'html');

  if (wantsFile) {
    const layout = ensureStorage(cwd);
    const stamp = stored.scanId;
    let kind: string;
    let file: string;
    let contents: string;

    if (wantSarif) {
      kind = 'SARIF';
      file = outFile ? path.resolve(cwd, outFile) : safeResolveInside(layout.reports, `sarif-${stamp}.sarif`);
      contents = renderSarif(stored, { projectName: path.basename(cwd) });
    } else if (wantJson) {
      kind = 'JSON';
      file = outFile ? path.resolve(cwd, outFile) : safeResolveInside(layout.reports, `report-${stamp}.json`);
      contents = renderScanJson(stored);
    } else {
      kind = 'HTML report';
      file = outFile ? path.resolve(cwd, outFile) : safeResolveInside(layout.reports, `report-${stamp}.html`);
      contents = renderStaticReport({
        result: stored,
        cbom: generateCbom(stored, { project: path.basename(cwd) }),
      });
    }

    if (outFile) {
      ensureDir(path.dirname(file));
    }
    fs.writeFileSync(file, contents, 'utf8');

    cli.blank();
    cli.out(`${kind} written:`);
    cli.out(`  ${file}`);
    cli.out(renderFooter());
    return;
  }

  const outcome = fromStored(stored);
  cli.out(renderBanner());
  cli.out(renderSummary(outcome.result, outcome.risk, outcome.rollup, { logsHint: LOGS_HINT }));
  cli.out(renderFooter());

  const { threshold, error } = thresholdFrom(args);
  if (error) {
    cli.usageError(error);
    return;
  }
  if (exceedsThreshold(outcome.risk, threshold)) {
    cli.setExit(EXIT_FINDINGS);
  }
}

async function cmdRisk(ctx: Ctx): Promise<void> {
  const { cli, cwd, args } = ctx;
  const stored = await requireStored(cli, cwd);
  if (!stored) {
    return;
  }

  const risk = summarizeRisk(stored.detections);
  cli.out(renderBanner());
  cli.blank();
  cli.out('Risk Overview (preliminary static-analysis result):');
  cli.out(`Cryptographic Assets: ${risk.total}`);
  cli.out(`  Critical: ${risk.critical}`);
  cli.out(`  High:     ${risk.high}`);
  cli.out(`  Medium:   ${risk.medium}`);
  cli.out(`  Low:      ${risk.low}`);
  cli.out(`  Info:     ${risk.info}`);

  if (flagBool(args, 'json')) {
    cli.blank();
    cli.out(renderScanJson(stored).trimEnd());
  }

  const { threshold, error } = thresholdFrom(args);
  if (error) {
    cli.usageError(error);
    return;
  }
  if (exceedsThreshold(risk, threshold)) {
    cli.setExit(EXIT_FINDINGS);
  }
}

async function cmdStatus(ctx: Ctx): Promise<void> {
  const { cli, cwd, args, settings } = ctx;
  const stored = await readLatestScan(cwd);

  let backend: string | undefined;
  if (flagBool(args, 'check-server') && settings.serverUrl) {
    const client = new EcClient({
      serverUrl: settings.serverUrl,
      apiKey: settings.apiKey,
      projectId: settings.projectId,
      client: TOOL_NAME,
    });
    const result = await client.connect();
    backend = result.ok ? 'reachable' : `unreachable — ${result.reason ?? 'unknown error'}`;
  }

  cli.out(renderBanner());
  cli.out(
    renderStatus({
      surface: 'cli',
      workspaceRoot: cwd,
      lastScan: stored,
      risk: stored ? summarizeRisk(stored.detections) : undefined,
      settings: {
        serverUrl: settings.serverUrl,
        projectId: settings.projectId,
        enableTelemetry: settings.enableTelemetry,
        writeResultsToWorkspace: settings.writeResultsToWorkspace,
      },
      version: EXTENSION_VERSION,
      backend,
    }),
  );
}

async function cmdSync(ctx: Ctx): Promise<void> {
  const { cli, cwd, args, settings } = ctx;

  if (!settings.serverUrl) {
    cli.fail('No ECDAT server configured. Set PERIPERI_SERVER_URL or --server-url. Nothing was uploaded.');
    return;
  }

  const stored = await requireStored(cli, cwd);
  if (!stored) {
    return;
  }

  const cbom = generateCbom(stored, { project: path.basename(cwd) });
  const client = new EcClient({
    serverUrl: settings.serverUrl,
    apiKey: settings.apiKey,
    projectId: settings.projectId,
    client: TOOL_NAME,
  });

  if (flagBool(args, 'dry-run')) {
    cli.out(renderBanner());
    cli.out(`Target:   ${settings.serverUrl}/api/v1/cbom`);
    cli.out(`CBOM:     ${cbom.scan_id}`);
    cli.out(`Assets:   ${cbom.assets.length}`);
    cli.out(`Project:  ${settings.projectId || '(not set)'}`);
    cli.blank();
    cli.out('Dry run — nothing was uploaded.');
    cli.out(renderFooter());
    return;
  }

  const confirm = async (): Promise<boolean> => {
    if (flagBool(args, 'yes', 'y')) {
      return true;
    }
    if (!process.stdin.isTTY) {
      return false;
    }
    cli.out(
      `Upload CBOM ${cbom.scan_id} (${cbom.assets.length} asset records, file paths and line numbers) to ${settings.serverUrl}?`,
    );
    cli.out('Source code is never uploaded.');
    const answer = await cli.prompt('Type "upload" to confirm:');
    return answer.toLowerCase() === 'upload';
  };

  cli.out(renderBanner());
  cli.out(`Syncing CBOM ${cbom.scan_id} to ${settings.serverUrl}…`);

  const result = await client.syncScan(cbom, confirm);
  if (result.ok) {
    cli.blank();
    cli.out(`CBOM synchronised${result.remoteId ? ` (${result.remoteId})` : ''}.`);
    cli.out(renderFooter());
    return;
  }
  cli.fail(`Sync not completed — ${result.reason ?? 'unknown error'}`);
}

async function cmdClear(ctx: Ctx): Promise<void> {
  const { cli, cwd } = ctx;
  const layout = storageLayout(cwd);
  let removed = 0;
  for (const dir of [layout.scans, layout.cbom, layout.reports]) {
    try {
      for (const entry of fs.readdirSync(dir)) {
        fs.unlinkSync(path.join(dir, entry));
        removed += 1;
      }
    } catch {
      /* directory may not exist yet */
    }
  }
  cli.out(`Cleared ${removed} stored file(s) from ${layout.base}`);
}

function cmdHelp(ctx: Ctx): void {
  const { cli, args } = ctx;
  const topic = args.positionals[0];
  if (topic) {
    const command = findCommand(topic);
    if (command) {
      cli.blank();
      cli.out(`  ${command.usage}`);
      cli.out(`  ${command.summary}`);
      cli.blank();
      return;
    }
  }
  cli.out(renderHelp());
}

function cmdVersion(ctx: Ctx): void {
  ctx.cli.out(`${TOOL_NAME} ${EXTENSION_VERSION}`);
}

/* ---------------------------------------------------------------------- main */

async function dispatch(ctx: Ctx): Promise<void> {
  const { cli, args } = ctx;

  if (flagBool(args, 'version', 'v')) {
    return cmdVersion(ctx);
  }
  if (flagBool(args, 'help', 'h') || !args.command) {
    return cmdHelp(ctx);
  }

  const command = findCommand(args.command);
  if (!command) {
    cli.out(PARI_UNKNOWN_COMMAND_HINT);
    cli.out(`Available: ${PARI_COMMANDS.map((c) => c.name).join(', ')}`);
    cli.setExit(EXIT_USAGE);
    return;
  }

  switch (command.name) {
    case 'scan':
      return cmdScan(ctx);
    case 'cbom':
      return cmdCbom(ctx);
    case 'export':
      return cmdExport(ctx);
    case 'report':
      return cmdReport(ctx);
    case 'risk':
      return cmdRisk(ctx);
    case 'status':
      return cmdStatus(ctx);
    case 'sync':
      return cmdSync(ctx);
    case 'clear':
      return cmdClear(ctx);
    case 'help':
      return cmdHelp(ctx);
    default:
      return cmdHelp(ctx);
  }
}

function installSignalHandlers(io: CliIo): void {
  const handle = (): void => {
    if (io.cancelled.current) {
      process.exitCode = EXIT_ERROR;
      process.exit(EXIT_ERROR);
    }
    io.cancelled.current = true;
    io.stdout('[WARN] Cancellation requested — stopping at the next checkpoint. Press Ctrl+C again to force quit.');
  };
  process.once('SIGINT', handle);
  process.once('SIGTERM', handle);
}

export interface CliOptions {
  argv?: string[];
  cwd?: string;
  io?: Partial<CliIo>;
}

/** Programmatic entry point. Returns the process exit code without exiting. */
export async function main(options: CliOptions = {}): Promise<number> {
  const argv = options.argv ?? process.argv.slice(2);
  const args = parseArgs(argv);
  const cwd = options.cwd ?? defaultRoot();
  const io: CliIo = { ...defaultIo(), ...options.io };
  const cli = new Cli(io);

  if (options.argv === undefined) {
    installSignalHandlers(io);
  }

  try {
    await dispatch({ cli, cwd, args, settings: loadSettings(args, cwd) });
  } catch (err) {
    const { reason } = describeError(err);
    io.stderr(renderError(`${TOOL_NAME} failed`, reason));
    return EXIT_ERROR;
  }

  return cli.code;
}

const invokedDirectly =
  typeof require !== 'undefined' &&
  typeof module !== 'undefined' &&
  require.main === module;

if (invokedDirectly) {
  main().then((code) => {
    process.exitCode = code;
  });
}
