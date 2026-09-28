/**
 * Shared configuration contract.
 *
 * One set of keys, one set of defaults, three front-ends:
 *   - the VS Code extension (`config/configuration.ts` adapts `pariPari.*`),
 *   - the `periperi` CLI (flags / env / rc file),
 *   - the tests.
 *
 * Precedence for the CLI is: flags > env > rc file > defaults.
 * This module must stay free of any `vscode` import.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export interface PariPariSettings {
  serverUrl: string;
  apiKey: string;
  projectId: string;
  scanExclude: string[];
  maxFileSize: number;
  maxFiles: number;
  enableTelemetry: boolean;
  openDashboardAfterScan: boolean;
  writeResultsToWorkspace: boolean;
}

export const DEFAULT_SETTINGS: PariPariSettings = {
  serverUrl: '',
  apiKey: '',
  projectId: '',
  // `.pari-pari` is PARI PARI's own output directory. Excluding it prevents a
  // scan from re-detecting the crypto strings inside its previous CBOM, which
  // would inflate the result on every run.
  scanExclude: ['node_modules', '.git', 'dist', 'build', '.venv', '.pari-pari'],
  maxFileSize: 1048576,
  maxFiles: 20000,
  enableTelemetry: false,
  openDashboardAfterScan: false,
  writeResultsToWorkspace: true,
};

export const MAX_FILE_SIZE_RANGE = { min: 1024, max: 50 * 1024 * 1024 } as const;
export const MAX_FILES_RANGE = { min: 1, max: 250000 } as const;

/** rc file names probed in the working directory, in order. */
export const RC_FILENAMES = ['.periperirc', '.periperirc.json', '.pari-parirc'] as const;

export const ENV_PREFIX = 'PERIPERI_';

export function clamp(value: number, min: number, max: number, fallback: number): number {
  if (!Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(Math.max(value, min), max);
}

/** Redacted snapshot safe for logging or for a status view. */
export function settingsSnapshot(settings: PariPariSettings): PariPariSettings {
  return {
    ...settings,
    apiKey: settings.apiKey ? '***' : '',
  };
}

/** Split a comma or whitespace separated list. Empty entries are dropped. */
export function parseList(value: string): string[] {
  return value
    .split(/[,\s]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function toBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    const text = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(text)) {
      return true;
    }
    if (['0', 'false', 'no', 'off', ''].includes(text)) {
      return false;
    }
  }
  return fallback;
}

function toNumber(value: unknown): number | undefined {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function toStringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

function toStringList(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === 'string');
  }
  if (typeof value === 'string') {
    return parseList(value);
  }
  return undefined;
}

/** Shape accepted from an rc file. Mirrors the public settings keys in kebab and snake case. */
interface RawOverrides {
  serverUrl?: string;
  server_url?: string;
  apiKey?: string;
  api_key?: string;
  projectId?: string;
  project_id?: string;
  scanExclude?: string[];
  scan_exclude?: string[];
  exclude?: string[];
  maxFileSize?: number;
  max_file_size?: number;
  maxFiles?: number;
  max_files?: number;
  enableTelemetry?: boolean;
  enable_telemetry?: boolean;
  openDashboardAfterScan?: boolean;
  open_dashboard_after_scan?: boolean;
  writeResultsToWorkspace?: boolean;
  write_results_to_workspace?: boolean;
}

function firstString(...values: unknown[]): string | undefined {
  for (const value of values) {
    const text = toStringValue(value);
    if (text !== undefined) {
      return text;
    }
  }
  return undefined;
}

function firstNumber(...values: unknown[]): number | undefined {
  for (const value of values) {
    const num = toNumber(value);
    if (num !== undefined) {
      return num;
    }
  }
  return undefined;
}

function firstList(...values: unknown[]): string[] | undefined {
  for (const value of values) {
    const list = toStringList(value);
    if (list !== undefined) {
      return list;
    }
  }
  return undefined;
}

function firstBoolean(...values: unknown[]): boolean | undefined {
  for (const value of values) {
    if (typeof value === 'boolean') {
      return value;
    }
    if (typeof value === 'string' && value.trim() !== '') {
      return toBoolean(value, false);
    }
  }
  return undefined;
}

/**
 * Read the first rc file found for `cwd`, then the user-level config.
 * A malformed file is ignored rather than fatal: configuration must never
 * prevent a scan from running.
 */
/**
 * Drop a UTF-8 BOM. `JSON.parse` rejects one, and PowerShell's
 * `Set-Content -Encoding utf8` plus Notepad both add it, so without this a
 * hand-written rc file fails to load with no visible error.
 */
function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/** `max-file-size` -> `maxFileSize` */
function camelCase(key: string): string {
  return key.replace(/[-.](\w)/g, (_m, ch: string) => ch.toUpperCase());
}

/** `maxFileSize` -> `max_file_size` */
function snakeCase(key: string): string {
  return key.replace(/[-\s]+(\w)/g, (_m, ch: string) => `_${ch.toLowerCase()}`)
    .replace(/_+(\w)/g, (_m, ch: string) => `_${ch.toLowerCase()}`);
}

/**
 * Store a key under every alias the resolver understands, so a rc file may use
 * kebab (`max-files`), snake (`max_files`) or camel (`maxFiles`) case.
 */
function withAliases(
  out: Record<string, string | number | boolean>,
  key: string,
  value: string | number | boolean,
): void {
  out[key] = value;
  const camel = camelCase(key);
  const snake = snakeCase(key);
  if (camel !== key) {
    out[camel] = value;
  }
  if (snake !== key && snake !== camel) {
    out[snake] = value;
  }
}

/**
 * Parse the plain-text rc format used by `.periperirc` / `.pari-parirc`:
 * one `key = value` pair per line, `#` or `;` comments, optional quotes.
 * Returns `undefined` when the text yields no pairs.
 */
export function parseRcText(text: string): RawOverrides | undefined {
  const out: Record<string, string | number | boolean> = {};
  let found = false;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) {
      continue;
    }
    const match = /^(?<key>[A-Za-z0-9_.-]+)\s*(?:=|:)\s*(?<value>.*)$/.exec(line);
    if (!match?.groups) {
      continue;
    }
    const key = match.groups.key.trim();
    const value = match.groups.value.trim().replace(/^(['"])(.*)\1$/, '$2');
    if (!key) {
      continue;
    }
    withAliases(out, key, coerceRcValue(value));
    found = true;
  }

  return found ? (out as RawOverrides) : undefined;
}

/** Coerce a raw rc value so `max-files = 10` arrives as a number. */
function coerceRcValue(value: string): string | number | boolean {
  if (value === 'true') {
    return true;
  }
  if (value === 'false') {
    return false;
  }
  if (value !== '' && /^-?\d+(\.\d+)?$/.test(value)) {
    return Number(value);
  }
  return value;
}

/** Apply `withAliases` across a parsed JSON rc object. */
function normalizeRcObject(source: Record<string, unknown>): RawOverrides {
  const out: Record<string, string | number | boolean> = {};
  for (const [key, value] of Object.entries(source)) {
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      withAliases(out, key, value);
    } else if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
      withAliases(out, key, value.join(','));
    }
  }
  return out as RawOverrides;
}

/**
 * Read the first rc file found for `cwd`, then the user-level config.
 *
 * `.json` files are parsed as JSON; every other rc name is parsed as plain
 * `key = value` text. A malformed file is ignored rather than fatal:
 * configuration must never prevent a scan from running.
 */
export function loadRcFile(cwd: string, home = os.homedir()): RawOverrides {
  const candidates = [
    ...RC_FILENAMES.map((name) => path.join(cwd, name)),
    path.join(home, '.config', 'periperi', 'config.json'),
  ];
  for (const candidate of candidates) {
    try {
      if (!fs.statSync(candidate).isFile()) {
        continue;
      }
      const raw = stripBom(fs.readFileSync(candidate, 'utf8'));
      // Sniff the content rather than trusting the extension: users write JSON
      // into `.pari-parirc` as often as they write `key = value` into it.
      const looksJson = candidate.endsWith('.json') || /^\s*[[{]/.test(raw);
      if (looksJson) {
        const parsed: unknown = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          return normalizeRcObject(parsed as Record<string, unknown>);
        }
        continue;
      }
      const parsed = parseRcText(raw);
      if (parsed) {
        return parsed;
      }
    } catch {
      /* unreadable or malformed rc file is ignored */
    }
  }
  return {};
}

export interface ResolveSettingsInput {
  /** Parsed CLI flags (`parseArgs(...).flags`). */
  flags?: Record<string, string | boolean>;
  /** Defaults to `process.env`. */
  env?: Record<string, string | undefined>;
  /** Working directory used to locate an rc file. */
  cwd?: string;
  /** Home directory used to locate the user-level config. */
  home?: string;
}

/**
 * Merge every configuration source into the final settings object.
 * Unset values fall through to `DEFAULT_SETTINGS`.
 */
export function resolveSettings(input: ResolveSettingsInput = {}): PariPariSettings {
  const flags = input.flags ?? {};
  const env = input.env ?? process.env;
  const cwd = input.cwd ?? process.cwd();
  const rc = loadRcFile(cwd, input.home);

  const serverUrl = firstString(flags['server-url'], env[`${ENV_PREFIX}SERVER_URL`], rc.serverUrl, rc.server_url) ?? DEFAULT_SETTINGS.serverUrl;
  const apiKey = firstString(flags['api-key'], env[`${ENV_PREFIX}API_KEY`], rc.apiKey, rc.api_key) ?? DEFAULT_SETTINGS.apiKey;
  const projectId = firstString(flags['project-id'], env[`${ENV_PREFIX}PROJECT_ID`], rc.projectId, rc.project_id) ?? DEFAULT_SETTINGS.projectId;

  const scanExclude =
    firstList(flags.exclude, env[`${ENV_PREFIX}EXCLUDE`], rc.scanExclude, rc.scan_exclude, rc.exclude) ??
    DEFAULT_SETTINGS.scanExclude;

  const maxFileSize = clamp(
    firstNumber(flags['max-file-size'], env[`${ENV_PREFIX}MAX_FILE_SIZE`], rc.maxFileSize, rc.max_file_size) ??
      DEFAULT_SETTINGS.maxFileSize,
    MAX_FILE_SIZE_RANGE.min,
    MAX_FILE_SIZE_RANGE.max,
    DEFAULT_SETTINGS.maxFileSize,
  );

  const maxFiles = clamp(
    firstNumber(flags['max-files'], env[`${ENV_PREFIX}MAX_FILES`], rc.maxFiles, rc.max_files) ?? DEFAULT_SETTINGS.maxFiles,
    MAX_FILES_RANGE.min,
    MAX_FILES_RANGE.max,
    DEFAULT_SETTINGS.maxFiles,
  );

  const enableTelemetry =
    firstBoolean(flags.telemetry, env[`${ENV_PREFIX}TELEMETRY`], rc.enableTelemetry, rc.enable_telemetry) ??
    DEFAULT_SETTINGS.enableTelemetry;

  const openDashboardAfterScan =
    firstBoolean(
      flags['open-dashboard'],
      env[`${ENV_PREFIX}OPEN_DASHBOARD`],
      rc.openDashboardAfterScan,
      rc.open_dashboard_after_scan,
    ) ?? DEFAULT_SETTINGS.openDashboardAfterScan;

  // `--no-write` is the only way to disable workspace persistence from the CLI.
  const writeResultsToWorkspace =
    flags['no-write'] === true || toBoolean(env[`${ENV_PREFIX}NO_WRITE`], false)
      ? false
      : (firstBoolean(rc.writeResultsToWorkspace, rc.write_results_to_workspace) ??
        DEFAULT_SETTINGS.writeResultsToWorkspace);

  return {
    serverUrl,
    apiKey,
    projectId,
    scanExclude,
    maxFileSize,
    maxFiles,
    enableTelemetry,
    openDashboardAfterScan,
    writeResultsToWorkspace,
  };
}

/**
 * Legacy bridge: the VS Code terminal used to hand the CLI a JSON snapshot via
 * `PARI_PARI_SETTINGS`. Still honoured so an older extension build keeps working.
 */
export function readLegacySettingsSnapshot(dir: string): Record<string, unknown> {
  try {
    const raw = fs.readFileSync(path.join(dir, 'pari-settings.json'), 'utf8');
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
