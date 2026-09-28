/**
 * Terminal / output-channel formatting.
 *
 * Pure string builders with no I/O so they are shared byte-for-byte between:
 *   - the VS Code output channel,
 *   - the dedicated PARI PARI terminal,
 *   - the `pari` CLI shim.
 *
 * Progress lines are only emitted for stages that actually run.
 */

import type { ScanProgress, ScanResult, ScanStage } from '../scanner/types';
import type { RiskSummary, AssetRollup } from '../scanner/scanner';
import { DISCLAIMER } from '../version';

const BOX_WIDTH = 46;

function centre(text: string, width: number): string {
  if (text.length >= width) {
    return text;
  }
  const pad = Math.floor((width - text.length) / 2);
  return `${' '.repeat(pad)}${text}${' '.repeat(width - text.length - pad)}`;
}

export function renderBanner(): string {
  const line = '─'.repeat(BOX_WIDTH);
  return [
    `╭${line}╮`,
    `│${centre('PARI PARI TERMINAL', BOX_WIDTH)}│`,
    `│${centre('Enterprise Cryptographic Discovery', BOX_WIDTH)}│`,
    `╰${line}╯`,
    '',
  ].join('\n');
}

const STAGE_LABEL: Record<ScanStage, string> = {
  discover: 'Discovering supported files',
  source: 'Analysing source files',
  dependencies: 'Analysing dependencies',
  config: 'Detecting cryptographic artefacts',
  build: 'Assembling results',
  done: 'Preparing results',
};

/** Progress text bound to real stage transitions, e.g. `[2/5] Analysing source files`. */
export function renderProgress(progress: ScanProgress): string {
  const label = progress.stage === 'done' ? 'Scan completed' : STAGE_LABEL[progress.stage];
  const head = `[${progress.step}/${progress.totalSteps}] ${label}`;
  if (progress.stage === 'done') {
    return `${head}…`;
  }
  if (
    typeof progress.filesTotal === 'number' &&
    typeof progress.filesProcessed === 'number' &&
    progress.filesTotal > 0
  ) {
    return `${head} (${progress.filesProcessed}/${progress.filesTotal})`;
  }
  return `${head}…`;
}

export function renderScope(mode: ScanResult['mode'], rootLabel: string): string {
  const label = mode === 'workspace' ? 'Workspace' : mode === 'folder' ? 'Folder' : 'File';
  return `[SCAN] ${label} — ${rootLabel}`;
}

export function renderSummary(
  result: ScanResult,
  risk: RiskSummary,
  rollup: AssetRollup,
  options: { logsHint?: string } = {},
): string {
  const logsHint = options.logsHint ?? 'see the PARI PARI output channel';
  const lines: string[] = [];
  lines.push(result.cancelled ? '[WARN] Scan cancelled — results are partial.' : '✓ Scan completed');
  lines.push('');
  lines.push(`Scan:              ${result.scanId}`);
  lines.push(`Files scanned:     ${result.stats.filesScanned} of ${result.stats.filesDiscovered}`);
  lines.push(`Duration:          ${result.stats.durationMs} ms`);
  lines.push('');
  lines.push(`Cryptographic Assets: ${risk.total}`);
  lines.push('');
  lines.push('Risk Overview:');
  lines.push(`  Critical: ${risk.critical}`);
  lines.push(`  High:     ${risk.high}`);
  lines.push(`  Medium:   ${risk.medium}`);
  lines.push(`  Low:      ${risk.low}`);
  lines.push(`  Info:     ${risk.info}`);
  lines.push('');
  lines.push(`Algorithms (${rollup.algorithms.length}): ${rollup.algorithms.join(', ') || '—'}`);
  lines.push(`Libraries  (${rollup.libraries.length}): ${rollup.libraries.join(', ') || '—'}`);
  lines.push(`Protocols  (${rollup.protocols.length}): ${rollup.protocols.join(', ') || '—'}`);
  lines.push(`Files with findings: ${rollup.files.length}`);
  if (result.privateKeyFiles.length > 0) {
    lines.push('');
    lines.push(`Private-key files detected: ${result.privateKeyFiles.length} (contents not read)`);
  }
  if (result.errors.length > 0) {
    lines.push('');
    lines.push(`Files skipped / unreadable: ${result.errors.length}`);
    for (const err of result.errors.slice(0, 5)) {
      lines.push(`  - ${err.file}: ${err.reason}`);
    }
    if (result.errors.length > 5) {
      lines.push(`  … and ${result.errors.length - 5} more (${logsHint})`);
    }
  }
  return lines.join('\n');
}

export function renderFooter(extra: string[] = []): string {
  const lines = ['', DISCLAIMER];
  for (const line of extra) {
    lines.push(line);
  }
  return lines.join('\n');
}

export function renderProgressLine(progress: ScanProgress): string {
  return renderProgress(progress);
}

/** Friendly, non-technical failure block. Never includes a stack trace. */
export function renderError(title: string, reason: string, detail?: string): string {
  const lines = ['', 'PARI PARI failed', '──────────────', `Reason: ${reason}`];
  if (detail) {
    lines.push('', detail);
  }
  lines.push('', 'No source code was uploaded. Scanning is local.');
  return `${title}\n${lines.join('\n')}`;
}

export interface StatusInput {
  /** Which front-end is reporting. */
  surface: 'cli' | 'extension';
  /** Working directory (CLI) or workspace folder (extension). */
  workspaceRoot?: string;
  lastScan?: ScanResult;
  risk?: RiskSummary;
  settings: { serverUrl: string; projectId: string; enableTelemetry: boolean; writeResultsToWorkspace: boolean };
  version: string;
  /** Result of an optional backend health check. */
  backend?: string;
}

export function renderStatus(input: StatusInput): string {
  const isCli = input.surface === 'cli';
  const location = isCli
    ? `Working directory:    ${input.workspaceRoot ?? 'unknown'}`
    : `Workspace:            ${input.workspaceRoot ?? 'none (open a folder to scan)'}`;
  const host = isCli ? `Host:                ${process.platform} (node ${process.versions.node})` : '';

  const lines = [
    `PARI PARI Terminal v${input.version}`,
    '',
    location,
    host,
    'Mode:                 local-first (no network unless synchronisation is enabled)',
    '',
    'Settings:',
    `  serverUrl:            ${input.settings.serverUrl || '(not set — local only)'}`,
    `  projectId:            ${input.settings.projectId || '(not set)'}`,
    `  enableTelemetry:      ${input.settings.enableTelemetry ? 'on' : 'off'}`,
    `  writeResults:         ${input.settings.writeResultsToWorkspace ? 'on' : 'off'}`,
    '',
  ];

  if (input.lastScan && input.risk) {
    lines.push('Last scan:');
    lines.push(`  id:        ${input.lastScan.scanId}`);
    lines.push(`  scope:     ${input.lastScan.mode} (${input.lastScan.rootLabel})`);
    lines.push(`  files:     ${input.lastScan.stats.filesScanned}`);
    lines.push(`  assets:    ${input.risk.total}`);
    lines.push(`  high/med:  ${input.risk.high} / ${input.risk.medium}`);
    lines.push(`  duration:  ${input.lastScan.stats.durationMs} ms`);
    lines.push(`  cancelled: ${input.lastScan.cancelled ? 'yes' : 'no'}`);
    lines.push('');
    lines.push('Preliminary static-analysis result.');
  } else {
    lines.push(isCli ? 'No stored scan found. Run: periperi scan' : 'No scan has been run yet. Try: PARI PARI: Scan Workspace');
  }

  if (input.backend) {
    lines.push('');
    lines.push(`Backend: ${input.backend}`);
  } else if (!input.settings.serverUrl) {
    lines.push('');
    lines.push('Backend: not configured — everything stays on this machine.');
  }

  return lines.join('\n');
}

/** One-line-per-finding listing used by `periperi scan --quiet`. */
export function renderFindings(result: ScanResult, limit = 50): string {
  if (result.detections.length === 0) {
    return 'No cryptographic indicators detected.';
  }
  const lines = result.detections.slice(0, limit).map((d) => {
    const where = d.line > 0 ? `${d.file}:${d.line}` : d.file;
    const size = typeof d.keySize === 'number' ? ` (${d.keySize}-bit)` : '';
    return `  ${d.risk.padEnd(8)} ${d.algorithm}${size} — ${where}`;
  });
  if (result.detections.length > limit) {
    lines.push(`  … and ${result.detections.length - limit} more`);
  }
  return lines.join('\n');
}
