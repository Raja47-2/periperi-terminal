/**
 * CBOM exporters (JSON + CSV) and workspace storage.
 *
 * All writes go through `safeResolveInside`, so a crafted scan id or file name
 * can never escape the `.pari-pari/` directory.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';

import type { Cbom } from './types';
import type { ScanResult } from '../scanner/types';
import { safeResolveInside, ensureDir } from '../utils/paths';
import { logger } from '../utils/log';
import { UserFacingError } from '../utils/errors';

export const PARI_DIR = '.pari-pari';

export interface StorageLayout {
  base: string;
  scans: string;
  cbom: string;
  reports: string;
}

export function storageLayout(workspaceRoot: string): StorageLayout {
  const base = safeResolveInside(workspaceRoot, PARI_DIR);
  return {
    base,
    scans: safeResolveInside(base, 'scans'),
    cbom: safeResolveInside(base, 'cbom'),
    reports: safeResolveInside(base, 'reports'),
  };
}

export function ensureStorage(workspaceRoot: string): StorageLayout {
  const layout = storageLayout(workspaceRoot);
  ensureDir(layout.base);
  ensureDir(layout.scans);
  ensureDir(layout.cbom);
  ensureDir(layout.reports);
  return layout;
}

/** Writes are confined to `baseDir` and the file name is sanitised. */
function safeTarget(baseDir: string, fileName: string): string {
  const clean = fileName.replace(/[^\w.-]/g, '_');
  if (!clean || clean.startsWith('..')) {
    throw new UserFacingError('Refused to write an unsafe file name.');
  }
  return safeResolveInside(baseDir, clean);
}

export function toJson(cbom: Cbom): string {
  return `${JSON.stringify(cbom, null, 2)}\n`;
}

const CSV_HEADER = [
  'asset_id',
  'type',
  'algorithm',
  'key_size',
  'library',
  'file',
  'line',
  'column',
  'confidence',
  'risk',
  'source_type',
  'detection_method',
  'context',
] as const;

function csvEscape(value: string | number | undefined): string {
  const text = value === undefined || value === null ? '' : String(value);
  if (/[",\n\r]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

export function toCsv(cbom: Cbom): string {
  const rows: string[] = [CSV_HEADER.join(',')];
  for (const asset of cbom.assets) {
    rows.push(
      [
        asset.asset_id,
        asset.type,
        asset.algorithm,
        asset.key_size,
        asset.library,
        asset.file,
        asset.line,
        asset.column,
        asset.confidence,
        asset.risk,
        asset.source_type,
        asset.detection_method,
        asset.context,
      ]
        .map(csvEscape)
        .join(','),
    );
  }
  return `${rows.join('\r\n')}\r\n`;
}

export interface ExportResult {
  jsonPath?: string;
  csvPath?: string;
  scanPath?: string;
}

export interface ExportOptions {
  workspaceRoot?: string;
  /**
   * Explicit destination directory. Files are written straight into it instead
   * of under `<workspaceRoot>/.pari-pari/`, and the raw scan is not rewritten.
   */
  outputDir?: string;
  cbom: Cbom;
  scan?: ScanResult;
  formats?: { json?: boolean; csv?: boolean };
}

/**
 * Persist the CBOM.
 * - Without `workspaceRoot` or `outputDir` the caller is expected to use a save dialog.
 * - With `workspaceRoot` files land under `.pari-pari/`.
 * - With `outputDir` files land directly in that directory.
 */
export async function exportCbom(options: ExportOptions): Promise<ExportResult> {
  const { cbom, scan, outputDir } = options;
  const formats = { json: true, csv: true, ...options.formats };
  const result: ExportResult = {};
  const stamp = cbom.scan_id;

  if (outputDir) {
    await fs.mkdir(outputDir, { recursive: true });
    if (formats.json) {
      const target = safeTarget(outputDir, `cbom-${stamp}.json`);
      await fs.writeFile(target, toJson(cbom), 'utf8');
      result.jsonPath = target;
    }
    if (formats.csv) {
      const target = safeTarget(outputDir, `cbom-${stamp}.csv`);
      await fs.writeFile(target, toCsv(cbom), 'utf8');
      result.csvPath = target;
    }
    logger.info(`CBOM exported to ${outputDir}: json=${result.jsonPath ?? '-'} csv=${result.csvPath ?? '-'}`);
    return result;
  }

  if (scan) {
    result.scanPath = await writeScan(scan, options.workspaceRoot);
  }

  if (options.workspaceRoot) {
    const layout = ensureStorage(options.workspaceRoot);
    if (formats.json) {
      const target = safeTarget(layout.cbom, `cbom-${stamp}.json`);
      await fs.writeFile(target, toJson(cbom), 'utf8');
      result.jsonPath = target;
    }
    if (formats.csv) {
      const target = safeTarget(layout.cbom, `cbom-${stamp}.csv`);
      await fs.writeFile(target, toCsv(cbom), 'utf8');
      result.csvPath = target;
    }
  }

  logger.info(
    `CBOM exported: json=${result.jsonPath ?? '-'} csv=${result.csvPath ?? '-'}`,
  );
  return result;
}

export async function writeScan(scan: ScanResult, workspaceRoot?: string): Promise<string | undefined> {
  if (!workspaceRoot) {
    return undefined;
  }
  const layout = ensureStorage(workspaceRoot);
  const target = safeTarget(layout.scans, `scan-${scan.scanId}.json`);
  await fs.writeFile(target, `${JSON.stringify(scan, null, 2)}\n`, 'utf8');
  return target;
}

/** Content written to an arbitrary destination chosen through a save dialog. */
export function renderExport(cbom: Cbom, format: 'json' | 'csv'): string {
  return format === 'json' ? toJson(cbom) : toCsv(cbom);
}

export async function readLatestScan(workspaceRoot: string): Promise<ScanResult | undefined> {
  const layout = storageLayout(workspaceRoot);
  try {
    const entries = (await fs.readdir(layout.scans)).filter((n) => n.startsWith('scan-'));
    if (entries.length === 0) {
      return undefined;
    }
    entries.sort();
    const latest = entries[entries.length - 1];
    const raw = await fs.readFile(path.join(layout.scans, latest), 'utf8');
    return JSON.parse(raw) as ScanResult;
  } catch {
    return undefined;
  }
}
