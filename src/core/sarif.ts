/**
 * SARIF 2.1.0 export.
 *
 * Lets `periperi scan --sarif` feed GitHub code scanning, Azure DevOps and any
 * other SARIF consumer without a translation step.
 *
 * Rule ids reuse the CBOM asset ids (`PARI-0001`, …) so a SARIF result and a
 * CBOM asset refer to the same finding.
 *
 * Free of any `vscode` import.
 */

import type { Detection, RiskLevel, ScanResult } from '../scanner/types';
import { assetId } from '../utils/id';
import { EXTENSION_VERSION } from '../version';
import { RISK_ORDER, TOOL_NAME } from './resultJson';

export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
export const SARIF_VERSION = '2.1.0';

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

const LEVEL_BY_RISK: Record<RiskLevel, SarifLevel> = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'note',
  INFO: 'note',
};

export const SECURITY_TAGS = ['security', 'cryptography', 'cbom', 'static-analysis'];

function ruleIdFor(prefix: string, index: number): string {
  return `${prefix}/${assetId(index)}`;
}

function artifactUri(file: string): string {
  return file.replace(/\\/g, '/');
}

function resultMessage(detection: Detection): string {
  const parts = [`Detected ${detection.algorithm}`];
  if (detection.library) {
    parts.push(`via ${detection.library}`);
  }
  if (typeof detection.keySize === 'number') {
    parts.push(`(${detection.keySize}-bit)`);
  }
  parts.push(`at ${artifactUri(detection.file)}:${detection.line}`);
  const suffix = detection.rationale ? ` — ${detection.rationale}` : '';
  return `${parts.join(' ')}.${suffix}`;
}

export interface SarifOptions {
  /** Included as `runs[0].automationDetails.id`. */
  projectName?: string;
  /** Rule id prefix. Defaults to `PERIPERI`. */
  rulePrefix?: string;
}

export function toSarif(result: ScanResult, options: SarifOptions = {}): Record<string, unknown> {
  const prefix = options.rulePrefix ?? 'PERIPERI';
  const rules = result.detections.map((detection, index) => ({
    id: ruleIdFor(prefix, index),
    name: detection.algorithm,
    shortDescription: { text: `${detection.algorithm} usage` },
    fullDescription: { text: resultMessage(detection) },
    defaultConfiguration: { level: LEVEL_BY_RISK[detection.risk] },
    help: { text: detection.rationale ?? `Detected ${detection.assetType.replace(/_/g, ' ')}.` },
    properties: {
      risk: detection.risk,
      confidence: detection.confidence,
      assetType: detection.assetType,
      detectionMethod: detection.detectionMethod,
      tags: [...SECURITY_TAGS],
    },
  }));

  const results = result.detections.map((detection, index) => {
    const entry: Record<string, unknown> = {
      ruleId: ruleIdFor(prefix, index),
      level: LEVEL_BY_RISK[detection.risk],
      message: { text: resultMessage(detection) },
      partialFingerprints: { periperiAssetId: assetId(index) },
      properties: {
        risk: detection.risk,
        confidence: detection.confidence,
        assetType: detection.assetType,
        detectionMethod: detection.detectionMethod,
        sourceType: detection.sourceType,
      },
    };

    if (detection.line > 0) {
      const physical: Record<string, unknown> = {
        artifactLocation: { uri: artifactUri(detection.file) },
        region: { startLine: detection.line },
      };
      if (detection.column > 0) {
        (physical.region as Record<string, unknown>).startColumn = detection.column;
      }
      entry.locations = [{ physicalLocation: physical }];
    } else {
      entry.locations = [
        { physicalLocation: { artifactLocation: { uri: artifactUri(detection.file) } } },
      ];
    }

    return entry;
  });

  const worst = result.detections.reduce<RiskLevel | undefined>((acc, detection) => {
    if (!acc || RISK_ORDER[detection.risk] < RISK_ORDER[acc]) {
      return detection.risk;
    }
    return acc;
  }, undefined);

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: EXTENSION_VERSION,
            informationUri: 'https://github.com/pari-pari/pari-pari-terminal',
            rules,
          },
        },
        automationDetails: { id: options.projectName ?? result.rootLabel },
        invocations: [
          {
            executionSuccessful: !result.cancelled,
            startTimeUtc: result.startedAt,
            endTimeUtc: result.completedAt,
            properties: { cancelled: result.cancelled },
          },
        ],
        properties: {
          scanId: result.scanId,
          mode: result.mode,
          scope: 'local-static-analysis',
          worstRisk: worst ?? null,
          privateKeyFiles: result.privateKeyFiles,
          filesScanned: result.stats.filesScanned,
          filesDiscovered: result.stats.filesDiscovered,
        },
        results,
      },
    ],
  };
}

export function renderSarif(result: ScanResult, options: SarifOptions = {}): string {
  return `${JSON.stringify(toSarif(result, options), null, 2)}\n`;
}
