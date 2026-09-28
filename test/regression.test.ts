import { describe, expect, it } from 'vitest';

import { summarizeRisk, rollupAssets } from '../src/scanner/scanner';
import { exceedsThreshold } from '../src/core/resultJson';
import type { Detection, RiskLevel, ScanResult } from '../src/scanner/types';
import { columnFromIndex, redactContext } from '../src/utils/redact';

function detection(risk: RiskLevel, overrides: Partial<Detection> = {}): Detection {
  return {
    id: '',
    algorithm: 'AES',
    assetType: 'cryptographic_algorithm',
    file: 'src/a.ts',
    line: 1,
    column: 1,
    context: 'crypto.createCipheriv(...)',
    sourceType: 'source',
    detectionMethod: 'PATTERN_MATCH',
    confidence: 'HIGH',
    risk,
    rationale: 'test',
    ...overrides,
  } as Detection;
}

/**
 * `rollupAssets` takes a whole `ScanResult` and also folds in the discovered
 * library and protocol entities, so those arrays must exist here too.
 */
function scanResult(detections: Detection[]): ScanResult {
  return { detections, libraries: [], protocols: [] } as unknown as ScanResult;
}

describe('summarizeRisk', () => {
  it('counts every severity and totals them', () => {
    const summary = summarizeRisk([
      detection('CRITICAL'),
      detection('HIGH'),
      detection('HIGH'),
      detection('LOW'),
    ]);

    expect(summary).toEqual({ total: 4, critical: 1, high: 2, medium: 0, low: 1, info: 0 });
  });

  it('reports zeroes for an empty scan rather than undefined', () => {
    expect(summarizeRisk([])).toEqual({
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });
  });
});

describe('exceedsThreshold', () => {
  const risk = { total: 3, critical: 0, high: 1, medium: 2, low: 0, info: 0 };

  it('trips when a finding is at or above the threshold', () => {
    expect(exceedsThreshold(risk, 'high')).toBe(true);
    expect(exceedsThreshold(risk, 'medium')).toBe(true);
  });

  it('stays quiet when everything is below the threshold', () => {
    expect(exceedsThreshold(risk, 'critical')).toBe(false);
  });

  it('treats a clean scan as passing any threshold', () => {
    const clean = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    expect(exceedsThreshold(clean, 'info')).toBe(false);
  });
});

describe('rollupAssets', () => {
  it('deduplicates and sorts the rollup lists', () => {
    const rollup = rollupAssets(
      scanResult([
        detection('MEDIUM', { algorithm: 'SHA-256' }),
        detection('LOW', { algorithm: 'AES' }),
        detection('LOW', { algorithm: 'AES' }),
      ]),
    );

    expect(rollup.algorithms).toEqual(['AES', 'SHA-256']);
  });

  it('collects libraries and protocols separately from algorithms', () => {
    const rollup = rollupAssets(
      scanResult([
        detection('LOW', { assetType: 'cryptographic_library', algorithm: 'JWT libraries' }),
        detection('LOW', { assetType: 'protocol', algorithm: 'TLS' }),
      ]),
    );

    expect(rollup.libraries).toEqual(['JWT libraries']);
    expect(rollup.protocols).toEqual(['TLS']);
  });
});

describe('redactContext', () => {
  it('redacts a secret assignment', () => {
    const output = redactContext('const password = "hunter2hunter2";');
    expect(output).not.toContain('hunter2hunter2');
    expect(output).toContain('password');
  });

  it('redacts bearer tokens', () => {
    expect(redactContext('Authorization: Bearer abcdef1234567890')).not.toContain('abcdef1234567890');
  });

  it('redacts credentials embedded in a URL', () => {
    const output = redactContext('https://user:pass@host/path');
    expect(output).not.toContain('user:pass@');
  });

  it('leaves harmless text untouched', () => {
    expect(redactContext('const cipher = crypto.createCipheriv();')).toBe(
      'const cipher = crypto.createCipheriv();',
    );
  });
});

describe('columnFromIndex', () => {
  it('converts a 0-based index to a 1-based column', () => {
    expect(columnFromIndex('abcdef', 0)).toBe(1);
    expect(columnFromIndex('abcdef', 5)).toBe(6);
  });
});
