import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  DEFAULT_SETTINGS,
  ENV_PREFIX,
  RC_FILENAMES,
  loadRcFile,
  parseRcText,
  resolveSettings,
} from '../src/core/config';
import { isThreshold } from '../src/core/resultJson';
import { toCsv, toJson } from '../src/cbom/cbomExporter';

function workspace(prefix: string): string {
  return mkdtempSync(path.join(tmpdir(), prefix));
}

describe('parseRcText', () => {
  it('reads key = value pairs', () => {
    expect(parseRcText('max-files = 1')).toMatchObject({ maxFiles: 1 });
  });

  it('exposes kebab, camel and snake aliases of the same key', () => {
    const parsed = parseRcText('max-file-size = 2048');
    expect(parsed).toMatchObject({ 'max-file-size': 2048, maxFileSize: 2048, max_file_size: 2048 });
  });

  it('ignores comments and blank lines', () => {
    expect(parseRcText('# comment\n\n; another\nmax-files = 2\n')).toMatchObject({ maxFiles: 2 });
  });

  it('strips surrounding quotes', () => {
    expect(parseRcText('server-url = "https://example.test"')).toMatchObject({
      serverUrl: 'https://example.test',
    });
  });

  it('coerces booleans', () => {
    expect(parseRcText('write-results-to-workspace = false')).toMatchObject({
      writeResultsToWorkspace: false,
    });
  });

  it('returns undefined when there is nothing to read', () => {
    expect(parseRcText('')).toBeUndefined();
    expect(parseRcText('# only a comment\n')).toBeUndefined();
  });
});

describe('loadRcFile', () => {
  it('reads .periperirc as plain text', () => {
    const dir = workspace('pari-rc-');
    writeFileSync(path.join(dir, RC_FILENAMES[0]), 'max-files = 1\n', 'utf8');
    expect(loadRcFile(dir, dir)).toMatchObject({ maxFiles: 1 });
  });

  it('reads JSON written into an rc file whose name has no .json extension', () => {
    const dir = workspace('pari-rc-');
    writeFileSync(path.join(dir, '.pari-parirc'), '{"maxFiles": 3}', 'utf8');
    expect(loadRcFile(dir, dir)).toMatchObject({ maxFiles: 3 });
  });

  it('strips a UTF-8 BOM, which JSON.parse rejects', () => {
    const dir = workspace('pari-rc-');
    writeFileSync(path.join(dir, '.pari-parirc'), '\ufeff{"maxFiles": 4}', 'utf8');
    expect(loadRcFile(dir, dir)).toMatchObject({ maxFiles: 4 });
  });

  it('ignores a malformed file instead of throwing', () => {
    const dir = workspace('pari-rc-');
    writeFileSync(path.join(dir, '.periperirc.json'), '{ not valid json ][', 'utf8');
    expect(() => loadRcFile(dir, dir)).not.toThrow();
    expect(loadRcFile(dir, dir)).toEqual({});
  });

  it('returns no overrides when the directory holds no rc file', () => {
    const dir = workspace('pari-rc-');
    expect(loadRcFile(dir, dir)).toEqual({});
  });
});

describe('resolveSettings', () => {
  it('falls back to the defaults', () => {
    const settings = resolveSettings({ cwd: workspace('pari-set-'), env: {} });
    expect(settings.maxFiles).toBe(DEFAULT_SETTINGS.maxFiles);
    expect(settings.serverUrl).toBe('');
  });

  it('excludes PARI PARI output so a scan never re-reads its own CBOM', () => {
    expect(DEFAULT_SETTINGS.scanExclude).toContain('.pari-pari');
  });

  it('prefers a flag over the environment, the rc file and the default', () => {
    const dir = workspace('pari-set-');
    writeFileSync(path.join(dir, '.periperirc'), 'max-files = 1\n', 'utf8');

    const settings = resolveSettings({
      cwd: dir,
      home: dir,
      flags: { 'max-files': '7' },
      env: { [`${ENV_PREFIX}MAX_FILES`]: '5' },
    });

    expect(settings.maxFiles).toBe(7);
  });

  it('prefers the environment over the rc file', () => {
    const dir = workspace('pari-set-');
    writeFileSync(path.join(dir, '.periperirc'), 'max-files = 1\n', 'utf8');

    const settings = resolveSettings({
      cwd: dir,
      home: dir,
      env: { [`${ENV_PREFIX}MAX_FILES`]: '5' },
    });

    expect(settings.maxFiles).toBe(5);
  });

  it('reads the server URL and API key from the environment', () => {
    const settings = resolveSettings({
      cwd: workspace('pari-set-'),
      env: {
        [`${ENV_PREFIX}SERVER_URL`]: 'https://ecdat.example.test',
        [`${ENV_PREFIX}API_KEY`]: 'secret-key',
      },
    });

    expect(settings.serverUrl).toBe('https://ecdat.example.test');
    expect(settings.apiKey).toBe('secret-key');
  });
});

describe('isThreshold', () => {
  it('accepts the documented severities plus none', () => {
    for (const value of ['critical', 'high', 'medium', 'low', 'info', 'none']) {
      expect(isThreshold(value)).toBe(true);
    }
  });

  it('rejects anything else', () => {
    expect(isThreshold('nope')).toBe(false);
    expect(isThreshold('')).toBe(false);
  });
});

describe('serialisation helpers', () => {
  it('exposes JSON and CSV writers for the CBOM', () => {
    expect(typeof toJson).toBe('function');
    expect(typeof toCsv).toBe('function');
  });

  it('escapes CSV values that contain separators or quotes', () => {
    const csv = toCsv({
      scan_id: 'SCAN-1',
      generated_at: '2026-01-01T00:00:00Z',
      tool: { name: 'periperi', version: '0.1.0' },
      project: 'demo',
      assets: [
        {
          asset_id: 'PARI-0001',
          type: 'algorithm',
          algorithm: 'AES, GCM',
          file: 'src/a.ts',
          line: 3,
          risk: 'MEDIUM',
          source_type: 'source',
        },
      ],
    } as never);

    expect(csv).toContain('"AES, GCM"');
  });
});
