import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

/**
 * These tests drive the real `dist/cli/periperi.js` the same way a user or a CI
 * job would, so they cover argument parsing, the exit-code contract and the
 * files actually written to disk. The bundle is built once in `beforeAll`.
 */
const projectRoot = path.resolve(__dirname, '..');
const cliPath = path.join(projectRoot, 'dist', 'cli', 'periperi.js');

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
  /** Failures and usage errors are reported on stderr, results on stdout. */
  output: string;
}

function run(args: string[], cwd: string, env: NodeJS.ProcessEnv = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [cliPath, ...args],
      { cwd, env: { ...process.env, ...env }, maxBuffer: 32 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error && typeof error.code !== 'number') {
          reject(error);
          return;
        }
        const code = typeof error?.code === 'number' ? error.code : 0;
        resolve({
          code,
          stdout,
          stderr,
          output: `${stdout}${stderr}`,
        });
      },
    );
  });
}

/** A small project with real cryptographic indicators. */
function fixture(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'pari-cli-'));
  mkdirSync(path.join(dir, 'src'), { recursive: true });
  writeFileSync(
    path.join(dir, 'src', 'auth.ts'),
    'import crypto from "node:crypto";\n' +
      'export const h = (p: string) => crypto.createHash("sha256").update(p).digest("hex");\n',
    'utf8',
  );
  writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: 'fixture', dependencies: { bcrypt: '^5.1.0' } }, null, 2),
    'utf8',
  );
  return dir;
}

function scanJson(result: RunResult): Record<string, never> & {
  summary: { total: number; critical: number; high: number; medium: number; low: number; info: number };
  stats: { filesDiscovered: number; filesScanned: number };
  detections: { id: string; file: string; algorithm: string }[];
} {
  return JSON.parse(result.stdout) as never;
}

beforeAll(() => {
  if (!existsSync(cliPath)) {
    throw new Error(`Missing ${cliPath}. Run "npm run build" before the tests.`);
  }
}, 60_000);

describe('periperi --version and help', () => {
  it('prints a version', async () => {
    const result = await run(['--version'], tmpdir());
    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/periperi \d+\.\d+\.\d+/);
  });

  it('lists every advertised command', async () => {
    const result = await run(['help'], tmpdir());
    expect(result.code).toBe(0);
    for (const command of [
      'scan',
      'cbom',
      'export',
      'report',
      'risk',
      'status',
      'sync',
      'clear',
      'help',
    ]) {
      expect(result.stdout).toContain(`periperi ${command}`);
    }
  });
});

describe('periperi scan', () => {
  it('finds the crypto indicators in a fixture', async () => {
    const dir = fixture();
    const result = await run(['scan', '--json'], dir);
    expect(result.code).toBe(0);

    const json = scanJson(result);
    expect(json.summary.total).toBeGreaterThan(0);
    expect(json.stats.filesScanned).toBe(2);
    expect(json.detections.map((d) => d.file)).toContain('src/auth.ts');
  });

  it('emits nothing but JSON on stdout so it can be piped', async () => {
    const dir = fixture();
    const result = await run(['scan', '--json'], dir);
    // The banner and progress lines are suppressed in machine mode; if they
    // ever come back this parse throws.
    expect(() => JSON.parse(result.stdout)).not.toThrow();
    expect(result.stdout.trimStart().startsWith('{')).toBe(true);
  });

  it('emits a valid SARIF document with the declared schema', async () => {
    const dir = fixture();
    const result = await run(['scan', '--sarif'], dir);
    const sarif = JSON.parse(result.stdout) as {
      version: string;
      $schema: string;
      runs: { results: { ruleId: string }[] }[];
    };

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif');
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
    for (const entry of sarif.runs[0].results) {
      expect(entry.ruleId).toMatch(/^PERIPERI\//);
    }
  });

  it('gives every detection a stable, unique id', async () => {
    const dir = fixture();
    const ids = scanJson(await run(['scan', '--json'], dir)).detections.map((d) => d.id);
    expect(ids.every((id) => /^PARI-\d{4}$/.test(id))).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('exits 3 when findings reach --fail-on', async () => {
    const dir = fixture();
    const result = await run(['scan', '--quiet', '--fail-on', 'low'], dir);
    expect(result.code).toBe(3);
  });

  it('exits 0 when findings stay below --fail-on', async () => {
    const dir = fixture();
    const result = await run(['scan', '--quiet', '--fail-on', 'critical'], dir);
    expect(result.code).toBe(0);
  });

  it('exits 2 on an unknown --fail-on value', async () => {
    const dir = fixture();
    const result = await run(['scan', '--fail-on', 'catastrophic'], dir);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('catastrophic');
  });

  it('exits 2 for an unknown command and suggests help', async () => {
    const result = await run(['frobnicate'], tmpdir());
    expect(result.code).toBe(2);
    expect(result.stdout).toContain('help');
  });

  it('never re-reads its own .pari-pari output on a second run', async () => {
    const dir = fixture();
    const first = scanJson(await run(['scan', '--json'], dir)).summary.total;
    const second = scanJson(await run(['scan', '--json'], dir)).summary.total;
    const third = scanJson(await run(['scan', '--json'], dir)).summary.total;
    expect(second).toBe(first);
    expect(third).toBe(first);
  });

  it('writes nothing when --no-write is set', async () => {
    const dir = fixture();
    await run(['scan', '--no-write', '--json'], dir);
    expect(existsSync(path.join(dir, '.pari-pari'))).toBe(false);
  });

  it('honours --max-files', async () => {
    const dir = fixture();
    const json = scanJson(await run(['scan', '--json', '--max-files', '1'], dir));
    expect(json.stats.filesScanned).toBe(1);
  });

  it('reads max-files from a .periperirc file', async () => {
    const dir = fixture();
    writeFileSync(path.join(dir, '.periperirc'), 'max-files = 1\n', 'utf8');
    const json = scanJson(await run(['scan', '--json'], dir));
    expect(json.stats.filesScanned).toBe(1);
  });

  it('lets a flag override the rc file', async () => {
    const dir = fixture();
    writeFileSync(path.join(dir, '.periperirc'), 'max-files = 1\n', 'utf8');
    const json = scanJson(await run(['scan', '--json', '--max-files', '5'], dir));
    expect(json.stats.filesScanned).toBe(2);
  });

  it('lets the environment override the rc file', async () => {
    const dir = fixture();
    writeFileSync(path.join(dir, '.periperirc'), 'max-files = 1\n', 'utf8');
    const json = scanJson(await run(['scan', '--json'], dir, { PERIPERI_MAX_FILES: '5' }));
    expect(json.stats.filesScanned).toBe(2);
  });

  it('stays local unless a server is configured', async () => {
    const dir = fixture();
    await run(['scan', '--json'], dir);
    const sync = await run(['sync', '--dry-run'], dir);
    expect(sync.code).toBe(1);
    expect(sync.stderr).toContain('No ECDAT server configured');
  });
});

describe('periperi cbom, report and status', () => {
  it('writes a JSON and a CSV CBOM under .pari-pari/cbom', async () => {
    const dir = fixture();
    const result = await run(['cbom'], dir);
    expect(result.code).toBe(0);

    const files = readdirSync(path.join(dir, '.pari-pari', 'cbom'));
    expect(files.some((f) => f.endsWith('.json'))).toBe(true);
    expect(files.some((f) => f.endsWith('.csv'))).toBe(true);

    const json = JSON.parse(
      readFileSync(path.join(dir, '.pari-pari', 'cbom', files.find((f) => f.endsWith('.json'))!), 'utf8'),
    ) as { assets: unknown[] };
    expect(Array.isArray(json.assets)).toBe(true);
    expect(json.assets.length).toBeGreaterThan(0);
  });

  it('writes a self-contained HTML report', async () => {
    const dir = fixture();
    await run(['cbom'], dir);
    const result = await run(['report', '--html'], dir);
    expect(result.code).toBe(0);

    const reports = readdirSync(path.join(dir, '.pari-pari', 'reports'));
    const file = reports.find((f) => f.endsWith('.html'))!;
    const html = readFileSync(path.join(dir, '.pari-pari', 'reports', file), 'utf8');

    expect(html.toLowerCase()).toContain('<!doctype html>');
    expect(html).toContain("default-src 'none'");
    expect(html).toContain('nonce=');
  });

  it('reports no stored scan with a non-zero exit and a clear message', async () => {
    const dir = fixture();
    const result = await run(['report'], dir);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('No stored scan found');
  });
});

describe('exit codes', () => {
  it('returns 1 when a report is asked for before any scan', async () => {
    expect((await run(['report'], fixture())).code).toBe(1);
  });

  it('returns 1 when risk is asked for before any scan', async () => {
    expect((await run(['risk'], fixture())).code).toBe(1);
  });

  it('returns 1 for a path that does not exist', async () => {
    expect((await run(['scan', './definitely-not-here'], fixture())).code).toBe(1);
  });

  it('returns 1 for a --file that does not exist', async () => {
    expect((await run(['scan', '--file', 'missing.ts'], fixture())).code).toBe(1);
  });

  it('returns 1 when sync is attempted with no server configured', async () => {
    expect((await run(['sync'], fixture())).code).toBe(1);
  });

  it('returns 0 for help and version', async () => {
    expect((await run(['help'], tmpdir())).code).toBe(0);
    expect((await run(['--version'], tmpdir())).code).toBe(0);
  });
});

describe('periperi export and clear', () => {
  it('exports the latest scan straight into an explicit directory', async () => {
    const dir = fixture();
    await run(['cbom'], dir);
    const result = await run(['export', '--format', 'json', '--to', 'out'], dir);
    expect(result.code).toBe(0);

    const files = readdirSync(path.join(dir, 'out'));
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/\.json$/);
  });

  it('rejects an unknown --format', async () => {
    const dir = fixture();
    await run(['cbom'], dir);
    const result = await run(['export', '--format', 'yaml'], dir);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('yaml');
  });

  it('reports a bad --format as a usage error even with no stored scan', async () => {
    const result = await run(['export', '--format', 'yaml'], fixture());
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('yaml');
  });

  it('clears the stored results', async () => {
    const dir = fixture();
    await run(['cbom'], dir);
    expect(existsSync(path.join(dir, '.pari-pari', 'cbom'))).toBe(true);

    const result = await run(['clear'], dir);
    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/Cleared/);

    const report = await run(['report'], dir);
    expect(report.code).toBe(1);
  });
});
