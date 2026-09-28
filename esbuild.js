//@ts-check
'use strict';

const esbuild = require('esbuild');

const watch = process.argv.includes('--watch');
const production = process.argv.includes('--production') || process.env.NODE_ENV === 'production';

const shared = {
  bundle: true,
  format: 'cjs',
  platform: 'node',
  target: 'node20',
  logLevel: 'info',
  sourcemap: !production,
  minify: production,
  legalComments: 'none',
};

/** @type {esbuild.BuildOptions} */
const extensionConfig = {
  ...shared,
  entryPoints: ['src/extension.ts'],
  outfile: 'dist/extension.js',
  external: ['vscode'],
};

// The `periperi` CLI is a standalone Node script, published to npm as a bin and
// injected onto the PATH of the extension's dedicated terminal. It must not
// depend on the extension bundle or on the `vscode` module — note the absence
// of `external: ['vscode']`, which makes the build fail loudly if that ever
// changes. The shebang is prepended here rather than committed in the source.
const cliConfig = {
  ...shared,
  entryPoints: ['src/cli/periperi.ts'],
  outfile: 'dist/cli/periperi.js',
  banner: { js: '#!/usr/bin/env node' },
};

/** esbuild refuses `chmod` while bundling, so set the bit after the build. */
function makeExecutable(file) {
  if (process.platform === 'win32') {
    return;
  }
  try {
    require('node:fs').chmodSync(file, 0o755);
  } catch {
    /* non-fatal: npm sets the bit on the bin shim during install anyway */
  }
}

async function main() {
  if (watch) {
    const ctx1 = await esbuild.context(extensionConfig);
    const ctx2 = await esbuild.context(cliConfig);
    await Promise.all([ctx1.watch(), ctx2.watch()]);
    console.log('[esbuild] watching…');
    return;
  }

  await Promise.all([esbuild.build(extensionConfig), esbuild.build(cliConfig)]);
  makeExecutable(cliConfig.outfile);
  console.log('[esbuild] build complete');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
