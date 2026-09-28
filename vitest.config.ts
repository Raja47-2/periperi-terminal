import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    reporters: ['default'],
    testTimeout: 30000,
  },
  resolve: {
    alias: {
      // The scanner and CBOM layers are pure Node code. Tests that touch the
      // presentation layer load a minimal `vscode` stub instead of the real API.
      vscode: path.resolve(__dirname, 'test/stubs/vscode.ts'),
    },
  },
});
