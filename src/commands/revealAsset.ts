import type { PariContext } from './context';
import { revealLocation } from '../ui/dashboard';

/**
 * `PARI PARI: Reveal Cryptographic Asset`.
 * Called from the tree view, the dashboard and diagnostics; opens the exact
 * `file:line:column`.
 */
export async function revealAsset(
  file?: string,
  line?: number,
  column?: number,
): Promise<void> {
  if (!file) {
    return;
  }
  await revealLocation(file, line ?? 1, column ?? 1);
}

/** Opens the dedicated PARI PARI terminal (never replaces an existing one). */
export async function openTerminal(ctx: PariContext): Promise<void> {
  await ctx.terminal.ensureTerminal();
  ctx.output.appendLine('[INFO] PARI PARI terminal opened');
}
