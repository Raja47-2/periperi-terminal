/**
 * In-memory result store.
 *
 * Holds at most the most recent scan + its CBOM, refreshed by every scan
 * command. Persistence is handled separately by `cbom/cbomExporter.ts`.
 */

import type { Cbom } from './cbom/types';
import type { ScanResult } from './scanner/types';
import { generateCbom } from './cbom/cbomGenerator';
import { summarizeRisk, type RiskSummary } from './scanner/scanner';

export interface ScanState {
  result: ScanResult;
  cbom: Cbom;
}

type Listener = (state: ScanState | undefined) => void;

export class ResultStore {
  private current: ScanState | undefined;
  private readonly listeners = new Set<Listener>();

  set(result: ScanResult, options: { project?: string; projectVersion?: string } = {}): ScanState {
    const cbom = generateCbom(result, options);
    const state: ScanState = { result, cbom };
    this.current = state;
    for (const listener of this.listeners) {
      try {
        listener(state);
      } catch {
        /* a broken listener must not break a scan */
      }
    }
    return state;
  }

  get(): ScanState | undefined {
    return this.current;
  }

  require(): ScanState {
    if (!this.current) {
      throw new Error('NO_SCAN');
    }
    return this.current;
  }

  risk(): RiskSummary | undefined {
    return this.current ? summarizeRisk(this.current.result.detections) : undefined;
  }

  clear(): void {
    this.current = undefined;
    for (const listener of this.listeners) {
      listener(undefined);
    }
  }

  subscribe(listener: Listener): { dispose(): void } {
    this.listeners.add(listener);
    return {
      dispose: () => {
        this.listeners.delete(listener);
      },
    };
  }
}

export const results = new ResultStore();
