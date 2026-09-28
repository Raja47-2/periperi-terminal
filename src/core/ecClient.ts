/**
 * PARI PARI ECDAT backend client.
 *
 * Extracted from `services/pariPariService.ts` so the CLI can sync without VS
 * Code. The client is inert by default: with no `serverUrl` it refuses to do
 * anything and reports why.
 *
 * Security contract:
 *   - nothing is uploaded unless the caller explicitly invokes `syncScan`,
 *   - the payload is a CBOM (metadata + file/line locations), never file bodies,
 *   - credentials are read from the caller's config and never logged.
 */

import type { Cbom } from '../cbom/types';
import { logger } from '../utils/log';

export interface SyncResult {
  ok: boolean;
  reason?: string;
  remoteId?: string;
}

export interface EcClientConfig {
  serverUrl?: string;
  apiKey?: string;
  projectId?: string;
  /** Identifies the calling front-end in the `x-periperi-client` header. */
  client?: string;
  healthTimeoutMs?: number;
  uploadTimeoutMs?: number;
}

export const DEFAULT_CLIENT_ID = 'periperi-cli';
export const DEFAULT_HEALTH_TIMEOUT_MS = 10000;
export const DEFAULT_UPLOAD_TIMEOUT_MS = 30000;

function reason(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}

export class EcClient {
  private readonly config: EcClientConfig;

  constructor(config: EcClientConfig = {}) {
    this.config = config;
  }

  get serverUrl(): string {
    return (this.config.serverUrl ?? '').trim();
  }

  isConfigured(): boolean {
    return this.serverUrl.length > 0;
  }

  private validateUrl(): string | undefined {
    if (!this.serverUrl) {
      return 'No server configured. Set PERIPERI_SERVER_URL or --server-url.';
    }
    if (!/^https?:\/\//i.test(this.serverUrl)) {
      return 'Server URL must start with http:// or https://.';
    }
    return undefined;
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    const apiKey = this.config.apiKey ?? '';
    return {
      accept: 'application/json',
      'x-periperi-client': this.config.client ?? DEFAULT_CLIENT_ID,
      ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
      ...extra,
    };
  }

  /** Optional handshake with the ECDAT server. Never called automatically. */
  async connect(): Promise<SyncResult> {
    const invalid = this.validateUrl();
    if (invalid) {
      return { ok: false, reason: invalid };
    }

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.config.healthTimeoutMs ?? DEFAULT_HEALTH_TIMEOUT_MS,
    );
    try {
      const response = await fetch(new URL('/api/health', this.serverUrl), {
        method: 'GET',
        headers: this.headers(),
        signal: controller.signal,
      });
      if (!response.ok) {
        return { ok: false, reason: `Server responded ${response.status} ${response.statusText}` };
      }
      logger.info('ECDAT health check succeeded');
      return { ok: true };
    } catch (err) {
      const failure = reason(err, 'Connection failed');
      logger.warn(`ECDAT health check failed: ${failure}`);
      return { ok: false, reason: failure };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Upload a CBOM. Reachable only through an explicit, confirmed call.
   * `confirm` is awaited before any network traffic happens.
   */
  async syncScan(cbom: Cbom, confirm?: () => Promise<boolean> | boolean): Promise<SyncResult> {
    const invalid = this.validateUrl();
    if (invalid) {
      return { ok: false, reason: invalid };
    }
    if (confirm && !(await confirm())) {
      return { ok: false, reason: 'Synchronisation cancelled.' };
    }

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.config.uploadTimeoutMs ?? DEFAULT_UPLOAD_TIMEOUT_MS,
    );
    try {
      const projectId = this.config.projectId ?? '';
      const response = await fetch(new URL('/api/v1/cbom', this.serverUrl), {
        method: 'POST',
        headers: this.headers({
          'content-type': 'application/json',
          ...(projectId ? { 'x-periperi-project': projectId } : {}),
        }),
        body: JSON.stringify(cbom),
        signal: controller.signal,
      });
      if (!response.ok) {
        return { ok: false, reason: `Upload rejected: ${response.status} ${response.statusText}` };
      }
      const body = (await response.json().catch(() => ({}))) as { id?: string };
      logger.info(`CBOM synchronised to ECDAT (${cbom.scan_id})`);
      return { ok: true, remoteId: body.id };
    } catch (err) {
      const failure = reason(err, 'Upload failed');
      logger.warn(`CBOM sync failed: ${failure}`);
      return { ok: false, reason: failure };
    } finally {
      clearTimeout(timer);
    }
  }
}
