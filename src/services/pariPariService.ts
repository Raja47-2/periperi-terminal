/**
 * ECDAT backend connector for the VS Code surface.
 *
 * The transport lives in `core/ecClient.ts` so `periperi sync` speaks exactly
 * the same protocol. This adapter only supplies credentials from settings and
 * SecretStorage.
 *
 * Security rules:
 *   - local-first; `isConfigured()` is false unless `pariPari.serverUrl` is set,
 *   - nothing is uploaded by activation, by a scan, or by reading settings,
 *   - `syncScan` is only reachable through the explicit `pariPari.syncScan`
 *     command, which asks the user to confirm first,
 *   - credentials are never written to logs, the workspace or CBOM files.
 */

import type * as vscode from 'vscode';

import { readSettings } from '../config/configuration';
import { EcClient, type SyncResult } from '../core/ecClient';

export type { SyncResult };

export interface PariPariServiceOptions {
  secretStorage?: vscode.SecretStorage;
}

const SECRET_KEY = 'pariPari.apiKey';

export class PariPariService {
  private readonly secretStorage?: vscode.SecretStorage;

  constructor(options: PariPariServiceOptions = {}) {
    this.secretStorage = options.secretStorage;
  }

  get serverUrl(): string {
    return readSettings().serverUrl;
  }

  isConfigured(): boolean {
    return this.serverUrl.length > 0;
  }

  /** API key resolution: secret storage wins over the settings value. */
  async getApiKey(): Promise<string> {
    const fromSecret = await this.secretStorage?.get(SECRET_KEY);
    return fromSecret || readSettings().apiKey;
  }

  async setApiKey(value: string): Promise<void> {
    await this.secretStorage?.store(SECRET_KEY, value);
  }

  private async client(client: string): Promise<EcClient> {
    const settings = readSettings();
    return new EcClient({
      serverUrl: settings.serverUrl,
      // Secret storage wins over the plain settings value.
      apiKey: (await this.getApiKey()) || settings.apiKey,
      projectId: settings.projectId,
      client,
    });
  }

  /**
   * Optional handshake with the ECDAT server. Never called automatically.
   * Returns a structured result instead of throwing, so callers can render a
   * friendly message.
   */
  async connect(): Promise<SyncResult> {
    if (!this.isConfigured()) {
      return { ok: false, reason: 'pariPari.serverUrl is not configured.' };
    }
    const client = await this.client('vscode-extension');
    return client.connect();
  }

  /**
   * Upload a CBOM. Reachable only through an explicit, user-confirmed command.
   * Payload contains CBOM metadata and file/line locations — never file bodies.
   */
  async syncScan(
    cbom: Parameters<EcClient['syncScan']>[0],
    confirm: () => Promise<boolean>,
  ): Promise<SyncResult> {
    if (!this.isConfigured()) {
      return { ok: false, reason: 'pariPari.serverUrl is not configured.' };
    }
    const client = await this.client('vscode-extension');
    return client.syncScan(cbom, confirm);
  }

  dispose(): void {
    /* No subscriptions: the client is created per request. */
  }
}
