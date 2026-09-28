import * as vscode from 'vscode';

import {
  DEFAULT_SETTINGS,
  MAX_FILE_SIZE_RANGE,
  MAX_FILES_RANGE,
  clamp,
  settingsSnapshot,
  type PariPariSettings,
} from '../core/config';

/**
 * VS Code adapter for the shared settings contract.
 *
 * The keys, defaults and clamping all live in `core/config.ts` so the CLI and
 * the extension can never drift apart. This module only translates
 * `pariPari.*` into the shared shape.
 */

export { DEFAULT_SETTINGS, settingsSnapshot, clamp };
export type { PariPariSettings };

const CONFIG_SECTION = 'pariPari';

export function readSettings(
  config: vscode.WorkspaceConfiguration = vscode.workspace.getConfiguration(CONFIG_SECTION),
): PariPariSettings {
  return {
    serverUrl: config.get<string>('serverUrl', DEFAULT_SETTINGS.serverUrl).trim(),
    apiKey: config.get<string>('apiKey', DEFAULT_SETTINGS.apiKey),
    projectId: config.get<string>('projectId', DEFAULT_SETTINGS.projectId),
    scanExclude: config.get<string[]>('scan.exclude', DEFAULT_SETTINGS.scanExclude),
    maxFileSize: clamp(
      config.get<number>('maxFileSize', DEFAULT_SETTINGS.maxFileSize),
      MAX_FILE_SIZE_RANGE.min,
      MAX_FILE_SIZE_RANGE.max,
      DEFAULT_SETTINGS.maxFileSize,
    ),
    maxFiles: clamp(
      config.get<number>('maxFiles', DEFAULT_SETTINGS.maxFiles),
      MAX_FILES_RANGE.min,
      MAX_FILES_RANGE.max,
      DEFAULT_SETTINGS.maxFiles,
    ),
    enableTelemetry: config.get<boolean>('enableTelemetry', DEFAULT_SETTINGS.enableTelemetry),
    openDashboardAfterScan: config.get<boolean>(
      'openDashboardAfterScan',
      DEFAULT_SETTINGS.openDashboardAfterScan,
    ),
    writeResultsToWorkspace: config.get<boolean>(
      'writeResultsToWorkspace',
      DEFAULT_SETTINGS.writeResultsToWorkspace,
    ),
  };
}

export function onSettingsChanged(listener: () => void): vscode.Disposable {
  return vscode.workspace.onDidChangeConfiguration((e) => {
    if (e.affectsConfiguration(CONFIG_SECTION)) {
      listener();
    }
  });
}
