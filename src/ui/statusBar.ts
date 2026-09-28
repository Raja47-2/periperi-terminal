import * as vscode from 'vscode';

import { results } from '../store';

let statusItem: vscode.StatusBarItem | undefined;
let subscription: { dispose(): void } | undefined;

const ID = 'pariPari.status';
const IDLE_TEXT = '$(lock) PARI PARI';

export function createStatusBarItem(): vscode.StatusBarItem {
  disposeStatusBar();

  statusItem = vscode.window.createStatusBarItem(ID, vscode.StatusBarAlignment.Left, 100);
  statusItem.name = 'PARI PARI';
  statusItem.text = IDLE_TEXT;
  statusItem.tooltip =
    'PARI PARI Terminal — preliminary static-analysis result. Click to open the security dashboard.';
  statusItem.command = 'pariPari.showDashboard';
  statusItem.show();

  subscription = results.subscribe((state) => {
    if (!state) {
      if (statusItem) {
        statusItem.text = IDLE_TEXT;
      }
      return;
    }
    updateStatusBar(state.result.detections.length, state.result.cancelled);
  });

  return statusItem;
}

export function updateStatusBar(assetCount: number, cancelled = false): void {
  if (!statusItem) {
    return;
  }
  statusItem.text = cancelled
    ? `$(warning) PARI PARI: ${assetCount} Assets (partial)`
    : `$(lock) PARI PARI: ${assetCount} Assets`;
  statusItem.show();
}

export function resetStatusBar(): void {
  if (statusItem) {
    statusItem.text = IDLE_TEXT;
  }
}

export function disposeStatusBar(): void {
  subscription?.dispose();
  subscription = undefined;
  statusItem?.dispose();
  statusItem = undefined;
}
