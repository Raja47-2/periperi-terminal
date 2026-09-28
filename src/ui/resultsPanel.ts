/**
 * Results tree view (activity-bar container `pariPari` → `pariPari.results`).
 *
 * Nodes are grouped as: Summary → Risk buckets → individual assets. Selecting
 * an asset reveals it in the editor at the exact line/column.
 */

import * as vscode from 'vscode';

import { results, type ScanState } from '../store';
import type { Detection, RiskLevel } from '../scanner/types';
import { summarizeRisk } from '../scanner/scanner';

export const REVEAL_COMMAND = 'pariPari.revealAsset';

export type TreeNode =
  | { kind: 'header' }
  | { kind: 'group'; title: string; detail: string }
  | { kind: 'asset'; detection: Detection }
  | { kind: 'file'; file: string; count: number }
  | { kind: 'empty' }
  | { kind: 'error'; file: string; reason: string };

const RISK_ORDER: readonly RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

class PariNode implements vscode.TreeItem {
  label: string;
  id: string;
  description?: string;
  tooltip?: vscode.MarkdownString;
  collapsibleState?: vscode.TreeItemCollapsibleState;
  iconPath?: vscode.ThemeIcon;
  contextValue?: string;
  command?: vscode.Command;
  children: PariNode[] = [];

  constructor(label: string, id: string, node: TreeNode) {
    this.label = label;
    this.id = id;
    this.contextValue = 'pariPariAsset';

    switch (node.kind) {
      case 'header':
        this.description = results.get() ? results.get()?.result.scanId : undefined;
        this.collapsibleState = vscode.TreeItemCollapsibleState.None;
        break;
      case 'group':
        this.description = node.detail;
        this.collapsibleState = vscode.TreeItemCollapsibleState.Collapsed;
        this.contextValue = 'pariPariGroup';
        this.iconPath = new vscode.ThemeIcon('folder');
        break;
      case 'asset':
        this.description = `${node.detection.file}:${node.detection.line}`;
        this.contextValue = 'pariPariAsset';
        this.collapsibleState = vscode.TreeItemCollapsibleState.None;
        this.iconPath = new vscode.ThemeIcon('shield');
        this.tooltip = this.buildTooltip(node.detection);
        this.command = {
          command: REVEAL_COMMAND,
          title: 'Reveal Cryptographic Asset',
          arguments: [node.detection.file, node.detection.line, node.detection.column],
        };
        break;
      case 'file':
        this.description = `${node.count} finding${node.count === 1 ? '' : 's'}`;
        this.collapsibleState = vscode.TreeItemCollapsibleState.Collapsed;
        this.contextValue = 'pariPariFile';
        this.iconPath = new vscode.ThemeIcon('file-code');
        break;
      case 'empty':
        this.description = 'run a scan';
        this.contextValue = 'pariPariEmpty';
        break;
      case 'error':
        this.description = node.reason;
        this.collapsibleState = vscode.TreeItemCollapsibleState.None;
        this.contextValue = 'pariPariError';
        this.iconPath = new vscode.ThemeIcon('warning');
        break;
      default:
        this.collapsibleState = vscode.TreeItemCollapsibleState.None;
    }
  }

  private buildTooltip(d: Detection): vscode.MarkdownString {
    const md = new vscode.MarkdownString();
    md.supportThemeIcons = true;
    md.appendMarkdown(`### ${d.algorithm}\n\n`);
    md.appendMarkdown(`- **File:** \`${d.file}:${d.line}:${d.column}\`\n`);
    md.appendMarkdown(`- **Type:** ${d.assetType}\n`);
    md.appendMarkdown(`- **Detection method:** ${d.detectionMethod}\n`);
    md.appendMarkdown(`- **Confidence:** ${d.confidence}\n`);
    md.appendMarkdown(`- **Preliminary risk:** ${d.risk}\n`);
    if (d.keySize) {
      md.appendMarkdown(`- **Key size:** ${d.keySize}\n`);
    }
    if (d.library) {
      md.appendMarkdown(`- **Library:** ${d.library}\n`);
    }
    md.appendMarkdown(`- **Context:** \`${d.context}\`\n`);
    if (d.rationale) {
      md.appendMarkdown(`\n${d.rationale}\n`);
    }
    md.appendMarkdown(`\n_Preliminary static-analysis result._\n`);
    return md;
  }
}

export class ResultsTreeProvider implements vscode.TreeDataProvider<PariNode> {
  private readonly emitter = new vscode.EventEmitter<PariNode | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;
  private readonly disposables: vscode.Disposable[] = [];

  constructor() {
    this.disposables.push(results.subscribe(() => this.refresh()));
  }

  refresh(): void {
    this.emitter.fire(undefined);
  }

  getTreeItem(element: PariNode): vscode.TreeItem {
    return element;
  }

  async getChildren(element?: PariNode): Promise<PariNode[]> {
    if (element) {
      return element.children;
    }
    return this.buildRoots();
  }

  private buildRoots(): PariNode[] {
    const state = results.get();
    if (!state) {
      const node = new PariNode('No scan results yet', 'empty', { kind: 'empty' });
      return [node];
    }
    return this.buildFromState(state);
  }

  private buildFromState(state: ScanState): PariNode[] {
    const { result, cbom } = state;
    const risk = summarizeRisk(result.detections);

    const roots: PariNode[] = [];
    const summary = new PariNode('Scan Summary', 'summary', { kind: 'header' });
    summary.children = [
      new PariNode(`Assets Found — ${risk.total}`, 'summary-total', { kind: 'empty' }),
      new PariNode(`Critical — ${risk.critical}`, 'summary-critical', { kind: 'empty' }),
      new PariNode(`High Risk — ${risk.high}`, 'summary-high', { kind: 'empty' }),
      new PariNode(`Medium Risk — ${risk.medium}`, 'summary-medium', { kind: 'empty' }),
      new PariNode(`Low Risk — ${risk.low}`, 'summary-low', { kind: 'empty' }),
      new PariNode(`Info — ${risk.info}`, 'summary-info', { kind: 'empty' }),
      new PariNode(`Files scanned — ${result.stats.filesScanned}`, 'summary-files', { kind: 'empty' }),
    ];
    roots.push(summary);

    // Risk buckets containing the actual assets.
    for (const level of RISK_ORDER) {
      const bucket = result.detections.filter((d) => d.risk === level);
      if (bucket.length === 0) {
        continue;
      }
      const group = new PariNode(`${level} Risk`, `risk-${level}`, {
        kind: 'group',
        title: level,
        detail: String(bucket.length),
      });
      group.children = bucket.map(
        (d, index) => new PariNode(`${d.algorithm} — ${d.file}`, `risk-${level}-${index}`, { kind: 'asset', detection: d }),
      );
      roots.push(group);
    }

    // Algorithms / libraries / protocols roll-ups.
    const algorithmGroup = new PariNode('Algorithms', 'algorithms', {
      kind: 'group',
      title: 'Algorithms',
      detail: String(cbom.algorithms.length),
    });
    algorithmGroup.children = cbom.algorithms.map(
      (a) =>
        new PariNode(a.name, `algo-${a.name}`, {
          kind: 'group',
          title: a.name,
          detail: `${a.occurrences}× ${a.risk}`,
        }),
    );
    roots.push(algorithmGroup);

    const libraryGroup = new PariNode('Libraries', 'libraries', {
      kind: 'group',
      title: 'Libraries',
      detail: String(cbom.libraries.length),
    });
    libraryGroup.children = cbom.libraries.map(
      (l) =>
        new PariNode(l.version ? `${l.name} ${l.version}` : l.name, `lib-${l.name}`, {
          kind: 'group',
          title: l.name,
          detail: l.ecosystem,
        }),
    );
    roots.push(libraryGroup);

    const protocolGroup = new PariNode('Protocols', 'protocols', {
      kind: 'group',
      title: 'Protocols',
      detail: String(cbom.protocols.length),
    });
    protocolGroup.children = cbom.protocols.map(
      (p) =>
        new PariNode(p.version ? `${p.name} ${p.version}` : p.name, `proto-${p.name}`, {
          kind: 'group',
          title: p.name,
          detail: `${p.occurrences}×`,
        }),
    );
    roots.push(protocolGroup);

    // Files
    const byFile = new Map<string, number>();
    for (const d of result.detections) {
      byFile.set(d.file, (byFile.get(d.file) ?? 0) + 1);
    }
    const filesGroup = new PariNode('Files', 'files', {
      kind: 'group',
      title: 'Files',
      detail: String(byFile.size),
    });
    filesGroup.children = [...byFile.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([file, count]) => new PariNode(file, `file-${file}`, { kind: 'file', file, count }));
    roots.push(filesGroup);

    if (result.privateKeyFiles.length > 0) {
      const keys = new PariNode('Private-key files (not read)', 'keys', {
        kind: 'group',
        title: 'Private-key files',
        detail: String(result.privateKeyFiles.length),
      });
      keys.children = result.privateKeyFiles.map((f, i) =>
        new PariNode(f, `key-${i}`, {
          kind: 'error',
          file: f,
          reason: 'contents not read',
        }),
      );
      roots.push(keys);
    }

    if (result.errors.length > 0) {
      const errs = new PariNode('Skipped files', 'errors', {
        kind: 'group',
        title: 'Skipped files',
        detail: String(result.errors.length),
      });
      errs.children = result.errors.map(
        (e, i) => new PariNode(e.file, `err-${i}`, { kind: 'error', file: e.file, reason: e.reason }),
      );
      roots.push(errs);
    }

    return roots;
  }

  dispose(): void {
    this.emitter.dispose();
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
