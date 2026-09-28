/**
 * Security dashboard report.
 *
 * One HTML body serves two surfaces:
 *   - the VS Code webview (`interactive: true` — rows navigate the editor),
 *   - a standalone report file written by `periperi report --html`
 *     (`interactive: false` — no `vscode` API, no editor navigation).
 *
 * Every interpolated value goes through `escapeHtml`.
 */

import type { ScanState } from '../store';
import { rollupAssets, summarizeRisk } from '../scanner/scanner';
import { DISCLAIMER, EXTENSION_VERSION } from '../version';
import { BASE_STYLES, escapeHtml, renderHtmlDocument } from './html';

const MAX_ROWS = 400;
const MAX_ERROR_ROWS = 50;
const MAX_FILE_CHIPS = 40;

export interface ReportBodyOptions {
  /**
   * True when the report is hosted by the extension and can navigate the
   * editor. False for a standalone file, where locations are plain text.
   */
  interactive?: boolean;
  /** Render the "Refresh" affordance. Only meaningful when interactive. */
  refresh?: boolean;
}

function usageLabel(detectionMethod: string, confidence: string): string {
  if (detectionMethod === 'MANIFEST_DECLARATION') {
    return 'Dependency declared';
  }
  return confidence === 'HIGH' ? 'Detected Indicator (strong)' : 'Detected Indicator';
}

export function renderReportBody(state: ScanState, options: ReportBodyOptions = {}): string {
  const { interactive = false, refresh = false } = options;
  const { result, cbom } = state;
  const risk = summarizeRisk(result.detections);
  const rollup = rollupAssets(result);

  const chips = (values: string[]): string =>
    values.length
      ? values.map((v) => `<span class="chip">${escapeHtml(v)}</span>`).join('')
      : '<span class="muted">none detected</span>';

  const rows = result.detections
    .slice(0, MAX_ROWS)
    .map((d) => {
      const label = usageLabel(d.detectionMethod, d.confidence);
      const rowAttrs = interactive
        ? `data-file="${escapeHtml(d.file)}" data-line="${d.line}" data-column="${d.column}"`
        : '';
      return `
        <tr class="asset" ${rowAttrs}>
          <td><strong>${escapeHtml(d.algorithm)}</strong></td>
          <td><span class="chip ${d.risk.toLowerCase()}">${escapeHtml(d.risk)}</span></td>
          <td><span class="badge indicator">${escapeHtml(label)}</span></td>
          <td><code>${escapeHtml(d.file)}:${d.line}</code></td>
          <td>${escapeHtml(d.detectionMethod)}</td>
          <td>${escapeHtml(d.confidence)}</td>
        </tr>`;
    })
    .join('');

  const errorBlock =
    result.errors.length > 0
      ? `<h2>Skipped / unreadable (${result.errors.length})</h2>
         <table><tr><th>File</th><th>Reason</th></tr>
         ${result.errors
           .slice(0, MAX_ERROR_ROWS)
           .map((e) => `<tr><td><code>${escapeHtml(e.file)}</code></td><td>${escapeHtml(e.reason)}</td></tr>`)
           .join('')}
         </table>`
      : '';

  const keyBlock =
    cbom.private_key_files.length > 0
      ? `<h2>Private-key files detected (${cbom.private_key_files.length})</h2>
         <p class="muted">PARI PARI reports the presence of these files only. Key material is never read, stored or displayed.</p>
         <ul>${cbom.private_key_files.map((f) => `<li><code>${escapeHtml(f)}</code></li>`).join('')}</ul>`
      : '';

  const actions = refresh
    ? '<div class="actions"><button id="refresh">Refresh</button></div>'
    : '';

  const hint = interactive
    ? 'A textual match is an <em>indicator</em>, not proof that the code executes. Select a row to open the source location.'
    : 'A textual match is an <em>indicator</em>, not proof that the code executes.';

  const truncated =
    result.detections.length > MAX_ROWS
      ? `<p class="muted">Showing the first ${MAX_ROWS} of ${result.detections.length} detections. The full set is in the CBOM export.</p>`
      : '';

  const filter = interactive
    ? ''
    : `<div class="actions">
         <input id="filter" class="filter" type="search" placeholder="Filter by algorithm, file or method…" autocomplete="off" />
       </div>
       <p class="stat-line" id="filter-count">${result.detections.length} detections shown</p>`;

  return `
    <h1>PARI PARI TERMINAL</h1>
    <div class="sub">Enterprise Cryptographic Discovery &amp; Analysis (ECDAT) · v${escapeHtml(EXTENSION_VERSION)}</div>

    <div class="banner">
      <strong>Preliminary static-analysis result.</strong><br/>
      ${escapeHtml(DISCLAIMER)}
    </div>

    ${actions}
    ${filter}

    <div class="grid">
      <div class="card"><div class="value">${risk.total}</div><div class="label">Cryptographic Assets</div></div>
      <div class="card"><div class="value" style="color:var(--critical)">${risk.critical}</div><div class="label">Critical</div></div>
      <div class="card"><div class="value" style="color:var(--high)">${risk.high}</div><div class="label">High Risk</div></div>
      <div class="card"><div class="value" style="color:var(--medium)">${risk.medium}</div><div class="label">Medium Risk</div></div>
      <div class="card"><div class="value" style="color:var(--low)">${risk.low}</div><div class="label">Low Risk</div></div>
      <div class="card"><div class="value">${risk.info}</div><div class="label">Info</div></div>
    </div>

    <h2>Scan</h2>
    <table>
      <tr><th>Scan ID</th><th>Scope</th><th>Files</th><th>Duration</th><th>Cancelled</th></tr>
      <tr>
        <td><code>${escapeHtml(result.scanId)}</code></td>
        <td>${escapeHtml(result.mode)} — ${escapeHtml(result.rootLabel)}</td>
        <td>${result.stats.filesScanned} / ${result.stats.filesDiscovered}</td>
        <td>${result.stats.durationMs} ms</td>
        <td>${result.cancelled ? 'yes (partial results)' : 'no'}</td>
      </tr>
    </table>

    <h2>Algorithms (${rollup.algorithms.length})</h2>
    <div>${chips(rollup.algorithms)}</div>

    <h2>Libraries (${rollup.libraries.length})</h2>
    <div>${chips(rollup.libraries)}</div>

    <h2>Protocols (${rollup.protocols.length})</h2>
    <div>${chips(rollup.protocols)}</div>

    <h2>Files with findings (${rollup.files.length})</h2>
    <div>${chips(rollup.files.slice(0, MAX_FILE_CHIPS))}</div>

    <h2>Detected Indicators (${result.detections.length})</h2>
    <p class="muted">${hint}</p>
    <table id="detections">
      <tr><th>Algorithm</th><th>Risk</th><th>Classification</th><th>Location</th><th>Method</th><th>Confidence</th></tr>
      ${rows}
    </table>
    ${truncated}

    ${keyBlock}
    ${errorBlock}
  `;
}

export function renderEmptyReportBody(): string {
  return `
    <h1>PARI PARI TERMINAL</h1>
    <div class="sub">Enterprise Cryptographic Discovery &amp; Analysis (ECDAT)</div>
    <div class="banner">No scan results yet. Run <code>periperi scan</code> to populate this report.</div>`;
}

/** Client-side row filter for the standalone report. No network, no dependencies. */
const FILTER_SCRIPT = `
  (function () {
    var input = document.getElementById('filter');
    var count = document.getElementById('filter-count');
    var table = document.getElementById('detections');
    if (!input || !table) { return; }
    var rows = Array.prototype.slice.call(table.querySelectorAll('tr.asset'));
    input.addEventListener('input', function () {
      var needle = input.value.trim().toLowerCase();
      var shown = 0;
      rows.forEach(function (row) {
        var hit = !needle || row.textContent.toLowerCase().indexOf(needle) !== -1;
        row.classList.toggle('hidden', !hit);
        if (hit) { shown += 1; }
      });
      if (count) {
        count.textContent = needle
          ? shown + ' of ' + rows.length + ' detections match'
          : rows.length + ' detections shown';
      }
    });
  })();
`;

/** A complete, self-contained HTML document for the standalone report. */
export function renderStaticReport(state: ScanState): string {
  return renderHtmlDocument({
    title: 'PARI PARI — Security Report',
    body: renderReportBody(state, { interactive: false }),
    styles: BASE_STYLES,
    script: FILTER_SCRIPT,
    csp: true,
  });
}
