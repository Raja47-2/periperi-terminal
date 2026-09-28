/**
 * HTML primitives shared by the VS Code webview and the static CLI report.
 *
 * Free of any `vscode` import: a `scriptSrc` is just a string here, so the same
 * document builder serves a webview (URI) and a file on disk (path).
 */

import * as crypto from 'node:crypto';

export function createNonce(): string {
  return crypto.randomBytes(16).toString('base64');
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export interface HtmlDocumentOptions {
  title: string;
  body: string;
  styles?: string;
  /** Inline script. Nonced when `csp` is enabled. */
  script?: string;
  /** External script URI or path. Nonced when `csp` is enabled. */
  scriptSrc?: string;
  /**
   * Emit a strict `default-src 'none'` CSP with a fresh nonce. Enable for
   * untrusted rendering surfaces (webviews, browser-opened reports).
   */
  csp?: boolean;
}

export function renderHtmlDocument(options: HtmlDocumentOptions): string {
  const csp = options.csp ?? true;
  const nonce = createNonce();

  const scriptTag = options.scriptSrc
    ? `<script nonce="${nonce}" src="${escapeHtml(options.scriptSrc)}"></script>`
    : options.script
      ? `<script nonce="${nonce}">${options.script}</script>`
      : '';

  const cspMeta = csp
    ? `<meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; img-src data:; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';" />`
    : '';

  const styleTag = options.styles
    ? csp
      ? `<style nonce="${nonce}">${options.styles}</style>`
      : `<style>${options.styles}</style>`
    : '';

  return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  ${cspMeta}
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(options.title)}</title>
  ${styleTag}
</head>
<body>
${options.body}
${scriptTag}
</body>
</html>`;
}

/** Base stylesheet shared by the dashboard, results panels and static reports. */
export const BASE_STYLES = `
  :root {
    --bg: #0b0b0d;
    --panel: #15151a;
    --border: #2a2a33;
    --text: #e8e8ec;
    --muted: #9a9aa8;
    --gold: #f5c518;
    --critical: #ff3b5c;
    --high: #ff7a45;
    --medium: #f5c518;
    --low: #4cc38a;
    --info: #6aa9ff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 24px;
    background: var(--bg);
    color: var(--text);
    font-family: var(--vscode-font-family, system-ui, sans-serif);
    font-size: 13px;
    line-height: 1.5;
  }
  h1 { font-size: 18px; margin: 0 0 4px; letter-spacing: .5px; }
  h2 { font-size: 13px; margin: 24px 0 8px; color: var(--gold); text-transform: uppercase; letter-spacing: 1px; }
  .sub { color: var(--muted); margin-bottom: 20px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px; }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px;
  }
  .card .value { font-size: 26px; font-weight: 600; }
  .card .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .8px; }
  .chip {
    display: inline-block; padding: 2px 8px; margin: 0 6px 6px 0;
    border: 1px solid var(--border); border-radius: 10px;
    background: #101014; color: var(--text); font-size: 12px;
  }
  .chip.critical { border-color: var(--critical); color: var(--critical); }
  .chip.high { border-color: var(--high); color: var(--high); }
  .chip.medium { border-color: var(--medium); color: var(--medium); }
  .chip.low { border-color: var(--low); color: var(--low); }
  .chip.info { border-color: var(--info); color: var(--info); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .8px; }
  tr.asset { cursor: pointer; }
  tr.asset:hover { background: #1b1b22; }
  .badge { font-size: 10px; padding: 1px 6px; border-radius: 3px; background: #23232c; border: 1px solid var(--border); }
  .badge.confirmed { border-color: var(--low); color: var(--low); }
  .badge.indicator { border-color: var(--medium); color: var(--medium); }
  .banner { border-left: 3px solid var(--gold); background: #141410; padding: 10px 14px; margin-bottom: 18px; }
  .muted { color: var(--muted); }
  code { background: #101014; padding: 1px 5px; border-radius: 3px; border: 1px solid var(--border); }
  .actions button {
    background: var(--panel); color: var(--text); border: 1px solid var(--border);
    border-radius: 4px; padding: 6px 12px; margin: 0 8px 8px 0; cursor: pointer;
  }
  .actions button:hover { border-color: var(--gold); }
  .filter {
    background: var(--panel); color: var(--text); border: 1px solid var(--border);
    border-radius: 4px; padding: 6px 10px; width: 280px; max-width: 100%;
  }
  .filter:focus { outline: none; border-color: var(--gold); }
  tr.hidden { display: none; }
  .stat-line { color: var(--muted); margin: 0 0 12px; }
`;
