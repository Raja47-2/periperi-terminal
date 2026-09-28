/**
 * Webview shell for the VS Code surface.
 *
 * The HTML primitives live in `core/html.ts` so the standalone report written by
 * `periperi report --html` uses exactly the same markup and stylesheet. This
 * module only adds what a webview needs: a `localResourceRoots`-safe script URI
 * and a strict CSP.
 */

import { BASE_STYLES, createNonce, escapeHtml, renderHtmlDocument } from '../core/html';

export { BASE_STYLES, createNonce, escapeHtml };

export interface WebviewShellOptions {
  title: string;
  body: string;
  styles: string;
  script?: string;
  /** Webview URI of an external script. Nonced like inline script. */
  scriptUri?: string;
}

export function renderWebviewHtml(options: WebviewShellOptions): string {
  return renderHtmlDocument({
    title: options.title,
    body: options.body,
    styles: options.styles,
    script: options.script,
    scriptSrc: options.scriptUri,
    csp: true,
  });
}
