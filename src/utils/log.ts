/**
 * Output-channel logger.
 *
 * The logger is deliberately free of any `vscode` import so the scanner can be
 * unit tested in plain Node. `extension.ts` injects a real OutputChannel sink.
 *
 * Hard rule: this logger never receives source-code lines, secrets or tokens.
 * Callers pass structural messages only (counts, paths, stage names).
 */

export type LogSink = (line: string) => void;

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ICON: Record<LogLevel, string> = {
  debug: '·',
  info: 'ℹ',
  warn: '⚠',
  error: '✖',
};

export class Logger {
  private sinks: LogSink[] = [];
  private history: string[] = [];
  private readonly maxHistory: number;

  constructor(maxHistory = 500) {
    this.maxHistory = maxHistory;
  }

  addSink(sink: LogSink): void {
    this.sinks.push(sink);
  }

  private write(level: LogLevel, message: string): void {
    const line = `[${new Date().toISOString()}] ${LEVEL_ICON[level]} ${message}`;
    this.history.push(line);
    if (this.history.length > this.maxHistory) {
      this.history.shift();
    }
    for (const sink of this.sinks) {
      try {
        sink(line);
      } catch {
        /* never let logging break a scan */
      }
    }
  }

  debug(message: string): void {
    this.write('debug', message);
  }

  info(message: string): void {
    this.write('info', message);
  }

  warn(message: string): void {
    this.write('warn', message);
  }

  error(message: string): void {
    this.write('error', message);
  }

  lines(): readonly string[] {
    return this.history;
  }
}

/** Process-wide logger instance. */
export const logger = new Logger();
