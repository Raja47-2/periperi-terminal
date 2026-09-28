/** Thrown for expected, user-facing failures. The message is safe to display. */
export class UserFacingError extends Error {
  readonly detail?: string;

  constructor(message: string, detail?: string) {
    super(message);
    this.name = 'UserFacingError';
    this.detail = detail;
  }
}

export function describeError(err: unknown): { reason: string; code?: string } {
  if (err instanceof Error) {
    const code = (err as NodeJS.ErrnoException).code;
    switch (code) {
      case 'EACCES':
      case 'EPERM':
        return { reason: 'Permission denied', code };
      case 'ENOENT':
        return { reason: 'File or folder no longer exists', code };
      case 'EISDIR':
        return { reason: 'Path is a folder, not a file', code };
      case 'ENAMETOOLONG':
        return { reason: 'Path is too long for the operating system', code };
      case 'EMFILE':
      case 'ENFILE':
        return { reason: 'Too many open files (raise the OS limit and retry)', code };
      default:
        return { reason: err.message || 'Unknown error', code };
    }
  }
  return { reason: 'Unknown error' };
}
