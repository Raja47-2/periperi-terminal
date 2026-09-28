/** Shared version constants. Kept in one place so package.json and code agree. */
export const EXTENSION_ID = 'pari-pari.terminal';
export const EXTENSION_VERSION = '0.1.0';
export const CBOM_VERSION = '0.1';
export const DISPLAY_NAME = 'PARI PARI Terminal';

export const DISCLAIMER =
  'Preliminary static-analysis result. Detected indicators are not proof of confirmed cryptographic usage. ' +
  'Advanced quantum-risk analysis is delivered by a future PARI PARI ECDAT phase.';

export const CONFIDENCE_NOTE =
  'confidence=HIGH: unambiguous artefact (sized algorithm, PEM/API header, manifest dependency); ' +
  'confidence=MEDIUM: crypto-flavoured token with supporting context; ' +
  'confidence=LOW: bare name that may appear in prose or comments.';
