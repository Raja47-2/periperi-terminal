/**
 * Cryptographic configuration scanning.
 *
 * Detects TLS/SSL version pinning, cipher-suite configuration, certificate and
 * key references, and HTTPS settings. Private-key *contents* are never read;
 * only the presence of a key reference is reported.
 */

import * as path from 'node:path';
import { readFile } from 'node:fs/promises';

import type { ConfigSignal, Detection, ProtocolUsage, RiskLevel, ScanError } from './types';
import { relativeLabel } from '../utils/paths';
import { redactContext } from '../utils/redact';

interface ConfigRule {
  id: string;
  label: string;
  pattern: RegExp;
  risk: RiskLevel;
  note: string;
  extract?: (line: string) => string | undefined;
  /** Optional filter so the rule only fires in plausibly-relevant files. */
  fileFilter?: RegExp;
}

const CONFIG_RULES: readonly ConfigRule[] = [
  {
    id: 'tls-min-version',
    label: 'TLS minimum version',
    pattern: /\b(min(?:imum)?[_-]?(?:tls|ssl)[_ -]?version|tls[_ -]?min[_ -]?version|ssl[_ -]?protocol)\b\s*[=:]\s*["']?([A-Za-z0-9._]+)/i,
    risk: 'INFO',
    note: 'Record the pinned minimum TLS version and confirm it is TLS 1.2 or above.',
    extract: (line) => /([A-Za-z0-9._]+)$/.exec(line.trim())?.[1],
  },
  {
    id: 'ssl3-enabled',
    label: 'SSLv3 configuration',
    pattern: /\b(?:sslv3|ssl[_-]?protocol\s*[=:]\s*ssl3|SSLv3Method)\b/i,
    risk: 'HIGH',
    note: 'SSLv3 is obsolete (POODLE). Any configuration enabling it needs remediation.',
  },
  {
    id: 'tls10-11',
    label: 'Legacy TLS 1.0/1.1 configuration',
    pattern: /\btls1[._]?[01]\b|\btls1[._]?1\b|\bSSLv23[_A-Za-z]*\b/i,
    risk: 'HIGH',
    note: 'TLS 1.0/1.1 are deprecated by RFC 8996 and should be disabled.',
  },
  {
    id: 'cipher-list',
    label: 'Cipher suite configuration',
    pattern: /\b(cipher[_ -]?s?uites?|ssl[_ -]?ciphers|ciphers|ssl_ciphers)\b\s*[=:]\s*["']?([^"';,\n]{3,})/i,
    risk: 'MEDIUM',
    note: 'A custom cipher list may include weak or export-grade suites. Review the list.',
    extract: (line) => /([^\s"';,]{3,})$/.exec(line.trim())?.[1],
  },
  {
    id: 'cert-ref',
    label: 'Certificate reference',
    pattern: /\b(cert(?:ificate)?[_ -]?(?:file|path|chain)|tls[_ -]?cert|ssl[_ -]?cert|X509|ca[_ -]?file)\b\s*[=:]\s*["']?([^"';\s]+)/i,
    risk: 'INFO',
    note: 'Certificate reference found. Verify expiry and signature algorithm.',
    extract: (line) => /([^\s"';,]{3,})$/.exec(line.trim())?.[1],
  },
  {
    id: 'key-ref',
    label: 'Key file reference',
    pattern: /\b(private[_ -]?key[_ -]?(?:file|path)|key[_ -]?(?:file|path)|tls[_ -]?key|ssl[_ -]?key|keyfile)\b\s*[=:]\s*["']?([^"';\s]+)/i,
    risk: 'MEDIUM',
    note: 'Key reference found. PARI PARI reports the reference only and never reads key material.',
    extract: (line) => /([^\s"';,]{3,})$/.exec(line.trim())?.[1],
  },
  {
    id: 'https-required',
    label: 'HTTPS enforcement',
    pattern: /\b(HSTS|Strict-Transport-Security|require[_ -]?https|https_only|secure[_ -]?cookies?|SameSite\s*[:=]\s*Strict)\b/i,
    risk: 'INFO',
    note: 'HTTPS/HSTS setting present; confirm it is enforced in every environment.',
  },
  {
    id: 'insecure-tls',
    label: 'TLS verification disabled',
    pattern: /\b(insecureSkipVerify|rejectUnauthorized\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*0|verify\s*[:=]\s*false|CURLOPT_SSL_VERIFYPEER\s*[=:]\s*(?:false|0)|SSL_VERIFY\s*[=:]\s*(?:0|none))\b/i,
    risk: 'HIGH',
    note: 'TLS certificate verification appears to be disabled, which enables MITM.',
  },
  {
    id: 'passwordless-kdf',
    label: 'Password hashing cost lowered',
    pattern: /\b(?:(\$2[aby]\$[01]\d\$)|rounds\s*[:=]\s*(?:[0-9]|1024|2048|4096)\b)/,
    risk: 'HIGH',
    note: 'Password-hash cost parameters look unusually low.',
  },
  {
    id: 'jwt-alg-none',
    label: 'JWT "none" algorithm',
    pattern: /\b(alg\s*[:=]\s*["']?none["']?|JWT_ALGORITHM\s*[=:]\s*["']?none["']?)/i,
    risk: 'HIGH',
    note: 'The JWT `none` algorithm disables signature verification.',
  },
  {
    id: 'hardcoded-iv',
    label: 'Static IV / nonce',
    pattern: /\b(iv|nonce|initialization[_ -]?vector)\s*[:=]\s*["'](0{8,}|1{8,}|AAAAAAAA|123456)["']/i,
    risk: 'HIGH',
    note: 'A static IV/nonce was found; IVs and nonces must be unique per operation.',
  },
];

const PROTOCOL_RULES: readonly { pattern: RegExp; protocol: string; version?: string }[] = [
  { pattern: /\bTLS[\s_-]?1\.3\b|\btls13\b/i, protocol: 'TLS', version: '1.3' },
  { pattern: /\bTLS[\s_-]?1\.2\b|\btls12\b/i, protocol: 'TLS', version: '1.2' },
  { pattern: /\bTLS[\s_-]?1\.1\b|\btls11\b/i, protocol: 'TLS', version: '1.1' },
  { pattern: /\bTLS[\s_-]?1\.0\b|\btls10\b/i, protocol: 'TLS', version: '1.0' },
  { pattern: /\bSSL[\s_-]?v?3(?:\.0)?\b/i, protocol: 'SSL', version: '3.0' },
  { pattern: /\bDTLS\b/i, protocol: 'DTLS' },
  { pattern: /\bQUIC\b/i, protocol: 'QUIC' },
  { pattern: /\bHTTPS\b/i, protocol: 'HTTPS' },
  { pattern: /\bSSH\b/i, protocol: 'SSH' },
  { pattern: /\bIPsec\b/i, protocol: 'IPsec' },
];

const PEM_CERT_HEADER = /-----BEGIN\s+CERTIFICATE-----/;
const PEM_PRIVATE_HEADER = /-----BEGIN\s+(?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----/;

export interface ConfigScanOptions {
  root: string;
  /** Full absolute paths of the files to inspect. */
  files: string[];
}

export interface ConfigScanResult {
  configSignals: ConfigSignal[];
  protocols: ProtocolUsage[];
  detections: Detection[];
  errors: ScanError[];
}

/** Scan configuration-flavoured files. Pure text analysis; no code execution. */
export async function scanConfiguration(options: ConfigScanOptions): Promise<ConfigScanResult> {
  const configSignals: ConfigSignal[] = [];
  const protocols: ProtocolUsage[] = [];
  const detections: Detection[] = [];
  const errors: ScanError[] = [];

  for (const file of options.files) {
    const base = path.basename(file);
    const lower = base.toLowerCase();
    const isConfig =
      /\.(ya?ml|json|xml|conf|ini|cfg|properties|toml|env|crt|pem|csr)$/.test(lower) ||
      lower.includes('dockerfile') ||
      lower === 'nginx.conf' ||
      lower === 'openssl.cnf';
    if (!isConfig) {
      continue;
    }

    // Certificate / key files are handled by the header detector only: we do
    // not attempt to parse full X.509 bodies here.
    if (/\.(pem|crt|cer|der|csr)$/.test(lower)) {
      continue;
    }

    const label = relativeLabel(options.root, file);

    let text: string;
    try {
      const raw = await readFile(file, 'utf8');
      if (raw.includes('\u0000')) {
        continue;
      }
      text = raw;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      errors.push({ file: label, reason: code || 'Unable to read file', code });
      continue;
    }

    const lines = text.split(/\r?\n/);
    const seenSignals = new Set<string>();
    const seenProtocols = new Set<string>();

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      if (line.length === 0) {
        continue;
      }

      if (PEM_CERT_HEADER.test(line)) {
        detections.push({
          id: '',
          algorithm: 'X.509 certificate',
          assetType: 'certificate',
          file: label,
          line: i + 1,
          column: 1,
          context: '[certificate] PEM CERTIFICATE header detected',
          sourceType: 'certificate',
          detectionMethod: 'CONTENT_HEADER',
          confidence: 'HIGH',
          risk: 'INFO',
          rationale: 'PEM certificate header found. The certificate body is not parsed in Phase 1.',
        });
      }

      if (PEM_PRIVATE_HEADER.test(line)) {
        detections.push({
          id: '',
          algorithm: 'Potential private-key file',
          assetType: 'private_key_material',
          file: label,
          line: i + 1,
          column: 1,
          context: 'Potential private-key file detected (contents not read)',
          sourceType: 'keyfile',
          detectionMethod: 'CONTENT_HEADER',
          confidence: 'HIGH',
          risk: 'HIGH',
          rationale: 'PEM private-key header found. PARI PARI never reads, stores or displays key material.',
        });
      }

      for (const rule of CONFIG_RULES) {
        if (rule.fileFilter && !rule.fileFilter.test(lower)) {
          continue;
        }
        const match = rule.pattern.exec(line);
        if (!match) {
          continue;
        }
        const key = `${rule.id}:${i}`;
        if (seenSignals.has(key)) {
          continue;
        }
        seenSignals.add(key);
        const value = rule.extract ? rule.extract(line) : undefined;
        configSignals.push({
          setting: rule.label,
          value: value ?? redactContext(line).slice(0, 120),
          file: label,
          line: i + 1,
          risk: rule.risk,
          note: rule.note,
        });
        detections.push({
          id: '',
          algorithm: rule.label,
          assetType: 'configuration',
          file: label,
          line: i + 1,
          column: match.index + 1,
          context: redactContext(line),
          sourceType: 'config',
          detectionMethod: 'CONFIG_PATTERN',
          confidence: rule.risk === 'HIGH' ? 'HIGH' : 'MEDIUM',
          risk: rule.risk,
          rationale: rule.note,
        });
      }

      for (const proto of PROTOCOL_RULES) {
        if (!proto.pattern.test(line)) {
          continue;
        }
        const key = `${proto.protocol}:${proto.version ?? ''}`;
        if (seenProtocols.has(`${key}:${i}`)) {
          continue;
        }
        seenProtocols.add(`${key}:${i}`);
        const risk: RiskLevel =
          proto.protocol === 'SSL' || proto.version === '1.0' || proto.version === '1.1'
            ? 'HIGH'
            : 'LOW';
        protocols.push({
          protocol: proto.protocol,
          version: proto.version,
          file: label,
          line: i + 1,
          context: redactContext(line),
          confidence: 'MEDIUM',
        });
        detections.push({
          id: '',
          algorithm: proto.version ? `${proto.protocol} ${proto.version}` : proto.protocol,
          assetType: 'protocol',
          file: label,
          line: i + 1,
          column: 1,
          context: redactContext(line),
          sourceType: 'config',
          detectionMethod: 'CONFIG_PATTERN',
          confidence: 'MEDIUM',
          risk,
          rationale: `Protocol ${proto.protocol}${proto.version ? ` ${proto.version}` : ''} referenced in configuration.`,
        });
      }
    }
  }

  return { configSignals, protocols, detections, errors };
}
