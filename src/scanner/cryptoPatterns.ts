/**
 * Detection rule set.
 *
 * Every rule is a plain regular expression evaluated against a single line of
 * text. Rules are intentionally conservative and ordered from most specific to
 * least specific so that `RSA-4096` wins over the bare `RSA` rule.
 *
 * Confidence policy
 * -----------------
 * LOW    – the token is a name that is commonly used in prose or comments.
 * MEDIUM – a crypto-flavoured token, a manifest dependency, or a config value.
 * HIGH   – an unambiguous artefact: sized algorithm, a library header, a PEM
 *          header, or a crypto API call.
 *
 * `sourceScanner` applies a deterministic context boost so that, for example, a
 * bare `AES` inside `crypto.createCipheriv(..., 'aes-256-gcm')` is upgraded.
 */

import type { AssetType, Confidence, DetectionMethod, RiskLevel } from './types';

export interface CryptoPatternRule {
  /** Unique rule id, used in the UI rationale and in tests. */
  id: string;
  /** Canonical display name. */
  name: string;
  /** Line-scoped matcher. Must not use the global flag. */
  pattern: RegExp;
  assetType: AssetType;
  detectionMethod: DetectionMethod;
  baseConfidence: Confidence;
  risk: RiskLevel;
  keySize?: number;
  /** Optional grouping shown in the dashboard. */
  category?: string;
  rationale: string;
}

/** Tokens that raise the confidence of a co-located match. */
export const CRYPTO_CONTEXT_TOKENS: readonly RegExp[] = [
  /\bcrypto\b/i,
  /\bcipher/i,
  /\bhash\b/i,
  /\bencrypt/i,
  /\bdecrypt/i,
  /\bsign(ing|ature)?\b/i,
  /\bverify\b/i,
  /\bkey\b/i,
  /\bkdf\b/i,
  /\bpbkdf/i,
  /\bsalt\b/i,
  /\biv\b|\bnonce\b/i,
  /\btls\b|\bssl\b/i,
  /\bopenssl\b/i,
  /\btlsv|\bsslv/i,
  /[_-]?(aes|rsa|sha\d|hmac|hkdf|pbkdf2|ecdsa|ecdh|blowfish|chacha)[-_]?/i,
];

export const ALGORITHM_RULES: readonly CryptoPatternRule[] = [
  // --- RSA (sized variants first) -----------------------------------------
  rule('rsa-4096', 'RSA', /\bRSA[\s_-]?4096\b/i, { keySize: 4096, risk: 'LOW' }),
  rule('rsa-3072', 'RSA', /\bRSA[\s_-]?3072\b/i, { keySize: 3072, risk: 'LOW' }),
  rule('rsa-2048', 'RSA', /\bRSA[\s_-]?2048\b/i, { keySize: 2048, risk: 'MEDIUM' }),
  rule('rsa-1024', 'RSA', /\bRSA[\s_-]?1024\b/i, { keySize: 1024, risk: 'HIGH' }),
  rule('rsa-generic', 'RSA', /\bRSA\b/i, { risk: 'MEDIUM', confidence: 'MEDIUM' }),

  // --- AES ----------------------------------------------------------------
  rule('aes-256', 'AES', /\bAES[\s_-]?256(?:-[A-Z0-9]{2,8})?\b/i, {
    keySize: 256,
    risk: 'LOW',
  }),
  rule('aes-192', 'AES', /\bAES[\s_-]?192\b/i, { keySize: 192, risk: 'LOW' }),
  rule('aes-128', 'AES', /\bAES[\s_-]?128(?:-[A-Z0-9]{2,8})?\b/i, {
    keySize: 128,
    risk: 'LOW',
  }),
  rule('aes-generic', 'AES', /\bAES\b/i, { risk: 'MEDIUM', confidence: 'MEDIUM' }),

  // --- Legacy block ciphers ----------------------------------------------
  rule('triple-des', '3DES', /\b(?:3DES|Triple[\s_-]?DES|DES[\s_-]?EDE|TDEA)\b/i, {
    risk: 'HIGH',
  }),
  rule('des', 'DES', /\bDES\b/i, { risk: 'HIGH' }),
  rule('blowfish', 'Blowfish', /\bBlowfish\b/i, { risk: 'MEDIUM', confidence: 'MEDIUM' }),
  rule('rc4', 'RC4', /\bRC4\b/i, { risk: 'HIGH' }),
  rule('chacha', 'ChaCha20', /\bChaCha20(?:-Poly1305)?\b|\bchacha20-poly1305\b/i, {
    risk: 'LOW',
  }),

  // --- Elliptic curve -----------------------------------------------------
  rule('ecdsa', 'ECDSA', /\bECDSA\b/i, { risk: 'MEDIUM' }),
  rule('ecdh', 'ECDH', /\bECDH\b/i, { risk: 'MEDIUM' }),
  rule('ed25519', 'Ed25519', /\bEd25519\b|\bed25519\b/i, { risk: 'LOW' }),
  rule('ecc-generic', 'ECC', /\bECC\b|\bElliptic[\s_-]?Curve\b/i, {
    risk: 'MEDIUM',
    confidence: 'MEDIUM',
  }),

  // --- Signature / key agreement -----------------------------------------
  rule('dsa', 'DSA', /\bDSA\b/i, { risk: 'MEDIUM' }),
  rule('dh-generic', 'Diffie-Hellman', /\bDH\b|\bDiffie[\s-]?Hellman\b|\bDHE\b|\bECDH\b/i, {
    risk: 'MEDIUM',
  }),

  // --- Hashes (sized variants first) -------------------------------------
  rule('sha-512', 'SHA-512', /\bSHA[\s_-]?512\b/i, { risk: 'LOW' }),
  rule('sha-384', 'SHA-384', /\bSHA[\s_-]?384\b/i, { risk: 'LOW' }),
  rule('sha-256', 'SHA-256', /\bSHA[\s_-]?256\b/i, { risk: 'LOW' }),
  rule('sha-224', 'SHA-224', /\bSHA[\s_-]?224\b/i, { risk: 'LOW' }),
  rule('sha-1', 'SHA-1', /\bSHA[\s_-]?1\b|\bsha1\b/i, { risk: 'HIGH' }),
  rule('sha-generic', 'SHA-2', /\bSHA(?:v?[\s_-]?[0-9])?(?:-[0-9]{2,3})?\b/i, {
    risk: 'MEDIUM',
    confidence: 'MEDIUM',
  }),
  rule('md5', 'MD5', /\bMD5\b/i, { risk: 'HIGH' }),
  rule('md4', 'MD4', /\bMD4\b/i, { risk: 'HIGH' }),
  rule('crc32', 'CRC32', /\bCRC32\b/i, { risk: 'INFO', confidence: 'MEDIUM' }),

  // --- KDFs / MACs -------------------------------------------------------
  rule('pbkdf2', 'PBKDF2', /\bPBKDF2\b/i, { risk: 'LOW' }),
  rule('hkdf', 'HKDF', /\bHKDF\b/i, { risk: 'LOW' }),
  rule('hmac', 'HMAC', /\bHMAC\b/i, { risk: 'LOW' }),
  rule('argon2', 'Argon2', /\bArgon2(?:id|i|d)?\b/i, { risk: 'LOW' }),
  rule('bcrypt', 'bcrypt', /\bbcrypt\b/i, { risk: 'LOW' }),
  rule('scrypt', 'scrypt', /\bscrypt\b/i, { risk: 'LOW' }),

  // --- Protocols ---------------------------------------------------------
  rule('tls-13', 'TLS', /\bTLS[\s_-]?1\.3\b|\btls13\b/i, {
    assetType: 'protocol',
    risk: 'LOW',
  }),
  rule('tls-12', 'TLS', /\bTLS[\s_-]?1\.2\b|\btls12\b/i, {
    assetType: 'protocol',
    risk: 'LOW',
  }),
  rule('tls-10', 'TLS', /\bTLS[\s_-]?1\.0\b|\btls10\b/i, {
    assetType: 'protocol',
    risk: 'HIGH',
  }),
  rule('tls-generic', 'TLS', /\bTLSv?1?\.[0-3]\b|\bTLS\b/i, {
    assetType: 'protocol',
    risk: 'MEDIUM',
    confidence: 'MEDIUM',
  }),
  rule('ssl-30', 'SSL', /\bSSL[\s_-]?v?3(?:\.0)?\b/i, {
    assetType: 'protocol',
    risk: 'HIGH',
  }),
  rule('ssl-generic', 'SSL', /\bSSL\b/i, {
    assetType: 'protocol',
    risk: 'MEDIUM',
    confidence: 'MEDIUM',
  }),

  // --- Libraries ---------------------------------------------------------
  rule('openssl', 'OpenSSL', /\bOpenSSL\b|\blibssl\b/i, {
    assetType: 'cryptographic_library',
    risk: 'MEDIUM',
  }),
  rule('boringssl', 'BoringSSL', /\bBoringSSL\b/i, {
    assetType: 'cryptographic_library',
    risk: 'MEDIUM',
  }),
  rule('libressl', 'LibreSSL', /\bLibreSSL\b/i, {
    assetType: 'cryptographic_library',
    risk: 'MEDIUM',
  }),
  rule('libsodium', 'libsodium', /\blibsodium\b/i, {
    assetType: 'cryptographic_library',
    risk: 'LOW',
  }),
  rule('bouncycastle', 'Bouncy Castle', /\bBouncy[\s-]?Castle\b|\bbouncycastle\b/i, {
    assetType: 'cryptographic_library',
    risk: 'MEDIUM',
  }),
  rule('botan', 'Botan', /\bBotan\b/i, { assetType: 'cryptographic_library', risk: 'MEDIUM' }),
  rule('jose', 'JOSE', /\bjose\b/i, { assetType: 'cryptographic_library', risk: 'MEDIUM' }),
  rule('pyca-cryptography', 'cryptography (PyCA)', /\bfrom\s+cryptography\b|\bimport\s+cryptography\b/i, {
    assetType: 'cryptographic_library',
    risk: 'LOW',
  }),
  rule('pycryptodome', 'PyCryptodome', /\bPyCryptodome\b|\bCrypto\.Cipher\b|\bCrypto\.Hash\b/i, {
    assetType: 'cryptographic_library',
    risk: 'MEDIUM',
  }),
  rule('webcrypto', 'Web Crypto API', /\bcrypto\.subtle\b|\bSubtleCrypto\b/i, {
    assetType: 'cryptographic_library',
    risk: 'LOW',
  }),
  rule('node-crypto', 'Node.js crypto', /\brequire\(\s*['"]node:crypto['"]\s*\)|\brequire\(\s*['"]crypto['"]\s*\)|from\s+['"]node:crypto['"]/i, {
    assetType: 'cryptographic_library',
    risk: 'LOW',
  }),
];

/** Crypto API call shapes. These are indicators, not confirmed usage. */
export const API_RULES: readonly CryptoPatternRule[] = [
  api('node-create-cipheriv', 'crypto.createCipheriv', /\bcrypto\.createCipheriv\b/),
  api('node-create-decipheriv', 'crypto.createDecipheriv', /\bcrypto\.createDecipheriv\b/),
  api('node-create-hash', 'crypto.createHash', /\bcrypto\.createHash\b/),
  api('node-create-hmac', 'crypto.createHmac', /\bcrypto\.createHmac\b/),
  api('node-create-sign', 'crypto.createSign', /\bcrypto\.createSign\b/),
  api('node-create-verify', 'crypto.createVerify', /\bcrypto\.createVerify\b/),
  api('node-generate-keypair', 'crypto.generateKeyPair', /\bcrypto\.generateKeyPairSync\b|\bcrypto\.generateKeyPair\b/),
  api('node-random-bytes', 'crypto.randomBytes', /\bcrypto\.randomBytes\b|\bcrypto\.randomUUID\b/),
  api('node-pbkdf2', 'crypto.pbkdf2', /\bcrypto\.pbkdf2(?:Sync)?\b/),
  api('node-scrypt', 'crypto.scrypt', /\bcrypto\.scrypt(?:Sync)?\b/),
  api('node-timing-safe', 'crypto.timingSafeEqual', /\bcrypto\.timingSafeEqual\b/),
  api('webcrypto-subtle', 'crypto.subtle', /\bcrypto\.subtle\b/),
  api('java-cipher', 'javax.crypto.Cipher', /\bjavax\.crypto\.Cipher\b|\bCipher\.getInstance\b/),
  api('java-keypair', 'java.security.KeyPairGenerator', /\bKeyPairGenerator\.getInstance\b/),
  api('java-signature', 'java.security.Signature', /\bSignature\.getInstance\b/),
  api('java-messageDigest', 'java.security.MessageDigest', /\bMessageDigest\.getInstance\b/),
  api('java-keyStore', 'java.security.KeyStore', /\bKeyStore\.getInstance\b/),
  api('bouncy-jce', 'Bouncy Castle JCE', /\bBouncyCastleProvider\b|\bBCJCE\b/),
  api('openssl-cmd', 'openssl CLI', /\bopenssl\s+(?:genpkey|req|genrsa|enc|pkey|rand|ecparam|version)\b/i),
  api('py-hashlib', 'hashlib', /\bhashlib\.(?:new|pbkdf2_hmac|sha256|sha1|md5)\b/),
  api('py-hmac', 'hmac.new', /\bhmac\.new\b/),
  api('py-cipher', 'Cipher (PyCryptodome)', /\b(?:AES|RSA|DES|ARC4|ChaCha20)\.new\(/),
  api('go-crypto', 'crypto/rsa', /\b"crypto\/rsa"\b|\b"crypto\/aes"\b|\b"crypto\/ecdsa"\b|\b"crypto\/sha256"\b/),
  api('rust-ring', 'ring / rustCrypto', /\bring::(?:signature|digest|rand|aead)\b|\brustcrypto::|\baws_lc_rs::|\baws-lc-rs\b/),
  api('dotnet-rsa', 'System.Security.Cryptography', /\bSystem\.Security\.Cryptography\b|\bRSACryptoServiceProvider\b|\bAes\.Create\b/),
  api('php-crypto', 'PHP openssl_*', /\bopenssl_(?:encrypt|decrypt|random_pseudo_bytes|sign|verify|digest_pkey)\b/),
  api('ruby-crypto', 'OpenSSL (Ruby)', /\bOpenSSL::(?:PKey|Cipher|Digest|HMAC)\b/),
  api('kotlin-jce', 'JCE (Kotlin/Java)', /\bjavax\.crypto\b|\bjava\.security\b/),
  api('swift-crypto', 'CryptoKit / CommonCrypto', /\bimport\s+CryptoKit\b|\bCC_SHA256\b|\bSecKey\b/),
];

export const ALL_RULES: readonly CryptoPatternRule[] = [...ALGORITHM_RULES, ...API_RULES];

/** File extensions read by the source scanner. */
export const SUPPORTED_EXTENSIONS: readonly string[] = [
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.java',
  '.c',
  '.cc',
  '.cpp',
  '.h',
  '.hpp',
  '.go',
  '.rs',
  '.php',
  '.cs',
  '.rb',
  '.kt',
  '.kts',
  '.swift',
  '.yaml',
  '.yml',
  '.json',
  '.xml',
  '.conf',
  '.ini',
  '.cfg',
  '.properties',
  '.env.example',
  '.pem',
  '.crt',
  '.cer',
  '.der',
  '.csr',
  '.key',
  '.p12',
  '.pfx',
  '.jks',
  '.keystore',
  '.sql',
  '.sh',
  '.ps1',
  '.md',
];

/** Exact file names (case-insensitive) that are always scanned. */
export const SUPPORTED_FILENAMES: readonly string[] = [
  'dockerfile',
  'containerfile',
  'makefile',
  'cmakelists.txt',
  'requirements.txt',
  'pyproject.toml',
  'pipfile',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'cargo.toml',
  'go.mod',
  'composer.json',
  'gemfile',
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'npm-shrinkwrap.json',
];

export function isSupportedFile(fileName: string): boolean {
  const lower = fileName.toLowerCase();
  if (SUPPORTED_FILENAMES.includes(lower)) {
    return true;
  }
  if (lower.startsWith('dockerfile') || lower.endsWith('dockerfile')) {
    return true;
  }
  return SUPPORTED_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/** Filenames that strongly suggest secret material. Contents are never read. */
export const PRIVATE_KEY_FILE_PATTERNS: readonly RegExp[] = [
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.jks$/i,
  /\.keystore$/i,
  /\.der$/i,
  /(^|[\\/])id_(rsa|dsa|ecdsa|ed25519)$/i,
  /\.ppk$/i,
];

function rule(
  id: string,
  name: string,
  pattern: RegExp,
  options: {
    keySize?: number;
    risk: RiskLevel;
    assetType?: AssetType;
    confidence?: Confidence;
  },
): CryptoPatternRule {
  return {
    id,
    name,
    pattern,
    assetType: options.assetType ?? 'cryptographic_algorithm',
    detectionMethod: 'PATTERN_MATCH',
    baseConfidence: options.confidence ?? 'HIGH',
    risk: options.risk,
    keySize: options.keySize,
    category: 'algorithm',
    rationale: `Static text matched the "${name}" indicator rule (${id}).`,
  };
}

function api(id: string, name: string, pattern: RegExp): CryptoPatternRule {
  return {
    id,
    name,
    pattern,
    assetType: 'cryptographic_api',
    detectionMethod: 'API_PATTERN',
    baseConfidence: 'HIGH',
    risk: 'INFO',
    category: 'api',
    rationale: `Static text matched a cryptographic API call shape (${name}). Call sites are indicators, not proof of live crypto.`,
  };
}
