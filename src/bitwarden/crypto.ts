/**
 * Bitwarden / Vaultwarden key schedule and ciphertext format.
 *
 * Everything here runs in the host process, which is the point: the master
 * password, the master key and the user key never become an environment
 * variable, an argument, or a file that another process could read.
 *
 * Key schedule (Bitwarden's `enc`/`mac` split, PBKDF2 accounts):
 *   masterKey  = PBKDF2-SHA256(NFKD(password), lowercase(email), iterations)
 *   encKey     = HKDF-Expand-SHA256(masterKey, info="enc", 32)
 *   macKey     = HKDF-Expand-SHA256(masterKey, info="mac", 32)
 *   loginHash  = base64(PBKDF2-SHA256(password=masterKey, salt=password, 1))
 *
 * Ciphertext is `EncString` version 2: `2.<iv>|<ct>|<mac>`, AES-256-CBC with
 * PKCS#7 padding and HMAC-SHA256(macKey, iv || ct).
 */
import { createDecipheriv, createCipheriv, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto'

/** KDF parameters an account declares in prelogin. */
export interface KdfParams {
  /** 0 is PBKDF2-SHA256, 1 is Argon2id. */
  kdf: number
  iterations: number
  memory?: number | null
  parallelism?: number | null
}

/** A 64-byte symmetric key split into its encryption and authentication halves. */
export interface SymmetricKey {
  encKey: Buffer
  macKey: Buffer
}

/** Character limit for one ciphertext part, so a hostile response cannot exhaust memory. */
const MAX_ENCRYPTED_LENGTH = 8 * 1024 * 1024

/** Derive the master key from the owner's password and the account email. */
export function deriveMasterKey(password: string, email: string, params: KdfParams): Buffer {
  if (params.kdf === 1) {
    throw new Error('this account uses Argon2id, which this build does not support yet; an account with PBKDF2 works')
  }
  if (params.kdf !== 0) throw new Error(`unknown key derivation function ${params.kdf}`)
  const iterations = Math.max(1, Math.floor(params.iterations))
  return pbkdf2Sync(
    Buffer.from(password.normalize('NFKD'), 'utf8'),
    Buffer.from(email.trim().toLowerCase(), 'utf8'),
    iterations,
    32,
    'sha256',
  )
}

/** The value the server expects as `password` in the token request. */
export function loginHash(masterKey: Buffer, password: string): string {
  const hash = pbkdf2Sync(masterKey, Buffer.from(password, 'utf8'), 1, 32, 'sha256')
  return hash.toString('base64')
}

/** Split the master key into the encryption and authentication halves. */
export function stretchKey(masterKey: Buffer): SymmetricKey {
  return {
    encKey: hkdfExpand(masterKey, 'enc', 32),
    macKey: hkdfExpand(masterKey, 'mac', 32),
  }
}

/** Build a symmetric key from the 64 bytes stored in the vault. */
export function keyFromBytes(bytes: Buffer): SymmetricKey {
  if (bytes.length !== 64) throw new Error(`expected a 64-byte key, got ${bytes.length} bytes`)
  return { encKey: bytes.subarray(0, 32), macKey: bytes.subarray(32, 64) }
}

/** Serialize a symmetric key back to the 64 bytes a vault stores. */
export function keyToBytes(key: SymmetricKey): Buffer {
  return Buffer.concat([key.encKey, key.macKey])
}

/** Decrypt an `EncString` to raw bytes. */
export function decryptToBytes(encString: string, key: SymmetricKey): Buffer {
  const { iv, ciphertext, mac } = parseEncString(encString)
  const expected = createHmac('sha256', key.macKey)
    .update(iv)
    .update(ciphertext)
    .digest()
  if (expected.length !== mac.length || !timingSafeEqual(expected, mac)) {
    throw new Error('the stored value failed its authentication check; the key is wrong or the value was altered')
  }
  const decipher = createDecipheriv('aes-256-cbc', key.encKey, iv)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

/** Decrypt an `EncString` to text. */
export function decryptToString(encString: string, key: SymmetricKey): string {
  return decryptToBytes(encString, key).toString('utf8')
}

/** Encrypt bytes into an `EncString`. Used by the tests and by nothing else at runtime. */
export function encryptBytes(bytes: Buffer, key: SymmetricKey, iv: Buffer = randomBytes(16)): string {
  if (iv.length !== 16) throw new Error('the initialization vector must be 16 bytes')
  const cipher = createCipheriv('aes-256-cbc', key.encKey, iv)
  const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()])
  const mac = createHmac('sha256', key.macKey).update(iv).update(ciphertext).digest()
  return `2.${iv.toString('base64')}|${ciphertext.toString('base64')}|${mac.toString('base64')}`
}

/** Encrypt text into an `EncString`. */
export function encryptString(text: string, key: SymmetricKey, iv?: Buffer): string {
  return encryptBytes(Buffer.from(text, 'utf8'), key, iv)
}

/** Parse and validate the `2.iv|ct|mac` form. */
function parseEncString(encString: string): { iv: Buffer; ciphertext: Buffer; mac: Buffer } {
  if (encString.length === 0 || encString.length > MAX_ENCRYPTED_LENGTH) {
    throw new Error('the stored value is empty or too large')
  }
  const parts = encString.split('|')
  if (parts.length !== 3) throw new Error('the stored value is not a valid encrypted string')
  const [head, ciphertextPart, macPart] = parts
  const [version, ivPart] = head.split('.')
  if (version !== '2') throw new Error(`unsupported encrypted value version ${version ?? 'missing'}`)
  if (ivPart === undefined || ciphertextPart === undefined || macPart === undefined) {
    throw new Error('the stored value is not a valid encrypted string')
  }
  const iv = Buffer.from(ivPart, 'base64')
  const ciphertext = Buffer.from(ciphertextPart, 'base64')
  const mac = Buffer.from(macPart, 'base64')
  if (iv.length !== 16) throw new Error('the stored value has an invalid initialization vector')
  if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
    throw new Error('the stored value has an invalid ciphertext length')
  }
  if (mac.length !== 32) throw new Error('the stored value has an invalid authentication tag')
  return { iv, ciphertext, mac }
}

/**
 * HKDF-Expand (RFC 5869) without the extract step.
 *
 * Bitwarden applies expand directly to the master key, so `node:crypto`'s
 * `hkdfSync` (which always extracts first) would produce a different key.
 */
function hkdfExpand(prk: Buffer, info: string, length: number): Buffer {
  const blocks: Buffer[] = []
  const infoBytes = Buffer.from(info, 'utf8')
  let previous = Buffer.alloc(0)
  let produced = 0
  for (let counter = 1; produced < length; counter += 1) {
    if (counter > 255) throw new Error('hkdf: requested length is too long')
    previous = createHmac('sha256', prk)
      .update(previous)
      .update(infoBytes)
      .update(Buffer.from([counter]))
      .digest()
    blocks.push(previous)
    produced += previous.length
  }
  return Buffer.concat(blocks).subarray(0, length)
}
