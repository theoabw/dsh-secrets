/**
 * Known-answer tests for the Bitwarden key schedule and ciphertext format.
 *
 * The expected values come from independent implementations, not this code:
 *   PBKDF2-SHA256: OpenSSL 3.5 and Python hashlib agree on the master key.
 *   HKDF-Expand: Python cryptography `HKDFExpand` (expand only, raw PRK).
 *   AES-256-CBC + HMAC-SHA256: Python cryptography with a fixed IV.
 *
 * OpenSSL's `kdf` takes a hex PRK as ASCII, so it is not used for HKDF here.
 *
 * A self-consistency test would pass with a wrong key schedule, so these
 * vectors are the only thing that shows the derivation matches Bitwarden's.
 * Run: node scripts/crypto-test.mjs
 */
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const {
  deriveMasterKey,
  stretchKey,
  loginHash,
  decryptToBytes,
  decryptToString,
  encryptString,
  keyFromBytes,
  keyToBytes,
} = require('../lib/crypto.js')

const PASSWORD = 'correct horse battery staple'
const EMAIL = 'agent@example.com'
const ITERATIONS = 600_000

const MASTER_KEY_HEX = '49228804bf9a4b8021eec119319ae8d540cf4a2c4bd0845f31946cafdcf8df6b'
const ENC_KEY_HEX = '57af3d0abdc252c1c023f9cea3c02f4cb266115207263d581fa7ee63ef20e043'
const MAC_KEY_HEX = '4c6befa38b235aa16473cf8b3b05c9863d08ea23a91d93797f0341b66d75ac25'
const LOGIN_HASH_BASE64 = 'kjZHCD54baaf3cNRCsVYypi3UMcE7/KM1C1lWa0uwTg='
const KAT_IV_HEX = '000102030405060708090a0b0c0d0e0f'
const KAT_PLAINTEXT = 'hunter2-in-a-vault'
const KAT_ENCSTRING = '2.AAECAwQFBgcICQoLDA0ODw==|YJVJsjd/covQ2JP+wy9BR/BI3lHU3r/aCDVbcjYQx8Q=|cQugNrajtmPIVRUWLg+/IV8QsYUJ0Wznt48BANTGgzQ='

/* 1. Master key, stretched keys and the password the server sees. */
const masterKey = deriveMasterKey(PASSWORD, EMAIL, { kdf: 0, iterations: ITERATIONS })
assert.equal(masterKey.toString('hex'), MASTER_KEY_HEX, 'master key matches OpenSSL PBKDF2')
const stretched = stretchKey(masterKey)
assert.equal(stretched.encKey.toString('hex'), ENC_KEY_HEX, 'enc key matches OpenSSL HKDF-Expand')
assert.equal(stretched.macKey.toString('hex'), MAC_KEY_HEX, 'mac key matches OpenSSL HKDF-Expand')
assert.equal(loginHash(masterKey, PASSWORD), LOGIN_HASH_BASE64, 'login hash matches Bitwarden scheme')

/* 2. The email is normalized, because it is the KDF salt. */
assert.equal(
  deriveMasterKey(PASSWORD, '  Agent@Example.COM ', { kdf: 0, iterations: ITERATIONS }).toString('hex'),
  MASTER_KEY_HEX,
  'email casing and surrounding space do not change the salt',
)

/* 3. Ciphertext known answer, in both directions. */
const key = { encKey: Buffer.from(ENC_KEY_HEX, 'hex'), macKey: Buffer.from(MAC_KEY_HEX, 'hex') }
assert.equal(decryptToString(KAT_ENCSTRING, key), KAT_PLAINTEXT, 'decrypts the OpenSSL-produced value')
assert.equal(
  encryptString(KAT_PLAINTEXT, key, Buffer.from(KAT_IV_HEX, 'hex')),
  KAT_ENCSTRING,
  'encrypting produces the same OpenSSL value',
)
assert.equal(decryptToBytes(KAT_ENCSTRING, key).toString('utf8'), KAT_PLAINTEXT)

/* 4. Tampering and malformed input are refused, not reinterpreted. */
const parts = KAT_ENCSTRING.split('|')
const tampered = `${parts[0]}|${parts[1]}|${Buffer.alloc(32, 7).toString('base64')}`
assert.throws(() => decryptToString(tampered, key), /authentication check/)
assert.throws(() => decryptToString('1.abc|def|ghi', key), /unsupported encrypted value version/)
assert.throws(() => decryptToString('2.AAECAwQFBgcICQoLDA0ODw==|LlF26w9a8Ndq32cyjnUXiIP/cOPjLL9TE1Mqvb0SXFg=', key), /not a valid encrypted string/)
assert.throws(() => decryptToString('', key), /empty or too large/)
assert.throws(() => decryptToString('2.!!!!|YJVJsjd/covQ2JP+wy9BR/BI3lHU3r/aCDVbcjYQx8Q=|cQugNrajtmPIVRUWLg+/IV8QsYUJ0Wznt48BANTGgzQ=', key), /invalid initialization vector/)

/* 5. A wrong key fails the authentication check instead of returning bytes. */
const wrongKey = { encKey: Buffer.alloc(32, 1), macKey: Buffer.alloc(32, 2) }
assert.throws(() => decryptToString(KAT_ENCSTRING, wrongKey), /authentication check/)

/* 6. Argon2id accounts are refused with an actionable message. */
assert.throws(
  () => deriveMasterKey(PASSWORD, EMAIL, { kdf: 1, iterations: 3, memory: 64, parallelism: 4 }),
  /Argon2id/,
)

/* 7. Key serialization round-trips and rejects a wrong length. */
const bytes = keyToBytes(stretched)
assert.equal(bytes.length, 64)
assert.deepEqual(keyFromBytes(bytes), stretched)
assert.throws(() => keyFromBytes(Buffer.alloc(32)), /64-byte key/)

console.log('dsh-secrets: crypto known-answer tests passed')
