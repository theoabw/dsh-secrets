/**
 * An opened vault: decrypted names plus the keys needed to read one field.
 *
 * Opening decrypts item names (so `secret_list` and name lookup work) and keeps
 * one item key per cipher. A field value is only decrypted when it is actually
 * asked for, which keeps the number of decryptions proportional to what the
 * grant is used for.
 */
import type { CipherJson } from './api'
import { decryptToBytes, decryptToString, keyFromBytes } from './crypto'
import type { SymmetricKey } from './crypto'

/** One item this vault can read. */
interface OpenedItem {
  cipher: CipherJson
  key: SymmetricKey
}

/** Login fields that have a shorthand name. */
const LOGIN_FIELDS = new Set(['password', 'username', 'totp', 'uri'])

/** A vault whose names are decrypted and whose item keys are held. */
export class Vault {
  private readonly items = new Map<string, OpenedItem>()

  private constructor(items: Map<string, OpenedItem>) {
    this.items = items
  }

  /**
   * Open a synced vault.
   * @param masterKey - the stretched key from `deriveMasterKey` + `stretchKey`.
   * @param profileKey - the encrypted user key from sync or the login response.
   * @param ciphers - the encrypted ciphers from sync.
   */
  static open(masterKey: SymmetricKey, profileKey: string, ciphers: readonly unknown[]): Vault {
    const userKey = keyFromBytes(decryptToBytes(profileKey, masterKey))
    const items = new Map<string, OpenedItem>()
    for (const raw of ciphers) {
      if (typeof raw !== 'object' || raw === null) continue
      const cipher = raw as CipherJson
      if (typeof cipher.name !== 'string' || cipher.name === '') continue
      let key = userKey
      if (typeof cipher.key === 'string' && cipher.key !== '') {
        try {
          key = keyFromBytes(decryptToBytes(cipher.key, userKey))
        } catch {
          // A cipher with an unreadable item key is skipped rather than
          // failing the whole vault: one corrupt item must not lock the rest.
          continue
        }
      }
      let name: string
      try {
        name = decryptToString(cipher.name, key)
      } catch {
        continue
      }
      if (name !== '' && !items.has(name)) items.set(name, { cipher, key })
    }
    return new Vault(items)
  }

  /** Every item name, sorted. */
  names(): string[] {
    return [...this.items.keys()].sort((left, right) => left.localeCompare(right))
  }

  /** Whether an item exists. */
  has(item: string): boolean {
    return this.items.has(item)
  }

  /**
   * Read one field of one item.
   * @param item - item name, exactly as the vault names it.
   * @param field - `password` (default), `username`, `totp`, `uri`, `notes`, or
   * a custom field name.
   */
  read(item: string, field: string | undefined): string {
    const opened = this.items.get(item)
    if (opened === undefined) throw new Error(`no item named "${item}" in this vault`)
    const name = (field ?? 'password').trim()
    const lower = name.toLowerCase()

    if (lower === 'notes') return this.field(opened, item, 'notes', opened.cipher.notes)
    if (LOGIN_FIELDS.has(lower)) {
      if (opened.cipher.login === undefined || opened.cipher.login === null) {
        throw new Error(`item "${item}" is not a login and has no ${lower}`)
      }
      if (lower === 'uri') {
        const uri = opened.cipher.login.uris?.[0]?.uri
        return this.field(opened, item, 'uri', uri)
      }
      return this.field(opened, item, lower, opened.cipher.login[lower as 'password' | 'username' | 'totp'])
    }

    for (const custom of opened.cipher.fields ?? []) {
      if (custom.name === undefined || custom.name === null) continue
      let customName: string
      try {
        customName = decryptToString(custom.name, opened.key)
      } catch {
        continue
      }
      if (customName !== name && customName.toLowerCase() !== lower) continue
      return this.field(opened, item, name, custom.value)
    }
    throw new Error(`item "${item}" has no field "${name}"; try password, username, totp, uri, notes, or a custom field name`)
  }

  /** Decrypt one value, turning an absent or unreadable one into a clear error. */
  private field(opened: OpenedItem, item: string, field: string, value: string | null | undefined): string {
    if (value === null || value === undefined || value === '') {
      throw new Error(`item "${item}" has no ${field}`)
    }
    try {
      return decryptToString(value, opened.key)
    } catch {
      throw new Error(`item "${item}" has an unreadable ${field}`)
    }
  }
}
