/**
 * The Bitwarden/Vaultwarden provider.
 *
 * Access is unlocked per session with the owner's master password, which is
 * used to derive the keys, log in and sync, and then dropped: what remains is
 * the decrypted vault in this process's memory and nothing else. No CLI, no
 * session token handed to a child, no unlocked agent another process can use.
 */
import { login, endpointsFor, prelogin, sync } from './api'
import { deriveMasterKey, loginHash, stretchKey } from './crypto'
import { Vault } from './vault'
import type { ProviderStatus, SecretProvider } from '../provider-types'

/** Non-secret account settings for one Bitwarden-compatible provider. */
export interface BitwardenConfig {
  /** Account email: the KDF salt, and not a secret. */
  email: string
  /** Vault base URL, for example `https://vault.example.com`. */
  server: string
  /** Stable device identifier the server sees. */
  deviceIdentifier: string
  /** Device name the server sees. */
  deviceName: string
  /** Timeout for one HTTP call. */
  timeoutMs: number
}

/** One session's opened vault. */
interface OpenVault {
  vault: Vault
}

/** A per-session, master-password-gated Bitwarden vault. */
export class BitwardenProvider implements SecretProvider {
  readonly kind = 'bitwarden' as const

  private readonly unlocked = new Map<string, OpenVault>()

  constructor(
    readonly id: string,
    private readonly config: BitwardenConfig,
  ) {}

  status(sessionId: string): ProviderStatus {
    if (this.config.email === '' || this.config.server === '') {
      return { id: this.id, ready: false, note: 'needs an email and a server URL' }
    }
    return {
      id: this.id,
      ready: true,
      note: this.unlocked.has(sessionId)
        ? 'unlocked for this session'
        : 'locked; the owner supplies the master password at first use',
    }
  }

  /** Whether this session already holds an opened vault. */
  isUnlocked(sessionId: string): boolean {
    return this.unlocked.has(sessionId)
  }

  /**
   * Unlock this session's access with the owner's master password.
   *
   * The password and every key derived from it are local to this call. Only the
   * opened vault is kept, and only for this session.
   */
  async unlock(sessionId: string, password: string): Promise<void> {
    const endpoints = endpointsFor(this.config.server)
    const params = await prelogin(endpoints, this.config.email, this.config.timeoutMs)
    const masterKey = deriveMasterKey(password, this.config.email, params)
    const stretched = stretchKey(masterKey)
    const passwordHash = loginHash(masterKey, password)
    const tokens = await login(endpoints, {
      email: this.config.email,
      passwordHash,
      deviceIdentifier: this.config.deviceIdentifier,
      deviceName: this.config.deviceName,
      timeoutMs: this.config.timeoutMs,
    })
    const synced = await sync(endpoints, tokens.accessToken, this.config.timeoutMs)
    const profileKey = synced.profileKey ?? tokens.encryptedKey
    if (profileKey === undefined) {
      throw new Error('the server returned no encrypted user key, so the vault cannot be opened')
    }
    this.unlocked.set(sessionId, { vault: Vault.open(stretched, profileKey, synced.ciphers) })
  }

  /** Drop one session's opened vault. */
  lock(sessionId: string): boolean {
    return this.unlocked.delete(sessionId)
  }

  /** Drop every session's opened vault, used when the plugin unloads. */
  lockAll(): void {
    this.unlocked.clear()
  }

  async list(query: string | undefined, sessionId: string): Promise<string[]> {
    const { vault } = this.openOrThrow(sessionId)
    const names = vault.names()
    if (query === undefined || query === '') return names
    const needle = query.toLowerCase()
    return names.filter((name) => name.toLowerCase().includes(needle))
  }

  async read(item: string, field: string | undefined, sessionId: string): Promise<string> {
    const { vault } = this.openOrThrow(sessionId)
    return vault.read(item, field)
  }

  private openOrThrow(sessionId: string): OpenVault {
    const opened = this.unlocked.get(sessionId)
    if (opened === undefined) {
      throw new Error(`provider "${this.id}" is locked; the owner has to supply the master password first`)
    }
    return opened
  }
}
