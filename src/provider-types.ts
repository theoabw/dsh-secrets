/**
 * The surface both provider kinds implement.
 *
 * `sessionId` is part of every call because a Bitwarden provider keeps one
 * unlocked vault per session: the owner's master password unlocks one session's
 * access, not the host.
 */

/** Readiness of one provider, as `secret_status` reports it. */
export interface ProviderStatus {
  id: string
  ready: boolean
  note?: string
}

/** A configured secret source. */
export interface SecretProvider {
  readonly id: string
  readonly kind: 'command' | 'bitwarden'
  status(sessionId: string): ProviderStatus
  list(query: string | undefined, sessionId: string): Promise<string[]>
  read(item: string, field: string | undefined, sessionId: string): Promise<string>
}
