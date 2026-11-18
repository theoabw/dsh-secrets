/**
 * Access grants.
 *
 * A grant is the owner's answer to "may this session read from this provider?".
 * It lives in host memory only: it dies with the session, with a service
 * restart, and when the owner revokes it. Nothing about a grant is persisted,
 * so a fresh session always starts with no access.
 */

/** What a grant covers inside one provider. */
export type Scope =
  | { kind: 'all' }
  | { kind: 'prefix'; prefix: string }
  | { kind: 'exact'; item: string }

/** One recorded consent decision. */
export interface Grant {
  readonly id: string
  readonly sessionId: string
  readonly provider: string
  readonly scope: Scope
  /** Epoch milliseconds, or `undefined` for "until this session ends". */
  readonly expiresAt: number | undefined
}

/**
 * Parse a scope expression.
 *
 * `*` covers every item, a trailing `*` covers names that start with the rest,
 * and anything else is one exact item name. Item names may contain spaces, so
 * there is no slash-separated path grammar to get wrong.
 */
export function parseScope(raw: string | undefined): Scope {
  const text = (raw ?? '*').trim()
  if (text === '' || text === '*') return { kind: 'all' }
  if (text.endsWith('*')) {
    const prefix = text.slice(0, -1)
    return prefix === '' ? { kind: 'all' } : { kind: 'prefix', prefix }
  }
  return { kind: 'exact', item: text }
}

/** Whether a scope covers one item name. */
export function scopeAllows(scope: Scope, item: string): boolean {
  switch (scope.kind) {
    case 'all':
      return true
    case 'prefix':
      return item.startsWith(scope.prefix)
    case 'exact':
      return item === scope.item
  }
}

/** Human-readable scope for a consent card or a status line. */
export function describeScope(scope: Scope): string {
  switch (scope.kind) {
    case 'all':
      return 'every item'
    case 'prefix':
      return `items starting with "${scope.prefix}"`
    case 'exact':
      return `exactly "${scope.item}"`
  }
}

/** Per-session grant table. */
export class GrantStore {
  private grants: Grant[] = []
  private counter = 0

  constructor(private readonly maxPerSession: number) {}

  /** Record a grant and return it. Expired grants for the same provider are replaced. */
  create(sessionId: string, provider: string, scope: Scope, expiresAt: number | undefined): Grant {
    this.prune()
    this.grants = this.grants.filter((grant) =>
      !(grant.sessionId === sessionId && grant.provider === provider))
    const grant: Grant = {
      id: `g${(this.counter += 1).toString(36)}`,
      sessionId,
      provider,
      scope,
      expiresAt,
    }
    if (this.count(sessionId) >= this.maxPerSession) {
      throw new Error(`this session already holds ${this.maxPerSession} grants; call secret_lock to drop them first`)
    }
    this.grants.push(grant)
    return grant
  }

  /** Every unexpired grant held by one session. */
  active(sessionId: string): Grant[] {
    this.prune()
    return this.grants.filter((grant) => grant.sessionId === sessionId)
  }

  /** The first unexpired grant held by this session that covers the item. */
  find(sessionId: string, provider: string, item: string): Grant | undefined {
    return this.active(sessionId).find((grant) =>
      grant.provider === provider && scopeAllows(grant.scope, item))
  }

  /** Whether this session may list names from a provider. */
  canList(sessionId: string, provider: string): boolean {
    return this.active(sessionId).some((grant) => grant.provider === provider)
  }

  /** Number of unexpired grants held by one session. */
  count(sessionId: string): number {
    this.prune()
    return this.grants.filter((grant) => grant.sessionId === sessionId).length
  }

  /** Drop every grant held by one session. */
  clearSession(sessionId: string): void {
    this.grants = this.grants.filter((grant) => grant.sessionId !== sessionId)
  }

  /** Drop every grant, used when the plugin unloads. */
  clear(): void {
    this.grants = []
  }

  private prune(): void {
    const now = Date.now()
    this.grants = this.grants.filter((grant) => grant.expiresAt === undefined || grant.expiresAt > now)
  }
}
