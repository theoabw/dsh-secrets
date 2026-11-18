/**
 * The three Bitwarden/Vaultwarden endpoints this plugin needs.
 *
 * No SDK and no CLI: prelogin for the account's KDF parameters, a password
 * grant for tokens, and one sync for the encrypted vault. The access token and
 * refresh token stay in host memory with the keys.
 */

/** Server endpoints derived from the vault's base URL. */
export interface Endpoints {
  api: string
  identity: string
}

/** KDF parameters as returned by prelogin, normalized from either casing. */
export interface PreloginResult {
  kdf: number
  iterations: number
  memory: number | null
  parallelism: number | null
}

/** A successful password grant. */
export interface LoginResult {
  accessToken: string
  refreshToken?: string
  /** Encrypted user key carried by the identity response (`Key`). */
  encryptedKey?: string
  expiresIn?: number
}

/** The parts of a sync response this plugin reads. */
export interface SyncResult {
  /** Encrypted user key (`profile.key`). */
  profileKey?: string
  ciphers: unknown[]
}

/** One cipher as the server sends it: every string field is still encrypted. */
export interface CipherJson {
  id?: string
  type?: number
  name?: string | null
  notes?: string | null
  key?: string | null
  login?: {
    username?: string | null
    password?: string | null
    totp?: string | null
    uris?: Array<{ uri?: string | null }> | null
  } | null
  fields?: Array<{ name?: string | null; value?: string | null; type?: number }> | null
}

/** Derive the API and identity bases from the vault's own URL. */
export function endpointsFor(server: string): Endpoints {
  const base = server.trim().replace(/\/+$/, '')
  if (base === '') throw new Error('the provider has no server URL')
  return { api: `${base}/api`, identity: `${base}/identity` }
}

/** Read the account's KDF parameters. */
export async function prelogin(endpoints: Endpoints, email: string, timeoutMs: number): Promise<PreloginResult> {
  const response = await request(`${endpoints.identity}/accounts/prelogin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
    timeoutMs,
  })
  const body = await readJson(response)
  const kdf = numberField(body, 'kdf', 'Kdf')
  const iterations = numberField(body, 'kdfIterations', 'KdfIterations')
  if (kdf === undefined || iterations === undefined) {
    throw new Error('the server did not return key derivation parameters for this account')
  }
  return {
    kdf,
    iterations,
    memory: numberField(body, 'kdfMemory', 'KdfMemory') ?? null,
    parallelism: numberField(body, 'kdfParallelism', 'KdfParallelism') ?? null,
  }
}

/** Exchange the owner's password for tokens. */
export async function login(
  endpoints: Endpoints,
  options: {
    email: string
    passwordHash: string
    deviceIdentifier: string
    deviceName: string
    timeoutMs: number
  },
): Promise<LoginResult> {
  const form = new URLSearchParams({
    grant_type: 'password',
    username: options.email,
    password: options.passwordHash,
    scope: 'api offline_access',
    client_id: 'cli',
    deviceType: '8',
    deviceIdentifier: options.deviceIdentifier,
    deviceName: options.deviceName,
    devicePushToken: '',
  })
  const response = await request(`${endpoints.identity}/connect/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Device-Type': '8',
      'Bitwarden-Client-Name': 'cli',
      'Bitwarden-Client-Version': '2026.1.0',
    },
    body: form.toString(),
    timeoutMs: options.timeoutMs,
  })
  const body = await readJson(response)
  if (!response.ok) throw new Error(describeLoginFailure(body, response.status, response.statusText))
  const accessToken = stringField(body, 'access_token')
  if (accessToken === undefined) throw new Error('the server accepted the login without returning a token')
  const encryptedKey = stringField(body, 'Key', 'key')
  const expiresIn = numberField(body, 'expires_in')
  const refreshToken = stringField(body, 'refresh_token')
  return {
    accessToken,
    ...(refreshToken === undefined ? {} : { refreshToken }),
    ...(encryptedKey === undefined ? {} : { encryptedKey }),
    ...(expiresIn === undefined ? {} : { expiresIn }),
  }
}

/** Fetch the encrypted vault. */
export async function sync(endpoints: Endpoints, accessToken: string, timeoutMs: number): Promise<SyncResult> {
  const response = await request(`${endpoints.api}/sync`, {
    method: 'GET',
    headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
    timeoutMs,
  })
  const body = await readJson(response)
  if (!response.ok) {
    throw new Error(`the vault sync failed with HTTP ${response.status}${response.statusText === '' ? '' : ` ${response.statusText}`}`)
  }
  const profile = typeof body === 'object' && body !== null ? (body as Record<string, unknown>).profile : undefined
  const profileKey = profile === undefined ? undefined : stringField(profile, 'key', 'Key')
  const ciphers = typeof body === 'object' && body !== null ? (body as Record<string, unknown>).ciphers : undefined
  return {
    ...(profileKey === undefined ? {} : { profileKey }),
    ciphers: Array.isArray(ciphers) ? ciphers : [],
  }
}

/** One HTTP call with a timeout, returning the response without reading the body. */
async function request(url: string, init: {
  method: string
  headers: Record<string, string>
  body?: string
  timeoutMs: number
}): Promise<Response> {
  let response: Response
  try {
    response = await fetch(url, {
      method: init.method,
      headers: init.headers,
      ...(init.body === undefined ? {} : { body: init.body }),
      signal: AbortSignal.timeout(Math.max(1, init.timeoutMs)),
      redirect: 'error',
    })
  } catch (error) {
    const reason = error instanceof Error && error.name === 'TimeoutError'
      ? `timed out after ${init.timeoutMs} ms`
      : error instanceof Error ? error.message : String(error)
    throw new Error(`could not reach ${url}: ${reason}`)
  }
  return response
}

/** Parse a JSON body, tolerating a non-JSON error page. */
async function readJson(response: Response): Promise<Record<string, unknown>> {
  let text: string
  try {
    text = await response.text()
  } catch {
    return {}
  }
  if (text === '') return {}
  try {
    const parsed: unknown = JSON.parse(text)
    return typeof parsed === 'object' && parsed !== null ? parsed as Record<string, unknown> : {}
  } catch {
    return { message: text.slice(0, 200) }
  }
}

/** Turn a token-endpoint failure into something the owner can act on. */
function describeLoginFailure(body: Record<string, unknown>, status: number, statusText: string): string {
  const description = stringField(body, 'error_description', 'error')
  if (body.TwoFactorProviders !== undefined || body.TwoFactorProviders2 !== undefined
    || (description !== undefined && /two.?factor|2fa/i.test(description))) {
    return 'this account has two-factor authentication enabled; a dedicated agent account without 2FA is required'
  }
  if (description !== undefined) {
    return `the server rejected the login: ${description.slice(0, 200)}`
  }
  return `the server rejected the login with HTTP ${status}${statusText === '' ? '' : ` ${statusText}`}`
}

function stringField(body: unknown, ...names: string[]): string | undefined {
  if (typeof body !== 'object' || body === null) return undefined
  const record = body as Record<string, unknown>
  for (const name of names) {
    const value = record[name]
    if (typeof value === 'string' && value !== '') return value
  }
  return undefined
}

function numberField(body: unknown, ...names: string[]): number | undefined {
  if (typeof body !== 'object' || body === null) return undefined
  const record = body as Record<string, unknown>
  for (const name of names) {
    const value = record[name]
    if (typeof value === 'number' && Number.isFinite(value)) return value
  }
  return undefined
}
