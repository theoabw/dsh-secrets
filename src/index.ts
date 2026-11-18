/**
 * @tabw/dsh-secrets host half.
 *
 * Consent-gated secret brokering. A task that needs a credential asks for it
 * by name; the owner approves access for that session once, and every value
 * afterwards travels from the provider command straight into the shell's
 * environment. The model only ever sees a handle:
 *
 *   secret_request  -> the owner allows this session to read from a provider
 *   secret_fetch    -> { handle, env: "DSH_SECRET_<handle>" }
 *   $DSH_SECRET_x   -> the real value, inside a bash command
 *
 * Guarantees:
 * - No secret value enters the conversation, the trajectory, the session log,
 *   or this plugin's configuration. The model-visible result carries a handle.
 * - Values live in host process memory only, keyed by a random handle, scoped
 *   to the session that fetched them, and forgotten after `handleMinutes`
 *   without use. A service restart forgets everything.
 * - A session starts with no access. Consent is the owner's answer in the GUI,
 *   it is scoped and time-bounded, it can be revoked with `secret_lock`, and
 *   it dies with the session.
 * - Every model-visible tool result is rewritten while a value is live, and
 *   spill files the shell executor wrote are scrubbed in place.
 *
 * Deliberate limits (see README): a session that has been granted access can
 * still exfiltrate a value through a command it is allowed to run, so consent
 * is a policy gate and redaction is a safety net, not a sandbox. The provider
 * command owns its own vault authentication, so this plugin never holds a
 * vault login at all.
 */
import { randomBytes, randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolExecution, PostToolDecision } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import type { DshEnvironmentKey } from '@deepseek-ai/dsh-shell'
import type { BashEnvContributor } from '@deepseek-ai/dsh-shell-env'
// Type-only: pulls the ctx.userQuestions service augmentation into the program.
import type {} from '@deepseek-ai/dsh-user-questions'
import { Config as ConfigSchema } from './config'
import type { Config } from './config'
import { CommandProvider } from './provider'
import type { SecretProvider } from './provider-types'
import { BitwardenProvider } from './bitwarden/provider'
import { GrantStore, describeScope, parseScope } from './grants'
import { flattenText, redact, redactBlocks, scrubSpillFile, spillPathsOf } from './redact'

/** Environment-variable prefix under which a fetched value is exposed to shell commands. */
export const SECRET_ENV_PREFIX = 'DSH_SECRET_'

/**
 * Question header that a masked-input card claims. A prompt plugin that renders
 * masked fields for this marker picks up the master-password question, so the
 * value is typed into a concealed input rather than a plain one.
 */
const PROMPT_HEADER_MARKER = 'dsh-secret'

/** Shortest gap between two consent cards for one session. */
const CONSENT_COOLDOWN_MS = 10_000

/** The cordis plugin contract: the validated configuration schema. */
export { ConfigSchema as Config }

/** Services required before this plugin can register tools and hooks. */
export const inject = ['tools', 'userQuestions', 'shellEnv', 'systemPrompt']

/** One live value, held in memory for one session. */
interface LiveValue {
  handle: string
  sessionId: string
  provider: string
  item: string
  value: string
  disposeEnv: () => void
  timer: ReturnType<typeof setTimeout>
}

/**
 * In-memory value table.
 *
 * The window is an idle window, not a lifetime: handing the value to a command
 * of the owning session restarts it, so a long run keeps its credential and a
 * finished one lets it go `ttlMs` after its last use.
 */
class LiveValues {
  private readonly entries = new Map<string, LiveValue>()

  constructor(
    private readonly ttlMs: number,
    private readonly maxPerSession: number,
    private readonly registerEnv: (
      envKey: string,
      sessionId: string,
      value: string,
      onUse: () => void,
    ) => () => void,
  ) {}

  /** Store one value and register its environment contributor. */
  put(sessionId: string, provider: string, item: string, value: string): LiveValue {
    if (this.count(sessionId) >= this.maxPerSession) {
      throw new Error(`this session already holds ${this.maxPerSession} live values; call secret_lock first`)
    }
    const handle = randomBytes(10).toString('hex').toUpperCase()
    const disposeEnv = this.registerEnv(
      `${SECRET_ENV_PREFIX}${handle}`,
      sessionId,
      value,
      () => this.touch(handle),
    )
    const timer = setTimeout(() => this.revoke(handle), this.ttlMs)
    timer.unref?.()
    const entry: LiveValue = {
      handle,
      sessionId,
      provider,
      item,
      value,
      disposeEnv,
      timer,
    }
    this.entries.set(handle, entry)
    return entry
  }

  /** Restart the idle window for one value. */
  touch(handle: string): void {
    const entry = this.entries.get(handle)
    if (entry === undefined) return
    clearTimeout(entry.timer)
    const timer = setTimeout(() => this.revoke(handle), this.ttlMs)
    timer.unref?.()
    entry.timer = timer
  }

  /** Forget one value; idempotent. */
  revoke(handle: string): boolean {
    const entry = this.entries.get(handle)
    if (entry === undefined) return false
    clearTimeout(entry.timer)
    entry.disposeEnv()
    this.entries.delete(handle)
    return true
  }

  /** Forget every value held by one session. */
  clearSession(sessionId: string): number {
    let revoked = 0
    for (const entry of [...this.entries.values()]) {
      if (entry.sessionId === sessionId && this.revoke(entry.handle)) revoked += 1
    }
    return revoked
  }

  /** Number of live values held by one session. */
  count(sessionId: string): number {
    let count = 0
    for (const entry of this.entries.values()) if (entry.sessionId === sessionId) count += 1
    return count
  }

  /** Every live value, used by the redaction listener. */
  values(): string[] {
    return [...this.entries.values()].map((entry) => entry.value)
  }

  /** Drop everything, used when the plugin unloads or the process stops. */
  clear(): void {
    for (const entry of [...this.entries.values()]) {
      clearTimeout(entry.timer)
      entry.disposeEnv()
    }
    this.entries.clear()
  }
}

/**
 * Register the secret tools, the per-value shellEnv contributors, the consent
 * card, and the post-execute redaction listener.
 * @param ctx - host context.
 * @param config - validated configuration.
 */
export function apply(ctx: Context, config: Config): void {
  validateProviders(config)

  const providers = new Map<string, SecretProvider>()
  for (const [id, provider] of Object.entries(config.providers)) {
    if (provider.kind === 'bitwarden') {
      providers.set(id, new BitwardenProvider(id, {
        email: provider.email ?? '',
        server: provider.server ?? '',
        deviceIdentifier: (provider.deviceIdentifier ?? '') === '' ? randomUUID() : provider.deviceIdentifier,
        deviceName: (provider.deviceName ?? '') === '' ? 'dsh-secrets' : provider.deviceName,
        timeoutMs: provider.timeoutMs,
      }))
      continue
    }
    providers.set(id, new CommandProvider(id, provider))
  }
  // One grant per provider is enough, so the cap only has to stay above the
  // provider count; the extra headroom covers a provider added later.
  const grants = new GrantStore(Math.max(providers.size, 8))
  const lastConsent = new Map<string, number>()

  const registerEnv = (
    envKey: string,
    sessionId: string,
    value: string,
    onUse: () => void,
  ): (() => void) => {
    // The key is runtime-computed, so the template-literal-keyed record is
    // asserted; the registry re-validates the key at runtime.
    const contributor: BashEnvContributor = {
      name: `secrets:${envKey}`,
      variables: {
        [envKey]: {
          description: 'A secret fetched by secret_fetch. Reference it in the command that needs it; never print or echo its value.',
        },
      } as BashEnvContributor['variables'],
      resolve(execution: ToolExecution): Readonly<Partial<Record<DshEnvironmentKey, string>>> {
        if (execution.agent?.session.header.id !== sessionId) {
          return {} as Readonly<Partial<Record<DshEnvironmentKey, string>>>
        }
        onUse()
        return { [envKey]: value } as Readonly<Partial<Record<DshEnvironmentKey, string>>>
      },
    }
    return ctx.shellEnv.register(contributor)
  }

  const values = new LiveValues(config.handleMinutes * 60_000, config.maxSecretsPerSession, registerEnv)

  // Plugin unload (HMR, shutdown) forgets every value and every grant.
  ctx.effect(() => () => {
    values.clear()
    grants.clear()
    lastConsent.clear()
    for (const provider of providers.values()) {
      if (provider instanceof BitwardenProvider) provider.lockAll()
    }
  }, 'secrets: state')

  ctx.systemPrompt.section({
    name: 'tool:secrets',
    order: 107,
    text: [
      'Credentials come from the owner through secret_request, never through chat and never through a command you compose.',
      'When a task needs a secret: call secret_request to ask the owner for access to the provider that holds it (scope "*" covers every item, or name a prefix), then secret_fetch for the item.',
      'You receive only a handle and the $DSH_SECRET_<handle> variable name; the harness injects the value into your bash command environment, so reference the variable in place and never print, echo, base64, or otherwise emit it.',
      'If a fetch fails because there is no grant, ask the owner with secret_request instead of inventing a value. Call secret_lock when the work is done.',
    ].join(' '),
  })

  /** Resolve a provider by id, defaulting when exactly one is configured. */
  const providerOrThrow = (id: string | undefined): SecretProvider => {
    const name = id?.trim()
    if (name !== undefined && name !== '') {
      const provider = providers.get(name)
      if (provider === undefined) {
        const known = [...providers.keys()].join(', ')
        throw new Error(`unknown provider "${name}"; configured providers: ${known === '' ? 'none' : known}`)
      }
      return provider
    }
    if (providers.size === 1) {
      const only = [...providers.values()][0]
      if (only !== undefined) return only
    }
    const known = [...providers.keys()].join(', ')
    throw new Error(`name a provider: ${known === '' ? 'none are configured' : known}`)
  }

  /** The live session id for a model-owned execution. */
  const sessionOf = (exec: ToolExecution): string => {
    if (exec.agent === undefined) throw new Error('this tool requires an agent-owned session')
    return exec.agent.session.header.id
  }

  /**
   * Ask the owner for a Bitwarden account's master password.
   *
   * The question carries the marker a masked-input card claims, so the value is
   * typed into a concealed field. The answer never becomes a tool result.
   */
  const askMasterPassword = async (provider: BitwardenProvider, exec: ToolExecution): Promise<string> => {
    const answer = await ctx.userQuestions.ask({
      questions: [{
        id: 'master',
        question: `Master password for "${provider.id}"`,
        header: `${PROMPT_HEADER_MARKER}: Unlock ${provider.id}`,
        detail: 'Used once to unlock access for this session. It is not stored, and no value from the vault is ever shown to the agent.',
      }],
      agent: exec.agent,
      signal: exec.signal,
    }).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error)
      throw new Error(`the owner could not be asked for the master password (${message})`)
    })
    const password = answer.answers[0]?.custom
    if (password === undefined || password === '') {
      throw new Error(`the master password for "${provider.id}" was not provided, so the vault stays locked`)
    }
    return password
  }

  /**
   * Drop opened vaults whose session no longer holds a grant for them, so an
   * unlock never outlives the consent that justified it.
   */
  const pruneUnlocked = (sessionId: string): void => {
    for (const provider of providers.values()) {
      if (provider instanceof BitwardenProvider && !grants.canList(sessionId, provider.id)) {
        provider.lock(sessionId)
      }
    }
  }

  ctx.tools.register(defineTool({
    name: 'secret_request',
    description: 'Ask the owner (in the GUI) for permission for THIS session to read secrets from a configured provider. The owner sees the provider, the scope, and your reason, and can allow for a few minutes, allow until the session ends, or deny. A session starts with no access, so call this before secret_fetch. Grants are per session and never survive a restart.',
    parameters: {
      provider: {
        type: 'string',
        description: 'Provider id to request access to. Optional when exactly one provider is configured.',
      },
      scope: {
        type: 'string',
        description: 'What the grant covers: "*" for every item (default), a prefix ending in "*" such as "deploy*", or one exact item name.',
      },
      reason: {
        type: 'string',
        description: 'One short sentence telling the owner why this session needs the secret. Shown in the consent card.',
      },
      minutes: {
        type: 'number',
        description: 'Minutes for the short allow option. Clamped to the configured maximum; the session-lifetime option is always offered.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          granted: { type: 'boolean', required: true },
          provider: { type: 'string', required: true },
          scope: { type: 'string', required: true, description: 'The scope expression that was requested.' },
          expiresAt: { type: 'string', description: 'ISO time the grant lapses, absent when it lasts until the session ends.' },
          note: { type: 'string', description: 'Why the request ended without a grant, when it did.' },
        },
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    async execute(args, exec) {
      const sessionId = sessionOf(exec)
      const provider = providerOrThrow(args.provider)
      const scopeText = args.scope?.trim() ?? '*'
      const scope = parseScope(scopeText)
      const minutes = Math.min(
        Math.max(Math.round(args.minutes ?? config.grantMinutes), 1),
        config.maxGrantMinutes,
      )
      const last = lastConsent.get(sessionId)
      const now = Date.now()
      // The cooldown map only needs the recent past; drop finished entries so a
      // long-lived service does not accumulate one row per session forever.
      for (const [key, at] of lastConsent) {
        if (now - at > CONSENT_COOLDOWN_MS * 60) lastConsent.delete(key)
      }
      if (last !== undefined && now - last < CONSENT_COOLDOWN_MS) {
        throw new Error('a consent request was just answered for this session; wait a few seconds before asking again')
      }
      lastConsent.set(sessionId, now)

      const shortLabel = `Allow for ${minutes} min`
      const sessionLabel = 'Allow until this session ends'
      const denyLabel = 'Deny'
      const detail = [
        `Provider: ${provider.id}`,
        `Scope: ${describeScope(scope)}`,
        args.reason === undefined || args.reason.trim() === ''
          ? undefined
          : `Reason given by the agent (unverified): ${args.reason.trim().slice(0, 200)}`,
        'While granted, this session can pull matching values into its shell environment. Values are never shown to the agent.',
        provider instanceof BitwardenProvider
          ? 'This vault is locked: the first fetch will ask you for its master password.'
          : undefined,
      ].filter((line): line is string => line !== undefined).join('\n')

      const answer = await ctx.userQuestions.ask({
        questions: [{
          id: 'consent',
          question: `Allow this session to read secrets from "${provider.id}"?`,
          header: `secret access: ${provider.id}`,
          detail,
          options: [
            { label: shortLabel, description: `Access lapses after ${minutes} minutes.` },
            { label: sessionLabel, description: 'Access lapses when this session ends or the service restarts.' },
            { label: denyLabel, description: 'No access. The agent cannot read any value from this provider.' },
          ],
          intent: {
            kind: 'approval',
            approve: shortLabel,
            reject: denyLabel,
            always: sessionLabel,
            subject: { name: provider.id },
          },
        }],
        agent: exec.agent,
        signal: exec.signal,
      }).catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error)
        throw new Error(`secret_request: the owner could not be asked for consent (${message})`)
      })

      const item = answer.answers[0]
      const custom = item?.custom?.trim()
      const selected = item?.selected?.[0]
      const choice = custom !== undefined && custom !== '' ? custom : (selected ?? '')

      // A typed number is a sensible free-text answer for a minutes prompt.
      if (choice !== '' && !choice.startsWith('Allow') && /^\d+$/.test(choice)) {
        const typed = Math.min(Math.max(Number(choice), 1), config.maxGrantMinutes)
        const expiresAt = Date.now() + typed * 60_000
        grants.create(sessionId, provider.id, scope, expiresAt)
        return { granted: true, provider: provider.id, scope: scopeText, expiresAt: new Date(expiresAt).toISOString() }
      }
      if (choice === sessionLabel) {
        grants.create(sessionId, provider.id, scope, undefined)
        return { granted: true, provider: provider.id, scope: scopeText }
      }
      if (choice === shortLabel) {
        const expiresAt = Date.now() + minutes * 60_000
        grants.create(sessionId, provider.id, scope, expiresAt)
        return { granted: true, provider: provider.id, scope: scopeText, expiresAt: new Date(expiresAt).toISOString() }
      }
      return {
        granted: false,
        provider: provider.id,
        scope: scopeText,
        note: choice === denyLabel ? 'the owner denied access' : 'the owner dismissed the request without granting access',
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'secret_fetch',
    description: 'Fetch one secret value from an approved provider and expose it to this session as the shell variable named in the result. Requires a grant from secret_request that covers the item. The value itself is never returned to you: reference $DSH_SECRET_<handle> inside a bash command and never print, echo, or encode it.',
    parameters: {
      item: {
        type: 'string',
        required: true,
        description: 'Item name inside the provider, exactly as the provider names it.',
      },
      field: {
        type: 'string',
        description: 'Field name, when the provider command wants one (for example "password").',
      },
      provider: {
        type: 'string',
        description: 'Provider id. Optional when exactly one provider is configured.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          handle: { type: 'string', required: true },
          env: { type: 'string', required: true, description: 'Shell variable that holds the value, for example DSH_SECRET_ab12 (reference it as $DSH_SECRET_ab12).' },
          provider: { type: 'string', required: true },
          item: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    async execute(args, exec) {
      const sessionId = sessionOf(exec)
      pruneUnlocked(sessionId)
      const provider = providerOrThrow(args.provider)
      const item = args.item.trim()
      if (item === '') throw new Error('secret_fetch: item is empty')
      const field = args.field?.trim() === '' ? undefined : args.field?.trim()
      const grant = grants.find(sessionId, provider.id, item)
      if (grant === undefined) {
        throw new Error(`this session has no grant for provider "${provider.id}" covering "${item}"; call secret_request first`)
      }
      if (provider instanceof BitwardenProvider && !provider.isUnlocked(sessionId)) {
        const password = await askMasterPassword(provider, exec)
        await provider.unlock(sessionId, password)
      }
      const value = await provider.read(item, field, sessionId)
      const entry = values.put(sessionId, provider.id, item, value)
      return { handle: entry.handle, env: `${SECRET_ENV_PREFIX}${entry.handle}`, provider: provider.id, item }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'secret_list',
    description: 'List the item names this session may read from a provider, filtered by the current grant. Names only: no value ever appears. Use it to discover what to ask for with secret_fetch.',
    parameters: {
      query: {
        type: 'string',
        description: 'Case-insensitive substring to narrow the list.',
      },
      provider: {
        type: 'string',
        description: 'Provider id. Optional when exactly one provider is configured.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          provider: { type: 'string', required: true },
          names: {
            type: 'array',
            required: true,
            items: { type: 'string' },
          },
        },
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    async execute(args, exec) {
      const sessionId = sessionOf(exec)
      pruneUnlocked(sessionId)
      const provider = providerOrThrow(args.provider)
      if (!grants.canList(sessionId, provider.id)) {
        throw new Error(`this session has no grant for provider "${provider.id}"; call secret_request first`)
      }
      const names = await provider.list(args.query?.trim(), sessionId)
      return {
        provider: provider.id,
        names: names.filter((name) => grants.find(sessionId, provider.id, name) !== undefined),
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'secret_status',
    description: 'Report the secret providers this deployment is configured with, whether each command is available, the grants this session currently holds, and how many values are live. Use it before asking the owner for access again.',
    parameters: {},
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          providers: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                id: { type: 'string', required: true },
                ready: { type: 'boolean', required: true },
                note: { type: 'string' },
              },
            },
          },
          grants: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                provider: { type: 'string', required: true },
                scope: { type: 'string', required: true },
                expiresAt: { type: 'string' },
              },
            },
          },
          values: { type: 'number', required: true, description: 'Live values held for this session.' },
        },
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    async execute(_args, exec) {
      const sessionId = sessionOf(exec)
      pruneUnlocked(sessionId)
      return {
        providers: [...providers.values()].map((provider) => provider.status(sessionId)),
        grants: grants.active(sessionId).map((grant) => ({
          provider: grant.provider,
          scope: describeScope(grant.scope),
          ...(grant.expiresAt === undefined ? {} : { expiresAt: new Date(grant.expiresAt).toISOString() }),
        })),
        values: values.count(sessionId),
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'secret_lock',
    description: 'Give access back. With a handle, forget that one value. Without one, forget every value this session fetched and drop every grant it holds. Idempotent; use it when the work that needed the secret is done.',
    parameters: {
      handle: {
        type: 'string',
        description: 'Handle returned by secret_fetch. Omit to lock everything for this session.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          revoked: { type: 'number', required: true, description: 'How many live values were forgotten.' },
          locked: { type: 'boolean', required: true, description: 'Whether every grant for this session was dropped.' },
        },
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    async execute(args, exec) {
      const sessionId = sessionOf(exec)
      if (args.handle !== undefined && args.handle.trim() !== '') {
        const revoked = values.revoke(args.handle.trim()) ? 1 : 0
        return { revoked, locked: false }
      }
      const revoked = values.clearSession(sessionId)
      grants.clearSession(sessionId)
      for (const provider of providers.values()) {
        if (provider instanceof BitwardenProvider) provider.lock(sessionId)
      }
      return { revoked, locked: true }
    },
  }))

  // Redact every model-visible tool result and scrub spill files while any
  // value is live. Registered with prepend so this runs before other
  // post-execute policies (truncation, reminders).
  ctx.on('tools/post-execute', async (exec, result, next) => {
    const decision = await next()
    const live = values.values().filter((value) => value.length >= config.minRedactLength)
    if (live.length === 0) return decision
    if (decision.kind === 'block') {
      const feedback = redactBlocks(decision.feedback, live)
      return feedback === decision.feedback ? decision : { ...decision, feedback }
    }
    if (decision.kind !== 'accept') return decision
    // Spill files are written at capture time, before any listener runs; scrub
    // the ones this result points at before the model can be told to read them.
    const paths = spillPathsOf(result.value, flattenText(result.content))
    if (Object.hasOwn(decision, 'value')) {
      try {
        const cloned = redactDeep(structuredClone(decision.value) as JsonValue, live)
        await Promise.all(paths.map((path) => scrubSpillFile(path, live)))
        return {
          kind: 'accept',
          value: cloned,
          ...decision.additionalContexts !== undefined ? { additionalContexts: decision.additionalContexts } : {},
        }
      } catch {
        return decision
      }
    }
    const content = decision.content ?? result.content
    const redacted = redactBlocks(content, live)
    if (redacted === content && paths.length === 0) return decision
    await Promise.all(paths.map((path) => scrubSpillFile(path, live)))
    if (redacted === content) return decision
    return {
      kind: 'accept',
      content: redacted,
      ...(decision.additionalContexts !== undefined ? { additionalContexts: decision.additionalContexts } : {}),
    } as PostToolDecision
  }, { prepend: true })

  /** Redact every string leaf of a cloned JSON value. */
  function redactDeep(node: JsonValue, live: readonly string[]): JsonValue {
    if (typeof node === 'string') return redact(node, live)
    if (Array.isArray(node)) {
      for (let index = 0; index < node.length; index += 1) {
        node[index] = redactDeep(node[index] as JsonValue, live)
      }
      return node
    }
    if (typeof node === 'object' && node !== null) {
      const record = node as Record<string, JsonValue>
      for (const key of Object.keys(record)) record[key] = redactDeep(record[key], live)
      return node
    }
    return node
  }
}

/** Reject a provider that is missing what its kind needs, before any tool runs. */
function validateProviders(config: Config): void {
  for (const [id, provider] of Object.entries(config.providers)) {
    if (provider.kind === 'bitwarden') {
      if ((provider.email ?? '').trim() === '') {
        throw new Error(`provider "${id}": a bitwarden provider needs an email`)
      }
      if ((provider.server ?? '').trim() === '') {
        throw new Error(`provider "${id}": a bitwarden provider needs a server URL`)
      }
      if (!/^https?:\/\//i.test((provider.server ?? '').trim())) {
        throw new Error(`provider "${id}": the server must be an http or https URL`)
      }
      continue
    }
    if (provider.command.length === 0) {
      throw new Error(`provider "${id}": a command provider needs a command`)
    }
  }
}
