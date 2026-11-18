/**
 * Command-backed secret providers.
 *
 * A provider is any CLI that prints one secret value to stdout, so the plugin
 * never implements a vault protocol and never holds a vault login: the command
 * owns its own authentication (`rbw` with an unlocked agent, `op` with a
 * signed-in session, `pass`, `sops`, a custom script). Replaceable argv
 * templates keep that generic without ever invoking a shell, which means an
 * item name cannot become a flag or a nested command.
 */
import { execFile } from 'node:child_process'
import { accessSync, constants } from 'node:fs'
import { delimiter, isAbsolute, join } from 'node:path'
import type { ProviderConfig } from './config'
import type { ProviderStatus, SecretProvider } from './provider-types'

/** Largest stdout a provider may produce before the call fails. */
const MAX_OUTPUT_BYTES = 1 << 20

/** Longest secret value this plugin will hold and inject. */
const MAX_VALUE_LENGTH = 65_536

/** One provider's readiness, as reported by `secret_status`. */
export type { ProviderStatus }

/**
 * One configured provider.
 *
 * Instances are cheap and stateless: every operation runs the configured
 * command. Caching belongs to the vault CLI, which already keeps its own
 * unlocked state.
 */
export class CommandProvider implements SecretProvider {
  readonly kind = 'command' as const

  constructor(
    readonly id: string,
    private readonly config: ProviderConfig,
  ) {}

  /** Whether the command's executable can be found. */
  status(_sessionId: string): ProviderStatus {
    const executable = this.config.command[0]
    if (executable === undefined || executable.trim() === '') {
      return { id: this.id, ready: false, note: 'no command configured' }
    }
    if (resolveExecutable(executable) === undefined) {
      return { id: this.id, ready: false, note: `${executable} is not on PATH` }
    }
    return { id: this.id, ready: true }
  }

  /**
   * Read one secret value.
   * @param item - item name passed to the command.
   * @param field - optional field name, when the command template wants one.
   */
  async read(item: string, field: string | undefined, _sessionId: string): Promise<string> {
    if (this.config.command.length === 0) {
      throw new Error(`provider "${this.id}" has no command configured`)
    }
    const argv = expand(this.config.command, { item, field }, this.id)
    const stdout = await run(argv, this.config, this.id)
    return cleanValue(stdout, this.id)
  }

  /** List item names the provider exposes, optionally filtered by a query. */
  async list(query: string | undefined, _sessionId: string): Promise<string[]> {
    if (this.config.list.length === 0) {
      throw new Error(`provider "${this.id}" has no list command configured; name the item yourself`)
    }
    const argv = expand(this.config.list, { query: query ?? '' }, this.id)
    const stdout = await run(argv, this.config, this.id)
    const names: string[] = []
    const seen = new Set<string>()
    for (const line of stdout.split('\n')) {
      const name = line.trim()
      if (name === '' || seen.has(name)) continue
      seen.add(name)
      names.push(name)
    }
    if (query === undefined || query === '') return names
    const needle = query.toLowerCase()
    return names.filter((name) => name.toLowerCase().includes(needle))
  }
}

/** Substitute `{name}` placeholders, refusing an unconfigured one rather than passing it through. */
function expand(
  template: readonly string[],
  values: Readonly<Record<string, string | undefined>>,
  provider: string,
): string[] {
  return template.map((part) =>
    part.replace(/\{([a-z]+)\}/g, (whole, key: string) => {
      const value = values[key]
      if (value === undefined) {
        throw new Error(`provider "${provider}": the command needs a ${key} name, but the call did not give one`)
      }
      return value
    }))
}

/** Run one provider command without a shell and return its stdout. */
function run(argv: string[], config: ProviderConfig, provider: string): Promise<string> {
  const executable = argv[0]
  if (executable === undefined || executable.trim() === '') {
    throw new Error(`provider "${provider}": the command template starts with an empty executable`)
  }
  return new Promise<string>((resolve, reject) => {
    execFile(
      executable,
      argv.slice(1),
      {
        encoding: 'utf8',
        timeout: config.timeoutMs,
        maxBuffer: MAX_OUTPUT_BYTES,
        windowsHide: true,
        env: { ...process.env, ...config.env },
      },
      (error, stdout, stderr) => {
        if (error === null) {
          resolve(stdout)
          return
        }
        reject(new Error(failureMessage(error, stderr, config.timeoutMs, provider)))
      },
    )
  })
}

/** Describe a failed invocation without ever including the value it was meant to print. */
function failureMessage(
  error: { killed?: boolean; code?: string | number },
  stderr: string,
  timeoutMs: number,
  provider: string,
): string {
  if (error.killed === true) {
    return `provider "${provider}": the command did not finish within ${timeoutMs} ms`
  }
  if (error.code === 'ENOENT') {
    return `provider "${provider}": the command's executable was not found`
  }
  // Provider stderr explains what went wrong (a locked vault, a missing item).
  // It is truncated and never carries the value, because a command that
  // succeeds prints the value on stdout instead.
  const detail = stderr.split('\n').map((line) => line.trim()).filter((line) => line !== '')[0]
  const code = typeof error.code === 'number' ? ` (exit ${error.code})` : ''
  return detail === undefined
    ? `provider "${provider}": the command failed${code}`
    : `provider "${provider}": the command failed${code}: ${detail.slice(0, 200)}`
}

/** Trim the command's trailing newline and enforce the value bound. */
function cleanValue(raw: string, provider: string): string {
  const value = raw.replace(/\r?\n$/, '')
  if (value.trim() === '') {
    throw new Error(`provider "${provider}" printed an empty value`)
  }
  if (value.length > MAX_VALUE_LENGTH) {
    throw new Error(`provider "${provider}" printed ${value.length} characters; the limit is ${MAX_VALUE_LENGTH}`)
  }
  return value
}

/** Absolute executable path, or a bare name found on PATH. */
function resolveExecutable(executable: string): string | undefined {
  if (isAbsolute(executable)) return executableFile(executable)
  const path = process.env.PATH ?? ''
  for (const directory of path.split(delimiter)) {
    if (directory === '') continue
    const candidate = executableFile(join(directory, executable))
    if (candidate !== undefined) return candidate
  }
  return undefined
}

function executableFile(path: string): string | undefined {
  try {
    accessSync(path, constants.X_OK)
    return path
  } catch {
    return undefined
  }
}
