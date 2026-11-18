/**
 * Plugin configuration.
 *
 * Everything deployment-varying lives here: which secret stores the plugin can
 * read from, how long a session's access lasts, and the redaction floor. No
 * secret value is ever a configuration field; providers are commands, and the
 * values they print stay in this plugin's memory.
 */
import z from '@deepseek-ai/schemastery'

/** One provider: a command that prints a secret value, or an in-process vault. */
export interface ProviderConfig {
  /** `command` runs a CLI; `bitwarden` logs in and decrypts here. */
  kind: 'command' | 'bitwarden'
  /**
   * argv template whose stdout is the secret value. Used when `kind` is `command`.
   *
   * Placeholders: `{item}` and `{field}`. The command runs with no shell, so
   * an item name can never be read as a flag or a command.
   */
  command: string[]
  /**
   * argv template whose stdout lists item names, one per line, for `secret_list`.
   * Placeholder: `{query}`. An empty array disables listing for this provider.
   */
  list: string[]
  /** Hard timeout for one provider operation. */
  timeoutMs: number
  /** Extra environment for the provider command, merged over the host's. */
  env: Record<string, string>
  /** Bitwarden account email, which is the KDF salt and not a secret. */
  email: string
  /** Bitwarden vault base URL, for example `https://vault.example.com`. */
  server: string
  /** Stable device identifier the server sees; generated per start when empty. */
  deviceIdentifier: string
  /** Device name the server sees. */
  deviceName: string
}

/** Validated plugin configuration. */
export interface Config {
  /** Providers by id. A provider id is what the agent names when it asks for access. */
  providers: Record<string, ProviderConfig>
  /** Minutes offered by the short "allow" choice in the consent card. */
  grantMinutes: number
  /** Upper bound a caller may request for one grant. */
  maxGrantMinutes: number
  /** Minutes a fetched value stays usable WITHOUT BEING USED before it is forgotten. */
  handleMinutes: number
  /** Maximum simultaneously live values per session. */
  maxSecretsPerSession: number
  /** Shortest value that is redacted from tool output. */
  minRedactLength: number
}

export const Config: z<Config> = z.object({
  providers: z.dict(z.object({
    kind: z.union(['command', 'bitwarden']).default('command'),
    command: z.array(String).default([]),
    list: z.array(String).default([]),
    timeoutMs: z.number().min(1).default(15_000),
    env: z.dict(String).default({}),
    email: z.string().default(''),
    server: z.string().default(''),
    deviceIdentifier: z.string().default(''),
    deviceName: z.string().default('dsh-secrets'),
  })).default({}),
  grantMinutes: z.number().min(1).default(30),
  maxGrantMinutes: z.number().min(1).default(240),
  handleMinutes: z.number().min(1).default(30),
  maxSecretsPerSession: z.number().min(1).default(20),
  minRedactLength: z.number().min(1).default(4),
})
