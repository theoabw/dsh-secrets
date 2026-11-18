/**
 * Diagnostic for one Bitwarden/Vaultwarden account, without dsh.
 *
 * It runs the same code path the plugin does (prelogin, password grant, sync,
 * key unwrap, item decryption) and prints only shapes and lengths. A secret
 * value is never printed, so running this is safe in a terminal whose scrollback
 * someone else may read.
 *
 *   node lib/live-check.js \
 *     --server https://vault.example.com \
 *     --email agent@example.com \
 *     --password-env VAULT_PASSWORD
 *
 * The password comes from the named environment variable, so it stays out of
 * the process arguments and the shell history. Export it for this one command
 * and unset it afterwards.
 */
import { endpointsFor, login, prelogin, sync } from './bitwarden/api'
import { deriveMasterKey, loginHash, stretchKey } from './bitwarden/crypto'
import { Vault } from './bitwarden/vault'

/** Fixed device identity, so a diagnostic does not look like a new device each run. */
const DEVICE_ID = '11111111-1111-4111-8111-111111111111'

interface Options {
  server: string
  email: string
  passwordEnv: string
  item?: string
  field?: string
}

function parseArgs(argv: readonly string[]): Options {
  const values = new Map<string, string>()
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === undefined || !arg.startsWith('--')) continue
    const name = arg.slice(2)
    const value = argv[index + 1]
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`--${name} needs a value`)
    }
    values.set(name, value)
    index += 1
  }
  const server = values.get('server')
  const email = values.get('email')
  const passwordEnv = values.get('password-env')
  if (server === undefined || email === undefined || passwordEnv === undefined) {
    throw new Error('usage: live-check.js --server URL --email ADDRESS --password-env VAR [--item NAME] [--field FIELD]')
  }
  return {
    server,
    email,
    passwordEnv,
    ...(values.get('item') === undefined ? {} : { item: values.get('item') }),
    ...(values.get('field') === undefined ? {} : { field: values.get('field') }),
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2))
  const password = process.env[options.passwordEnv]
  if (password === undefined || password === '') {
    throw new Error(`the environment variable ${options.passwordEnv} is empty or unset`)
  }
  const endpoints = endpointsFor(options.server)
  const timeoutMs = 15_000

  const params = await prelogin(endpoints, options.email, timeoutMs)
  console.log(`prelogin: kdf=${params.kdf} iterations=${params.iterations}`)

  const masterKey = deriveMasterKey(password, options.email, params)
  const tokens = await login(endpoints, {
    email: options.email,
    passwordHash: loginHash(masterKey, password),
    deviceIdentifier: DEVICE_ID,
    deviceName: 'dsh-secrets live check',
    timeoutMs,
  })
  console.log('login: ok')

  const synced = await sync(endpoints, tokens.accessToken, timeoutMs)
  console.log(`sync: ${synced.ciphers.length} item(s)`)

  const profileKey = synced.profileKey ?? tokens.encryptedKey
  if (profileKey === undefined) throw new Error('no encrypted user key in the response')
  const vault = Vault.open(stretchKey(masterKey), profileKey, synced.ciphers)
  const names = vault.names()
  console.log(`items: ${names.length === 0 ? '(none)' : names.map((name) => JSON.stringify(name)).join(', ')}`)

  if (options.item !== undefined) {
    const value = vault.read(options.item, options.field)
    console.log(`item ${JSON.stringify(options.item)} field ${JSON.stringify(options.field ?? 'password')}: ${value.length} character(s), decrypted`)
  }
}

main().catch((error: unknown) => {
  console.error(`live check failed: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
