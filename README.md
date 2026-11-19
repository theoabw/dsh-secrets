# @theoabw/dsh-secrets

[![npm](https://img.shields.io/npm/v/@theoabw/dsh-secrets?label=npm)](https://www.npmjs.com/package/@theoabw/dsh-secrets)

English | [中文](https://github.com/theoabw/dsh-secrets/blob/main/README.zh.md)

Consent-gated secret brokering for [deepseek-harness](https://github.com/deepseek-ai/deepseek-harness)
(dsh).

Giving an agent a credential usually means pasting it into the conversation.
That puts the value in the transcript, the session log, the trajectory, and
every later compaction of the context. This plugin removes that step. The agent
asks for a secret by name, **you** approve access for that session, and the
value travels from your password manager straight into the environment of the
shell command that needs it. The model only ever sees a handle:

```
secret_request   -> you allow this session to read from "vault"
secret_fetch     -> { handle: "A1B2…", env: "DSH_SECRET_A1B2…" }
$DSH_SECRET_A1B2… -> the value, inside your command
```

There is no vault protocol in this plugin and no stored credential. Providers
are ordinary commands, so whatever CLI already owns your vault keeps owning it.

This is the broker half of a pair.
[dsh-secret-prompt](https://github.com/theoabw/dsh-secret-prompt) is the ask
half: one credential, typed into a masked field mid-task.

## Why it is built this way

- **The agent never receives the value.** The tool result carries a handle and
  the name of an environment variable. The harness injects the real value into
  the command's process environment, the same channel it uses for
  `DSH_SESSION_ID`.
- **Access is per session and starts closed.** A fresh session can read nothing.
  Consent is your click, it is scoped, it is time-bounded, and it dies with the
  session or with a service restart.
- **The vault login never reaches the agent.** For a command provider, `op`,
  `pass` or your own script owns its own authentication in your terminal. For
  `kind: bitwarden`, the master password is used inside the host process and
  dropped, so the agent cannot reach the vault on its own. Nothing is written
  to disk either way.
- **Leaks are contained.** While a value is live, every model-visible tool
  result is rewritten to `[redacted]`, and temporary files the shell wrote for
  truncated output are scrubbed in place.

## Why this exists next to a bigger vault plugin

There is a mature Vaultwarden plugin for dsh with a vault browser, write
support, passkey export and a settings page. This one is deliberately smaller,
because handing an integration of that size your vault is a decision not
everyone wants to make:

- 1935 lines of runtime TypeScript, no runtime dependencies, and three HTTP
  endpoints on the one host you configure.
- No write path into the vault. No cache, no state file, no stored master
  password.
- A fetched value never comes back to the model. It goes into the command's
  environment and nowhere else.
- Consent is a scoped, time-bounded grant per session, and the model cannot
  answer its own consent card.

[docs/audit.md](https://github.com/theoabw/dsh-secrets/blob/main/docs/audit.md) lists every network call, process, file and
retained value, with the grep commands to verify each one. If you want features
over surface, use the bigger plugin; the two are not competitors at the same
scope.

## Install

```sh
dsh plugin --profile web add @theoabw/dsh-secrets
```

Then add the loader row to your profile patch (`~/.dsh/profiles/<name>/cordis.patch.yml`):

```yaml
- insert:
    - id: secrets
      name: '@theoabw/dsh-secrets'
      config:
        providers:
          vault:
            command: ["rbw", "get", "{item}", "--field", "{field}"]
            list: ["rbw", "list"]
        grantMinutes: 30
```

The plugin exists only in the host half, so a service restart (`dsh.service`)
is what makes it appear. Restarting ends live sessions.

### From a checkout

```sh
git clone https://github.com/theoabw/dsh-secrets
cd dsh-secrets
pnpm install
bash scripts/link-deps.sh   # symlink the running dsh install's @deepseek-ai packages
pnpm run build              # produces lib/, which the profile installs
dsh plugin --profile web add "file:$PWD"
```

`pnpm run check` runs the typecheck, the build, and the three test suites.

## Configure providers

A provider is an argv template, run without a shell. `{item}` and `{field}` are
substituted from the tool call, `{query}` from `secret_list`, and the command's
stdout is the value.

| Vault | `command` | `list` |
|---|---|---|
| Bitwarden / Vaultwarden | `kind: bitwarden`, see below | built in |
| rbw | `["rbw", "get", "{item}", "--field", "{field}"]` | `["rbw", "list"]` |
| 1Password | `["op", "read", "op://{item}/{field}"]` | `["op", "item", "list", "--format", "json"]` |
| pass | `["pass", "show", "{item}"]` | `["pass", "ls"]` |
| sops | `["sops", "-d", "--extract", "[\"{item}\"]", "secrets.enc.yaml"]` | |

For Bitwarden and Vaultwarden, `rbw` is the easiest fit: it keeps an unlocked
agent in memory, so no session key ever becomes a dsh value. Point it at your
server once with `rbw config set base_url https://vault.example.com`, then
`rbw register` and `rbw unlock` in your own terminal.

`list` is optional. Without it, `secret_list` tells the agent to name the item
itself.

### Masked entry

When the plugin asks the owner for a value, it sends the question with the
`dsh-secret` header. [dsh-secret-prompt](https://github.com/theoabw/dsh-secret-prompt)
renders masked fields for that header, and the plugin asks for the master
password that way. Without it the question falls back to the generic card, which
is not masked, so install the companion before using this for anything that
matters. The two are designed together: one asks for a single credential, the
other brokers scoped access to a provider.

## Bitwarden and Vaultwarden

`kind: bitwarden` logs in and decrypts inside the host process, which is what
makes the grant binding rather than advisory:

- You supply the master password once per session, in a masked field.
- The plugin derives the keys, logs in, and syncs. Only the granted items are
  decrypted. The password and the derived keys are then dropped.
- No session token is handed to a child process and no unlocked agent is left
  running, so there is nothing for another process to reuse.
- The agent ends up holding the email, the server URL, item names you granted,
  and handles. Not the password, not the master key, not the user key.

```yaml
providers:
  vault:
    kind: bitwarden
    email: agent@example.com          # the KDF salt, not a secret
    server: https://vault.example.com
```

`secret_lock` drops the keys, and so does losing the grant that justified them.

Requirements: an account whose KDF is PBKDF2 (the default) and which does not
use two-factor authentication. An Argon2id account is refused with a clear
error, and a 2FA challenge is reported rather than retried, because a TOTP
secret would have to live in the same place as the password.

Check an account without dsh:

```sh
node lib/live-check.js --server https://vault.example.com \
  --email agent@example.com --password-env VAULT_PASSWORD
```

It prints the KDF parameters, the item count, and the item names, and never
prints a value. The password comes from the named environment variable, so it
stays out of the process arguments.

The design and the protocol steps are in
[docs/bitwarden-provider.md](https://github.com/theoabw/dsh-secrets/blob/main/docs/bitwarden-provider.md).

## Tools

| Tool | What it does |
|---|---|
| `secret_request` | Asks you for a grant: provider, scope, reason, and how long. Options are a short allow, an allow until the session ends, or deny. |
| `secret_fetch` | Reads one item through the provider and returns `{ handle, env }`. Requires a grant that covers the item. |
| `secret_list` | Item names visible under the current grant. Names only, never values. |
| `secret_status` | Configured providers, whether each command is available, this session's grants, live value count. |
| `secret_lock` | Forget one handle, or drop every value and grant for this session. |

Scopes: `*` for every item, a prefix ending in `*` such as `deploy*`, or one
exact item name.

## What a session looks like

```
secret_request  provider="vault" scope="deploy*" reason="read the deploy token"
                -> owner allows for 30 min
secret_fetch    item="deploy-token" field="password"
                -> { handle: "9F3A…", env: "DSH_SECRET_9F3A…" }
bash            curl -H "Authorization: Bearer $DSH_SECRET_9F3A…" https://…
secret_lock
```

## Threat model

What is protected:

- The value never appears in the agent's context, the conversation, the session
  JSONL, or any log written by this plugin.
- The value is never persisted: it lives in host process memory, keyed by a
  random handle, and is forgotten after `handleMinutes` without use.
- A session cannot read a provider it was not granted, cannot read an item
  outside the grant's scope, and cannot answer its own consent card. Consent
  cards are refused for subagent sessions.
- Access can be withdrawn at any time with `secret_lock`, and it never outlives
  the session or the service.

What is deliberately not protected, and why:

- **A granted session can exfiltrate a value** through a command it is allowed
  to run (`echo $DSH_SECRET_x | base64`). A value has to pass through the
  command's process space to be usable, so consent is a policy gate and
  redaction is a safety net, not a sandbox.
- **The same OS user can read the process environment and the child process**
  that carries the value. Isolating secrets from an agent that runs as you
  needs an OS boundary, not a plugin.
- **Redaction matches exact text.** An encoded or transformed value is not
  caught. Values shorter than `minRedactLength` are not redacted at all, so a
  pathological one-character secret cannot destroy every tool result.
- **The master password is used inside the dsh process.** While a grant is
  live, the derived keys are in that process's memory. A hostile process
  running as the same OS user is the only thing that could read them, which is
  the same boundary that protects the rest of the host, and it is strictly
  stronger than a CLI, where the credential is reachable through `/proc`.
- **A provider's error text is shown to the agent**, truncated to one line,
  because "vault is locked" is what makes a failure actionable. A provider that
  printed a value on stderr while failing would leak it, since the value is not
  registered for redaction yet. Treat your provider CLI's error output as part
  of the trust surface.

## Non-goals

- Implementing a vault protocol, or syncing your vault.
- Storing the vault login, or storing any secret at rest.
- Remote or out-of-band approvals, multi-user deployments, hardware tokens.
- Sandboxing the agent. See the threat model above.

## Configuration reference

| Field | Default | Meaning |
|---|---|---|
| `providers` | `{}` | Provider id to `{ command, list, timeoutMs, env }`. |
| `grantMinutes` | `30` | Minutes offered by the short allow choice. |
| `maxGrantMinutes` | `240` | Ceiling for a requested grant. |
| `handleMinutes` | `30` | Idle minutes before a fetched value is forgotten. |
| `maxSecretsPerSession` | `20` | Live values per session. |
| `minRedactLength` | `4` | Shortest value that is redacted from output. |

## Development

```sh
pnpm run typecheck
pnpm run build
pnpm test
```

Three suites run against the built `lib/`:

- `crypto-test.mjs` checks the Bitwarden key schedule against independent
  implementations. The expected master key, stretched keys, login hash and
  ciphertext were produced with Python's `cryptography` and OpenSSL, not with
  this code, because a self-consistent test passes with a wrong key schedule.
- `smoke-test.mjs` drives the plugin: registration, consent card shape, grant
  scopes, a real provider command, per-session injection, redaction of content,
  feedback, value replacements and spill files, and locking.
- `bitwarden-test.mjs` stands a local HTTP server in place of the vault and
  serves a vault encrypted with the real key schedule, so prelogin, the
  password grant, sync, key unwrap, decryption and locking are exercised end
  to end without a server.

## Related work

The broker pattern is not new, and several projects take the same "values never
reach the model" stance. This plugin exists for the dsh case where a small,
auditable surface matters more than feature coverage.

- [dsh-vaultwarden](https://github.com/BuvkB/dsh-vaultwarden): the full-featured
  Vaultwarden integration for dsh, with a vault browser, writes and passkeys.
- [dsh-key-panel](https://github.com/MoruTeaven/dsh-key-panel): injects API keys
  into the assistant shell as `$DSH_*` variables.
- [dsh-safebox](https://github.com/jiangzhenguo/dsh-safebox): write-only
  credentials with metadata-only access for the agent.
- [agent-secret](https://github.com/kovyrin/agent-secret): a macOS approval
  broker that injects approved secrets into one child process.
- [secret-broker](https://pypi.org/project/secret-broker/): a federated facade
  over AWS, 1Password and Vault with references in and values never out.

## License

MIT

## See also

[dsh-secret-prompt](https://github.com/theoabw/dsh-secret-prompt) is the ask
half: a `prompt_secret` tool that collects one credential in a masked GUI field
and exposes it only as `$DSH_SECRET_<handle>`. This plugin builds on the same
convention for the questions it asks.
