# Audit surface

The claim this plugin makes is "small enough to read before you trust it with a
vault". This page makes that claim checkable: every network call, process,
file and retained value, with the commands to confirm each one.

Numbers as of the current tree:

| | Count |
|---|---|
| Runtime TypeScript | 1935 lines (1834 without the diagnostic CLI) |
| Tests | 679 lines across three suites |
| Runtime dependencies | none. The `@deepseek-ai/*` packages are supplied by the host, and nothing else is imported at runtime |
| Outbound HTTP | one helper in `src/bitwarden/api.ts`, three endpoints |
| Child processes | one site in `src/provider.ts`, used only by command providers |
| Filesystem writes | one, in `src/redact.ts` |

Largest files, so a reader knows where to start:

| File | Lines | Role |
|---|---|---|
| `src/index.ts` | 707 | Tools, consent, unlocking, redaction listener |
| `src/bitwarden/api.ts` | 225 | The three endpoints |
| `src/provider.ts` | 186 | Command providers, the only child process |
| `src/bitwarden/crypto.ts` | 157 | Key schedule and ciphertext format |
| `src/grants.ts` | 130 | Scopes and consent records |
| `src/bitwarden/vault.ts` | 123 | Item lookup and field decryption |
| `src/bitwarden/provider.ts` | 119 | Per-session unlock |
| `src/live-check.ts` | 101 | Diagnostic CLI, not loaded by the host |

## Network

The only host contacted is the one in the provider's `server` setting:

| Request | Purpose |
|---|---|
| `POST {server}/identity/accounts/prelogin` | The account's KDF parameters |
| `POST {server}/identity/connect/token` | Password grant for one access token |
| `GET {server}/api/sync` | The encrypted vault, once per unlock |

There is no telemetry, no update check, no analytics, and no other URL in the
code base.

## Processes

- `kind: bitwarden` spawns nothing. The login, the sync and the decryption all
  run inside the dsh host process, which is what makes the grant binding.
- `kind: command` runs the command you configured, once per operation, as an
  argv array with no shell.

## Files

- The plugin reads and writes one kind of file: a shell spill file that the
  executor already wrote for truncated output, and only to replace a live value
  with `[redacted]`. It creates no files, keeps no cache, and writes no state.
- Nothing is read from a credential store, and no key material is written
  anywhere.

## Retained material

| Material | Lifetime |
|---|---|
| Decrypted vault: item names and item keys | One session, until `secret_lock`, grant loss, service restart, or the plugin unloading |
| Fetched values | One session, for `handleMinutes` after the last use |
| Consent grants | One session, until the TTL or `secret_lock` |
| Master password | One unlock call. Never stored |
| Access token | One sync. Never stored |

## What it never does

- Write to the vault. There is no create, edit, delete or share path.
- Store the master password or any key derived from it.
- Answer its own consent card. The owner's answer comes from the question card,
  and a subagent session cannot ask at all.
- Reach any host other than the configured server.

## How to check

```sh
rg -n "fetch\(" src              # one helper, in src/bitwarden/api.ts
rg -n "writeFile|appendFile|mkdir" src   # one spill-file scrub
rg -n "execFile|spawn" src       # one, the command provider
rg -n "process\.env" src         # the provider command's environment
rg -n "readFile" src             # the spill file only
```

## Honest limits

- **Same OS user.** A process running as your user could attach to the dsh
  process while a grant is live. That is the boundary that protects the rest of
  the host, and it is the same boundary every implementation that runs in your
  user session has.
- **Redaction is exact-text.** An encoded or transformed value is not caught,
  and values shorter than `minRedactLength` are not redacted at all.
- **Provider stderr is shown to the agent**, truncated to one line. A provider
  that printed a value on stderr while failing would leak it, since the value is
  not registered for redaction yet. That applies to command providers; the
  Bitwarden path has no child process to leak from.
- **Node strings cannot be zeroed.** Locking drops the reference to the keys, it
  does not scrub memory.
