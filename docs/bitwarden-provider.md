# Bitwarden and Vaultwarden access model

Design note for adding a first-party Bitwarden/Vaultwarden provider to this
plugin. It records why the obvious implementation is rejected, what the access
model is, and what it costs to build.

## The requirement

The owner supplies the **master password**. Everything else about the account,
including the email, may be known to the agent. The account email is not merely
allowed to be public: Bitwarden derives the master key from
`PBKDF2(password, lowercased email, iterations)`, so the email is the salt and
the client has to know it.

The property is that consent is **binding**, not advisory: an agent that wanted
to bypass the owner's grant could not read a value outside it, because it does
not hold anything that unlocks the vault.

## Why a vault CLI cannot provide it

The command-provider design in this plugin is right for `op`, `pass` and
`sops`, but both available Bitwarden clients fail the property:

- **`rbw`** keeps an unlocked vault in `rbw-agent` and every `rbw` invocation
  talks to that agent. Any process running as the same user can also talk to
  it, so once the owner unlocks, the agent can call `rbw get` directly and the
  grant scope is gone.
- **`bw`** does not persist a session, which is better, but the session key has
  to be handed to each `bw` child through its environment or argv. Any process
  running as the same user can read `/proc/<pid>/environ` and
  `/proc/<pid>/cmdline` of that child, take the key, and then call `bw` freely.

Both routes leave an unlocked or unlockable vault reachable by the agent's own
shell. Redaction does not help, because the agent would use the key without
printing it.

## The design: login and decrypt inside the host process

The provider becomes a second provider kind, not a command template:

```yaml
providers:
  vault:
    kind: bitwarden
    email: agent@example.com        # not a secret; the KDF salt
    server: https://vault.example.com
```

Flow:

1. **Unlock is a separate, owner-gated step.** A grant is created by
   `secret_request` exactly as it is today. If the account is locked, the
   plugin asks the owner for the master password through a masked field, uses
   it once, and never stores it.
2. **The plugin talks to the server itself.** Prelogin for KDF parameters,
   password grant for tokens, sync for the encrypted vault. No CLI, no child
   process, no unlocked service.
3. **Only the granted items are decrypted.** Ciphers are filtered by name and
   collection against the grant scope before any key is touched, so the scope
   is enforced by the code that holds the keys rather than by a convention.
4. **Values travel to commands, never to the model.** `secret_fetch` returns a
   handle, and the value reaches the shell as `$DSH_SECRET_<handle>` through the
   environment contributor this plugin already has.
5. **Lock drops the keys.** `secret_lock`, the end of a grant, or the idle
   window discards the derived user key and access token from memory. There is
   no standing unlock to reuse.

The agent ends up holding: the email, the server URL, item names it is granted,
and handles. It never holds the master password, the master key, the user key,
or an access token.

## Protocol steps

Written down so the implementation is reviewable before it exists.

1. `POST /accounts/prelogin` `{ email }` returns the account's KDF:
   `{ Kdf, KdfIterations, KdfMemory, KdfParallelism }`.
2. `masterKey = PBKDF2-SHA256(NFKD(password), lowercase(email), iterations, 32)`.
   `Kdf = 0` is PBKDF2; `Kdf = 1` is Argon2id.
3. `stretchedEnc = HKDF-Expand-SHA256(masterKey, info="enc", 32)`,
   `stretchedMac = HKDF-Expand-SHA256(masterKey, info="mac", 32)`.
4. `masterPasswordHash = base64(PBKDF2-SHA256(masterKey, password, 1, 32))`.
5. `POST /identity/connect/token`, form-encoded:
   `grant_type=password`, `username`, `password=<masterPasswordHash>`,
   `scope=api offline_access`, `client_id=cli`, `deviceType`,
   `deviceIdentifier=<stable uuid>`, `deviceName`. The response carries
   `access_token`, `refresh_token`, and the encrypted user key.
6. `GET /sync` with the bearer token returns `profile.key` and the encrypted
   ciphers.
7. `userKey = AES-256-CBC-HMAC-SHA256-decrypt(profile.key, stretched keys)`,
   giving 64 bytes: 32 byte enc key and 32 byte mac key.
8. `itemKey = cipher.key ? decrypt(cipher.key, userKey) : userKey`, then each
   field is an `EncString` of the form `2.<iv>|<ct>|<mac>` decrypted with the
   item key.

An account with two factor enabled returns a second-factor challenge instead of
tokens. A dedicated agent account should not use 2FA: the master password is the
gate, and a TOTP second factor would have to become another secret in the same
place.

## Cost

- Crypto: PBKDF2 and HKDF are in `node:crypto`; the EncString format is
  AES-CBC plus HMAC, also built in. Argon2id accounts need an extra dependency
  (a WASM implementation, not a native build), so supporting them is a separate
  decision.
- HTTP: three endpoints, form encoding, and one JSON model. No SDK, which also
  avoids depending on Bitwarden's unsupported `sdk-internal` package (GPL, no
  support) or on `sdk-napi` (Secrets Manager only, token-based, and not
  implemented by Vaultwarden).
- Entry of the master password needs a masked field. Two options are in
  [the plugin README](https://github.com/theoabw/dsh-secrets#masked-entry): use the `dsh-secret` header
  that a companion prompt plugin already renders masked, or ship a small client
  half of our own for a dependency-free public install.
- Verification needs a real account on the target server. A dedicated account
  with no 2FA, one collection, and a few throwaway items is enough.

## Residual risks

- The master key lives in the dsh process memory while a grant is live. A
  hostile process running as the same OS user is the only thing that could read
  it, which is the same boundary that protects the rest of the host. This is
  strictly stronger than the CLI routes, where the credential is reachable
  through `/proc` by any same-user process.
- Node strings cannot be reliably zeroed, so "locked" means the reference is
  dropped, not that the memory is scrubbed.
- A sync pulls the whole vault over the wire, even though only granted items
  are decrypted. The server sees a normal client sync, and the decrypt step is
  what enforces scope.

## Status

Implemented, and verified in three layers:

1. **Key schedule**: known-answer tests against independent implementations
   (Python `cryptography` for HKDF-Expand and AES-CBC-HMAC, OpenSSL and Python
   for PBKDF2). A self-consistent test would pass with a wrong derivation, so
   this is the layer that proves the keys match Bitwarden's.
2. **Flow**: a local server stands in for the vault and serves a vault
   encrypted with the real key schedule, so prelogin, the password grant, sync,
   key unwrap, decryption, per-session unlock and locking all run for real.
3. **Live**: against a Vaultwarden account, login, sync, item-name decryption
   and password decryption succeed, checked with `lib/live-check.js` so no value
   is ever printed.

Not implemented, on purpose:

- **Argon2id accounts.** Prelogin reports the KDF, and an Argon2id account is
  refused with an actionable message rather than silently deriving a wrong key.
  Supporting it needs one WASM dependency.
- **Two-factor accounts.** The token endpoint's second-factor challenge is
  reported, not retried. A dedicated agent account should rely on the master
  password alone.
- **Writes.** The provider is read-only: no creating, editing or deleting
  items, so the plugin cannot be used to plant or alter data in the vault.

## Still to do before publishing

- Masked entry currently relies on a companion plugin rendering the
  `dsh-secret` header. Ship a small client half of our own so a public install
  does not need the companion to get a concealed field.
