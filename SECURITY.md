# Security policy

This plugin brokers secrets for an agent under an owner-granted, per-session
consent. The invariants below are what a report should be measured against.

## Reporting

Use GitHub's private "Report a vulnerability" form on this repository, or email
theo@tabw.dev. Please do not open a public issue for a vulnerability.

## Invariants

- A session starts with no access, and a grant is scoped, time-bounded, and
  revocable.
- A value never appears in a tool result, the conversation, the trajectory or
  the session log. It reaches a shell command's environment and nothing else.
- The master password for a Bitwarden provider is used once per session and
  never stored. The derived keys live in host memory until the grant ends.
- The plugin has no write path into a vault. It cannot create, edit or delete
  items.
- The only host contacted is the provider's configured server, and the only
  file written is a spill file that already contains a live value.

## Not protected

- **A granted session can exfiltrate a value** through a command it may run.
  Consent is a policy gate and redaction is a safety net, not a sandbox.
- **There is no OS boundary.** A process running as the same user can read the
  host process's memory while a grant is live.
- A provider's stderr is shown to the agent, truncated to one line, because
  "vault is locked" is what makes a failure actionable.
- Argon2id accounts are refused rather than supported, and a two-factor account
  is reported rather than retried.

## In scope for a report

- Reading a value without a grant, or outside the grant's scope.
- Getting a value into a model-visible result, the log or the trajectory.
- Reaching a host the provider configuration does not name.
- A write anywhere the audit page does not list.
- A consent question the model can answer itself.

## Supported versions

The latest published minor version receives fixes. This is a young project; pin
an exact version in your profile if you need a stable surface.
