/**
 * Host-half test for @theoabw/dsh-secrets.
 *
 * Loads the BUILT lib/index.js and drives apply() against a minimal mock
 * cordis context: captures the registered tools, the shellEnv contributors,
 * the consent card, and the post-execute listener, then walks the whole
 * consent -> fetch -> use -> redact -> lock lifecycle without a real harness.
 *
 * The provider is a real child process (node printing a value), so the test
 * exercises argv expansion, spawn, stdout capture, and failure handling for
 * real. Run: node scripts/smoke-test.mjs
 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const plugin = require('../lib/index.js')

/** Value the fake provider prints for an item, so assertions can name it. */
const valueOf = (item) => `s3cret-${item}-value`

/** Build a mock context that captures everything apply() touches. */
function mockContext(config) {
  const captured = {
    tools: new Map(),
    contributors: new Map(),
    postExecuteListener: null,
    askedQuestions: null,
    systemPromptSections: [],
    effects: [],
  }
  let askAnswer = null
  const ctx = {
    shellEnv: {
      register(contributor) {
        const envKey = Object.keys(contributor.variables)[0]
        assert.ok(!captured.contributors.has(envKey), `duplicate contributor ${envKey}`)
        captured.contributors.set(envKey, contributor)
        const disposer = () => { captured.contributors.delete(envKey) }
        return disposer
      },
    },
    tools: {
      register(tool) {
        assert.ok(!captured.tools.has(tool.name), `duplicate tool ${tool.name}`)
        captured.tools.set(tool.name, tool)
        return () => { captured.tools.delete(tool.name) }
      },
    },
    userQuestions: {
      async ask(request) {
        captured.askedQuestions = request
        if (askAnswer === null) throw new Error('test: no ask answer configured')
        return askAnswer
      },
    },
    on(name, listener) {
      assert.equal(name, 'tools/post-execute')
      captured.postExecuteListener = listener
      return () => { captured.postExecuteListener = null }
    },
    effect(callback) {
      const disposer = callback()
      if (typeof disposer === 'function') captured.effects.push(disposer)
      return () => { captured.effects.length = 0 }
    },
    systemPrompt: {
      section(section) { captured.systemPromptSections.push(section) },
    },
  }
  plugin.apply(ctx, config)
  return { captured, setAskAnswer: (answer) => { askAnswer = answer } }
}

/** A minimal exec carrier for the tools. */
function execFor(sessionId) {
  return {
    agent: { session: { header: { id: sessionId } } },
    signal: new AbortController().signal,
  }
}

/** A provider command that prints one value, used for every happy path. */
const printValue = [process.execPath, '-e', 'process.stdout.write("s3cret-" + process.argv[1] + "-value\\n")', '{item}']

const baseConfig = {
  providers: {
    vault: {
      command: printValue,
      list: [process.execPath, '-e', 'process.stdout.write("deploy-db\\ngithub-token\\n")'],
      timeoutMs: 5000,
      env: {},
    },
    exact: {
      command: printValue,
      list: [],
      timeoutMs: 5000,
      env: {},
    },
  },
  grantMinutes: 30,
  maxGrantMinutes: 240,
  handleMinutes: 30,
  maxSecretsPerSession: 2,
  minRedactLength: 4,
}

const allowShort = 'Allow for 30 min'
const allowSession = 'Allow until this session ends'
const denyLabel = 'Deny'

const sessionId = 'sess-a'
const otherSession = 'sess-b'
const { captured, setAskAnswer } = mockContext(baseConfig)

/* 1. Registration. */
for (const name of ['secret_request', 'secret_fetch', 'secret_list', 'secret_status', 'secret_lock']) {
  assert.ok(captured.tools.get(name), `${name} registered`)
}
assert.equal(captured.systemPromptSections.length, 1)
assert.equal(captured.systemPromptSections[0].name, 'tool:secrets')
assert.match(captured.systemPromptSections[0].text, /secret_request/)

const request = captured.tools.get('secret_request')
const fetchValue = captured.tools.get('secret_fetch')
const list = captured.tools.get('secret_list')
const status = captured.tools.get('secret_status')
const lock = captured.tools.get('secret_lock')

/* 2. Status lists providers and is ready. */
const before = await status.execute({}, execFor(sessionId))
assert.deepEqual(before.providers.map((provider) => provider.id).sort(), ['exact', 'vault'])
assert.ok(before.providers.every((provider) => provider.ready), 'both fake providers resolve')
assert.deepEqual(before.grants, [], 'a fresh session holds no grant')
assert.equal(before.values, 0)

/* 3. No grant means no value. */
await assert.rejects(
  () => fetchValue.execute({ provider: 'vault', item: 'deploy-db' }, execFor(sessionId)),
  /no grant for provider "vault"/,
)

/* 4. Consent card shape, and a denial grants nothing. */
setAskAnswer({ answers: [{ id: 'consent', selected: [denyLabel] }] })
const denied = await request.execute({ provider: 'vault', reason: 'deploy the site' }, execFor('sess-deny'))
assert.equal(denied.granted, false)
assert.match(denied.note, /denied/)
const question = captured.askedQuestions.questions[0]
assert.equal(question.id, 'consent')
assert.equal(question.intent.kind, 'approval')
assert.equal(question.intent.approve, allowShort)
assert.equal(question.intent.reject, denyLabel)
assert.equal(question.intent.always, allowSession)
assert.match(question.detail, /Reason given by the agent \(unverified\): deploy the site/)
assert.equal(captured.askedQuestions.agent.session.header.id, 'sess-deny')

/* 5. Allow for a session, then fetch: the result carries a handle, not a value. */
setAskAnswer({ answers: [{ id: 'consent', selected: [allowSession] }] })
const granted = await request.execute({ provider: 'vault' }, execFor(sessionId))
assert.equal(granted.granted, true)
assert.equal(granted.provider, 'vault')
assert.equal(granted.scope, '*')
assert.equal(granted.expiresAt, undefined, 'session-long grant has no expiry')

const fetched = await fetchValue.execute({ provider: 'vault', item: 'deploy-db' }, execFor(sessionId))
assert.match(fetched.handle, /^[0-9A-F]{20}$/, `handle shape: ${fetched.handle}`)
assert.equal(fetched.env, `DSH_SECRET_${fetched.handle}`)
assert.equal(fetched.item, 'deploy-db')
assert.ok(!JSON.stringify(fetched).includes(valueOf('deploy-db')), 'the result never carries the value')

const contributor = captured.contributors.get(fetched.env)
assert.ok(contributor, 'a contributor is registered for the handle')
assert.equal(contributor.resolve(execFor(sessionId))[fetched.env], valueOf('deploy-db'), 'the owner session sees the value')
assert.deepEqual(contributor.resolve(execFor(otherSession)), {}, 'another session does not')

/* 6. Redaction of every model-visible shape while the value is live. */
const listener = captured.postExecuteListener
const accept = { kind: 'accept' }
const plain = await listener(
  { name: 'bash' },
  { content: [{ type: 'text', text: `leak: ${valueOf('deploy-db')} here` }] },
  async () => accept,
)
assert.equal(plain.content[0].text, 'leak: [redacted] here')

const blocked = await listener({ name: 'bash' }, { content: [] }, async () => ({
  kind: 'block',
  feedback: [{ type: 'text', text: `failed on ${valueOf('deploy-db')}` }],
}))
assert.equal(blocked.feedback[0].text, 'failed on [redacted]')

const replaced = await listener({ name: 'bash' }, { content: [] }, async () => ({
  kind: 'accept',
  value: { lines: [valueOf('deploy-db'), { nested: valueOf('deploy-db') }] },
}))
assert.deepEqual(replaced.value.lines, ['[redacted]', { nested: '[redacted]' }])

const dir = mkdtempSync(join(tmpdir(), 'dsh-secrets-test-'))
try {
  const spill = join(dir, 'spill.log')
  writeFileSync(spill, `captured ${valueOf('deploy-db')} in a spill file`)
  await listener(
    { name: 'bash' },
    { content: [{ type: 'text', text: 'truncated' }], value: { stdout: { spillPath: spill } } },
    async () => accept,
  )
  assert.equal(readFileSync(spill, 'utf8'), 'captured [redacted] in a spill file')
} finally {
  rmSync(dir, { recursive: true, force: true })
}

/* 7. Scope: a prefix grant covers matching items and nothing else. */
setAskAnswer({ answers: [{ id: 'consent', selected: [allowShort] }] })
const scoped = await request.execute({ provider: 'vault', scope: 'github*' }, execFor('sess-scope'))
assert.equal(scoped.granted, true)
assert.match(scoped.expiresAt, /^\d{4}-/, 'the short option comes back with an expiry')
await assert.rejects(
  () => fetchValue.execute({ provider: 'vault', item: 'deploy-db' }, execFor('sess-scope')),
  /no grant for provider "vault" covering "deploy-db"/,
)
const listed = await list.execute({ provider: 'vault' }, execFor('sess-scope'))
assert.deepEqual(listed.names, ['github-token'], 'listing is filtered by the grant scope')

/* 8. A provider that fails surfaces a clean error, and no value. */
const failing = mockContext({
  ...baseConfig,
  providers: {
    broken: {
      command: [process.execPath, '-e', 'process.stderr.write("vault is locked\\n"); process.exit(3)'],
      list: [],
      timeoutMs: 5000,
      env: {},
    },
  },
})
failing.setAskAnswer({ answers: [{ id: 'consent', selected: [allowSession] }] })
await failing.captured.tools.get('secret_request').execute({ provider: 'broken' }, execFor('sess-fail'))
await assert.rejects(
  () => failing.captured.tools.get('secret_fetch').execute({ provider: 'broken', item: 'x' }, execFor('sess-fail')),
  /provider "broken": the command failed \(exit 3\): vault is locked/,
)

/* 9. Unknown provider, and the single-provider default. */
await assert.rejects(
  () => fetchValue.execute({ provider: 'nope', item: 'x' }, execFor(sessionId)),
  /unknown provider "nope"/,
)
setAskAnswer({ answers: [{ id: 'consent', selected: [allowSession] }] })
const defaulted = await failing.captured.tools.get('secret_request').execute({}, execFor('sess-default'))
assert.equal(defaulted.provider, 'broken', 'one configured provider needs no name')

/* 10. The consent cooldown stops a second card in the same session. */
await assert.rejects(
  () => failing.captured.tools.get('secret_request').execute({}, execFor('sess-default')),
  /just answered for this session/,
)

/* 11. Locking forgets values and grants, and disposes the contributor. */
const lockedOne = await lock.execute({ handle: fetched.handle }, execFor(sessionId))
assert.deepEqual(lockedOne, { revoked: 1, locked: false })
assert.equal(captured.contributors.has(fetched.env), false, 'the contributor was disposed')

const second = await fetchValue.execute({ provider: 'vault', item: 'github-token' }, execFor(sessionId))
assert.equal(second.provider, 'vault')
await assert.rejects(
  () => fetchValue.execute({ item: 'github-token' }, execFor(sessionId)),
  /name a provider: vault, exact/,
  'two configured providers make the provider name mandatory',
)
const lockedAll = await lock.execute({}, execFor(sessionId))
assert.deepEqual(lockedAll, { revoked: 1, locked: true })
const after = await status.execute({}, execFor(sessionId))
assert.deepEqual(after.grants, [])
assert.equal(after.values, 0)
await assert.rejects(
  () => fetchValue.execute({ provider: 'vault', item: 'github-token' }, execFor(sessionId)),
  /no grant for provider "vault"/,
)

/* 12. No agent means no session-scoped secret. */
await assert.rejects(
  () => fetchValue.execute({ item: 'x' }, { signal: new AbortController().signal }),
  /requires an agent-owned session/,
)

/* 13. The config schema accepts the documented shape and applies defaults. */
const schema = plugin.Config
assert.equal(typeof schema, 'function', 'Config is a schema value')
const validated = schema({
  providers: {
    vault: { command: ['rbw', 'get', '{item}'], list: [] },
  },
})
assert.equal(validated.grantMinutes, 30)
assert.equal(validated.providers.vault.timeoutMs, 15000)

const effects = captured.effects
for (const disposer of effects) disposer()

console.log('dsh-secrets: smoke test passed')
