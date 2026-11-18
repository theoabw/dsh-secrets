/**
 * End-to-end test for the in-process Bitwarden provider.
 *
 * A local HTTP server stands in for Vaultwarden and serves a real encrypted
 * vault: the profile key and the item fields are built with this plugin's own
 * crypto module, so the fetch path exercises prelogin, the password grant,
 * sync, key unwrapping, decryption, per-session unlock, and locking for real.
 *
 * Run: node scripts/bitwarden-test.mjs
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const plugin = require('../lib/index.js')
const {
  deriveMasterKey,
  stretchKey,
  loginHash,
  encryptBytes,
  encryptString,
  keyToBytes,
} = require('../lib/crypto.js')

const EMAIL = 'agent@example.com'
const PASSWORD = 'correct horse battery staple'
const ITERATIONS = 1 // a real account uses 600000; the flow is identical
const VALUE = 's3cret-from-vault'
const ITEM = 'deploy-token'

/* A real vault encrypted with the real key schedule. */
const masterKey = deriveMasterKey(PASSWORD, EMAIL, { kdf: 0, iterations: ITERATIONS })
const stretched = stretchKey(masterKey)
const userKey = { encKey: Buffer.alloc(32, 0x11), macKey: Buffer.alloc(32, 0x22) }
const profileKey = encryptBytes(keyToBytes(userKey), stretched)
const ciphers = [{
  id: 'cipher-1',
  type: 1,
  name: encryptString(ITEM, userKey),
  login: {
    password: encryptString(VALUE, userKey),
    username: encryptString('agent', userKey),
    totp: null,
  },
}]

/** Mutable server behaviour, so a test can make the server reject a login. */
const serverState = { twoFactor: false }
const expectedHash = loginHash(masterKey, PASSWORD)
const requests = []

const server = createServer((request, response) => {
  const chunks = []
  request.on('data', (chunk) => chunks.push(chunk))
  request.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf8')
    requests.push({ url: request.url, method: request.method, body })
    const send = (status, payload) => {
      response.writeHead(status, { 'Content-Type': 'application/json' })
      response.end(JSON.stringify(payload))
    }
    if (request.method === 'POST' && request.url === '/identity/accounts/prelogin') {
      const parsed = JSON.parse(body)
      if (parsed.email !== EMAIL) return send(404, { error: 'unknown account' })
      return send(200, { kdf: 0, kdfIterations: ITERATIONS })
    }
    if (request.method === 'POST' && request.url === '/identity/connect/token') {
      const form = new URLSearchParams(body)
      if (serverState.twoFactor) {
        return send(400, { error: 'invalid_grant', error_description: 'Two factor required.', TwoFactorProviders: [0] })
      }
      if (form.get('username') !== EMAIL || form.get('password') !== expectedHash) {
        return send(400, { error: 'invalid_grant', error_description: 'Invalid credentials.' })
      }
      if (form.get('grant_type') !== 'password' || form.get('scope') !== 'api offline_access') {
        return send(400, { error: 'invalid_request' })
      }
      return send(200, { access_token: 'access-token-1', refresh_token: 'refresh-1', expires_in: 3600, Key: profileKey })
    }
    if (request.method === 'GET' && request.url === '/api/sync') {
      if (request.headers.authorization !== 'Bearer access-token-1') return send(401, {})
      return send(200, { profile: { key: profileKey }, ciphers })
    }
    return send(404, { error: 'not found' })
  })
})

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const base = `http://127.0.0.1:${server.address().port}`

/* A mock cordis context that captures the tools and plays the owner. */
function mockContext(config) {
  const captured = { tools: new Map(), contributors: new Map(), questions: [], sections: [], effects: [] }
  let answerFor = () => { throw new Error('test: no answer configured') }
  const ctx = {
    shellEnv: {
      register(contributor) {
        const envKey = Object.keys(contributor.variables)[0]
        captured.contributors.set(envKey, contributor)
        return () => captured.contributors.delete(envKey)
      },
    },
    tools: {
      register(tool) {
        captured.tools.set(tool.name, tool)
        return () => captured.tools.delete(tool.name)
      },
    },
    userQuestions: {
      async ask(request) {
        captured.questions.push(request)
        return answerFor(request)
      },
    },
    on() { return () => {} },
    effect(callback) {
      const disposer = callback()
      if (typeof disposer === 'function') captured.effects.push(disposer)
      return () => {}
    },
    systemPrompt: { section(section) { captured.sections.push(section) } },
  }
  plugin.apply(ctx, config)
  return { captured, setAnswer: (handler) => { answerFor = handler } }
}

const config = {
  providers: {
    vault: {
      kind: 'bitwarden',
      email: EMAIL,
      server: base,
      deviceIdentifier: 'test-device',
      deviceName: 'test',
      command: [],
      list: [],
      timeoutMs: 5000,
      env: {},
    },
  },
  grantMinutes: 30,
  maxGrantMinutes: 240,
  handleMinutes: 30,
  maxSecretsPerSession: 20,
  minRedactLength: 4,
}

const execFor = (sessionId) => ({
  agent: { session: { header: { id: sessionId } } },
  signal: new AbortController().signal,
})

const consentAnswer = { answers: [{ id: 'consent', selected: ['Allow until this session ends'] }] }
const passwordAnswer = (value) => ({ answers: [{ id: 'master', selected: [], custom: value }] })

try {
  /* 1. Status reports a locked, configured provider. */
  const { captured, setAnswer } = mockContext(config)
  const request = captured.tools.get('secret_request')
  const fetchValue = captured.tools.get('secret_fetch')
  const status = captured.tools.get('secret_status')
  const lock = captured.tools.get('secret_lock')

  const sessionId = 'sess-vault'
  const initial = await status.execute({}, execFor(sessionId))
  assert.equal(initial.providers[0].ready, true)
  assert.match(initial.providers[0].note, /locked/)

  /* 2. Consent grants access but does not unlock anything. */
  setAnswer(() => consentAnswer)
  const granted = await request.execute({ provider: 'vault', scope: '*' }, execFor(sessionId))
  assert.equal(granted.granted, true)
  assert.match(captured.questions[0].questions[0].detail, /master password/)
  assert.equal(requests.length, 0, 'consent alone never contacts the server')
  assert.match((await status.execute({}, execFor(sessionId))).providers[0].note, /locked/)

  /* 3. The first fetch asks for the master password and decrypts the value. */
  let askedPassword = null
  setAnswer((question) => {
    const item = question.questions[0]
    if (item.id === 'master') {
      askedPassword = item
      return passwordAnswer(PASSWORD)
    }
    return consentAnswer
  })
  const fetched = await fetchValue.execute({ provider: 'vault', item: ITEM }, execFor(sessionId))
  assert.ok(askedPassword, 'the master password was requested')
  assert.match(askedPassword.header, /^dsh-secret:/, 'the question carries the masked-card marker')
  assert.match(fetched.handle, /^[0-9A-F]{20}$/)
  assert.equal(fetched.env, `DSH_SECRET_${fetched.handle}`)
  assert.ok(!JSON.stringify(fetched).includes(VALUE), 'the result never carries the value')
  const contributor = captured.contributors.get(fetched.env)
  assert.equal(contributor.resolve(execFor(sessionId))[fetched.env], VALUE, 'the value reaches the shell environment')
  assert.deepEqual(contributor.resolve(execFor('someone-else')), {}, 'and only the owning session')

  /* 4. The wire is exactly what a Bitwarden server expects. */
  assert.deepEqual(requests.map((entry) => entry.url), [
    '/identity/accounts/prelogin',
    '/identity/connect/token',
    '/api/sync',
  ])
  const tokenBody = new URLSearchParams(requests[1].body)
  assert.equal(tokenBody.get('username'), EMAIL)
  assert.equal(tokenBody.get('password'), expectedHash)
  assert.equal(tokenBody.get('client_id'), 'cli')
  assert.ok(!requests.map((entry) => entry.body).join('').includes(PASSWORD), 'the raw password never leaves the process')

  /* 5. The vault is now unlocked for that session only. */
  assert.match((await status.execute({}, execFor(sessionId))).providers[0].note, /unlocked/)
  const otherStatus = await status.execute({}, execFor('another-session'))
  assert.match(otherStatus.providers[0].note, /locked/, 'another session gets nothing from this unlock')

  /* 6. A second fetch reuses the unlock instead of asking again. */
  const before = captured.questions.length
  const second = await fetchValue.execute({ provider: 'vault', item: ITEM, field: 'username' }, execFor(sessionId))
  assert.equal(captured.questions.length, before, 'no new password question')
  const secondContributor = captured.contributors.get(second.env)
  assert.equal(secondContributor.resolve(execFor(sessionId))[second.env], 'agent', 'another field comes from the same unlock')

  /* 7. Locking forgets the vault and the grants. */
  const locked = await lock.execute({}, execFor(sessionId))
  assert.equal(locked.locked, true)
  assert.match((await status.execute({}, execFor(sessionId))).providers[0].note, /locked/)
  await assert.rejects(
    () => fetchValue.execute({ provider: 'vault', item: ITEM }, execFor(sessionId)),
    /no grant for provider "vault"/,
  )

  /* 8. A wrong master password fails closed and leaves the vault locked. */
  const wrong = mockContext(config)
  wrong.setAnswer((question) => question.questions[0].id === 'master'
    ? passwordAnswer('not the password')
    : consentAnswer)
  await wrong.captured.tools.get('secret_request').execute({ provider: 'vault' }, execFor('sess-wrong'))
  await assert.rejects(
    () => wrong.captured.tools.get('secret_fetch').execute({ provider: 'vault', item: ITEM }, execFor('sess-wrong')),
    /the server rejected the login: Invalid credentials/,
  )
  const wrongStatus = await wrong.captured.tools.get('secret_status').execute({}, execFor('sess-wrong'))
  assert.match(wrongStatus.providers[0].note, /locked/)

  /* 9. Dismissing the password prompt grants nothing. */
  const dismissed = mockContext(config)
  dismissed.setAnswer((question) => question.questions[0].id === 'master'
    ? passwordAnswer('')
    : consentAnswer)
  await dismissed.captured.tools.get('secret_request').execute({ provider: 'vault' }, execFor('sess-dismiss'))
  await assert.rejects(
    () => dismissed.captured.tools.get('secret_fetch').execute({ provider: 'vault', item: ITEM }, execFor('sess-dismiss')),
    /was not provided/,
  )

  /* 10. A scope that does not cover the item never reaches the password prompt. */
  const scoped = mockContext(config)
  let scopedAsked = 0
  scoped.setAnswer((question) => {
    if (question.questions[0].id === 'master') scopedAsked += 1
    return question.questions[0].id === 'master' ? passwordAnswer(PASSWORD) : consentAnswer
  })
  await scoped.captured.tools.get('secret_request').execute({ provider: 'vault', scope: 'other*' }, execFor('sess-scope'))
  await assert.rejects(
    () => scoped.captured.tools.get('secret_fetch').execute({ provider: 'vault', item: ITEM }, execFor('sess-scope')),
    /no grant for provider "vault" covering/,
  )
  assert.equal(scopedAsked, 0, 'no password was requested for an item outside the grant')

  /* 11. Two factor is reported, not retried. */
  serverState.twoFactor = true
  const twoFactor = mockContext(config)
  twoFactor.setAnswer((question) => question.questions[0].id === 'master' ? passwordAnswer(PASSWORD) : consentAnswer)
  await twoFactor.captured.tools.get('secret_request').execute({ provider: 'vault' }, execFor('sess-2fa'))
  await assert.rejects(
    () => twoFactor.captured.tools.get('secret_fetch').execute({ provider: 'vault', item: ITEM }, execFor('sess-2fa')),
    /two-factor authentication/,
  )
  serverState.twoFactor = false

  for (const disposer of captured.effects) disposer()
  console.log('dsh-secrets: bitwarden provider tests passed')
} finally {
  server.close()
}
