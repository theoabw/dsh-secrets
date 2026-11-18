/**
 * Bundle check for CI.
 *
 * The build keeps every `@deepseek-ai/*` import external, because the host
 * provides those packages at runtime. CI cannot install them (the published
 * versions do not match the harness this plugin is built against), so this
 * script checks the next best thing: that the built output exists and imports
 * nothing the host will not provide.
 *
 * Run: node scripts/check-bundle.mjs
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

/** Entries the package publishes. */
const REQUIRED = ['lib/index.js', 'lib/crypto.js', 'lib/api.js', 'lib/vault.js', 'lib/live-check.js']

/** Specifiers the host resolves at runtime. */
const HOST_PREFIXES = ['node:', '@deepseek-ai/', './', '../']

for (const file of REQUIRED) {
  const source = readFileSync(file, 'utf8')
  assert.ok(source.length > 0, `${file} is empty`)
  for (const match of source.matchAll(/^\s*import\s[^;\n]*?from\s+"([^"]+)"/gm)) {
    const specifier = match[1]
    assert.ok(
      HOST_PREFIXES.some((prefix) => specifier.startsWith(prefix)),
      `${file} imports "${specifier}", which the host does not provide`,
    )
  }
}

console.log(`bundle check passed: ${REQUIRED.length} entries, host-only imports`)
