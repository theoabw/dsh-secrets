/**
 * Build for @tabw/dsh-secrets.
 *
 * The plugin is host-only: `lib/index.js` is an ordinary ESM module the dsh
 * host loader imports, and every `@deepseek-ai/*` import stays external
 * because the host installation provides those packages.
 */
import { isBuiltin } from 'node:module'
import { defineConfig } from 'tsdown'

const ID = '@tabw/dsh-secrets'

export default defineConfig({
  name: ID,
  entry: {
    index: 'src/index.ts',
    crypto: 'src/bitwarden/crypto.ts',
    api: 'src/bitwarden/api.ts',
    vault: 'src/bitwarden/vault.ts',
    'live-check': 'src/live-check.ts',
  },
  outDir: 'lib',
  format: ['esm'],
  platform: 'node',
  target: 'es2024',
  fixedExtension: false,
  dts: false,
  clean: true,
  sourcemap: true,
  deps: {
    neverBundle: (specifier) => specifier.startsWith('@deepseek-ai/'),
    alwaysBundle: (specifier) => !isBuiltin(specifier) && !specifier.startsWith('@deepseek-ai/'),
  },
})
