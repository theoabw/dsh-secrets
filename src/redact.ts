/**
 * Redaction.
 *
 * Every model-visible tool result is rewritten while a value is live, so an
 * accidental leak (a command that echoes the variable, a provider that prints
 * it in an error) cannot land in the conversation or the session log. This is
 * a safety net, not a boundary: an agent that deliberately encodes a value it
 * was allowed to use can still emit it, which is the documented limit of the
 * whole design.
 *
 * Spill files are written by the shell executor at capture time, before any
 * listener runs, so they are scrubbed in place when a result points at them.
 */
import { readFile, writeFile } from 'node:fs/promises'
import type { ContentBlock } from '@deepseek-ai/dsh-llm'

/** Replacement text for any occurrence of a live value. */
const REDACTED = '[redacted]'

/**
 * Replace every occurrence of every value with `[redacted]`.
 *
 * Longer values run first, so a value that contains another never leaves a
 * fragment behind. Over-redaction is the accepted failure direction.
 */
export function redact(text: string, values: readonly string[]): string {
  if (text.length === 0 || values.length === 0) return text
  const ordered = [...values].filter((value) => value.length > 0)
    .sort((left, right) => right.length - left.length)
  if (ordered.length === 0) return text
  const pattern = ordered.map((value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')
  return text.replace(new RegExp(pattern, 'g'), REDACTED)
}

/** Redact the text blocks of a content array, keeping the input identity when nothing changed. */
export function redactBlocks(blocks: ContentBlock[], values: readonly string[]): ContentBlock[] {
  let changed = false
  const out = blocks.map((block) => {
    if (block.type !== 'text') return block
    const replaced = redact(block.text, values)
    if (replaced === block.text) return block
    changed = true
    return { ...block, text: replaced }
  })
  return changed ? out : blocks
}

/** Flatten text blocks for spill-path discovery. */
export function flattenText(blocks: ContentBlock[] | undefined): string {
  if (blocks === undefined) return ''
  let text = ''
  for (const block of blocks) if (block.type === 'text') text += block.text
  return text
}

/**
 * Collect spill-file paths reachable from one tool result: the structured
 * `stdout`/`stderr` spill path of the shell executor's canonical value, plus
 * absolute paths named in "full output: <path>" notices inside rendered text.
 */
export function spillPathsOf(value: unknown, contentText: string): string[] {
  const paths = new Set<string>()
  if (typeof value === 'object' && value !== null) {
    const record = value as Record<string, unknown>
    for (const stream of ['stdout', 'stderr']) {
      const streamRecord = record[stream]
      if (typeof streamRecord !== 'object' || streamRecord === null) continue
      const spillPath = (streamRecord as Record<string, unknown>).spillPath
      if (typeof spillPath === 'string' && spillPath.startsWith('/')) paths.add(spillPath)
    }
  }
  for (const match of contentText.matchAll(/full output: ([^\]]+)/g)) {
    for (const part of match[1].split(',')) {
      const path = part.trim()
      if (path.startsWith('/')) paths.add(path)
    }
  }
  return [...paths]
}

/** Best-effort in-place scrub of one spill file; absence or a read failure is fine. */
export async function scrubSpillFile(path: string, values: readonly string[]): Promise<void> {
  try {
    const content = await readFile(path, 'utf8')
    const replaced = redact(content, values)
    if (replaced !== content) await writeFile(path, replaced)
  } catch {
    // The executor may already have removed the file; nothing to do.
  }
}
