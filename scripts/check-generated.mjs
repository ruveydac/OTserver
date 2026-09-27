import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const generatedFiles = ['src/payload-types.ts', 'src/app/(payload)/admin/importMap.js']
const snapshot = () =>
  Promise.all(
    generatedFiles.map(async (file) => [file, await readFile(path.resolve(root, file), 'utf8')]),
  ).then((entries) => new Map(entries))
const pnpm = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm'
const run = (args) => {
  const result = spawnSync(pnpm, args, { cwd: root, stdio: 'inherit' })
  if (result.error) throw result.error
  if (result.status !== 0) process.exit(result.status ?? 1)
}

const before = await snapshot()
for (const script of ['generate:types', 'generate:importmap']) run(['run', script])
run(['exec', 'prettier', '--write', generatedFiles[1]])

const after = await snapshot()
const changed = generatedFiles.filter((file) => before.get(file) !== after.get(file))
if (changed.length) {
  console.error(
    `Generated Payload artifacts were stale:\n${changed.map((file) => `- ${file}`).join('\n')}`,
  )
  console.error('Review and commit the regenerated files, then rerun pnpm check:generated.')
  process.exitCode = 1
} else {
  console.log('Generated Payload artifacts are up to date.')
}
