process.loadEnvFile?.()

const { getPayload } = await import('payload')
const { default: config } = await import('./payload.config')
const { superviseWorker } = await import('./jobs/worker')

const queue = process.argv[2]
if (queue !== 'imports' && queue !== 'maintenance')
  throw new Error('Usage: worker imports|maintenance')
const controller = new AbortController()
process.on('SIGTERM', () => controller.abort())
process.on('SIGINT', () => controller.abort())
const payload = await getPayload({ config })
try {
  await superviseWorker(payload, queue, controller.signal)
} finally {
  await payload.destroy()
}

export {}
