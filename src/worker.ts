import 'dotenv/config'
import { getPayload } from 'payload'
import config from './payload.config'
import { superviseWorker } from './jobs/worker'

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
