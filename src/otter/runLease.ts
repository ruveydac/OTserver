import { APIError } from 'payload'
import { relationshipID } from '../access/authorization'
import type { OtterRun, OtterScanner } from '../payload-types'

export const activeRunStatuses: OtterRun['status'][] = ['assigned', 'running', 'cancel-requested']

export const isRunLeaseExpired = (run: OtterRun, now: Date) => {
  const expiresAt = Date.parse(run.leaseExpiresAt || '')
  return !Number.isFinite(expiresAt) || expiresAt <= now.getTime()
}

export const assertOtterRunOwner = (run: OtterRun, scanner: OtterScanner) => {
  if (String(relationshipID(run.scanner)) !== String(scanner.id))
    throw new APIError('Scan run does not belong to this scanner.', 404)
}

export const assertCurrentOtterRunLease = (run: OtterRun, scanner: OtterScanner, now: Date) => {
  assertOtterRunOwner(run, scanner)
  if (
    !activeRunStatuses.includes(run.status) ||
    String(relationshipID(scanner.currentRun)) !== String(run.id)
  )
    throw new APIError('This scan run is no longer the scanner’s current assignment.', 409)
  if (isRunLeaseExpired(run, now)) throw new APIError('The scanner lease has expired.', 409)
}
