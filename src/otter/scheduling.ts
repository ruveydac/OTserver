import { Cron } from 'croner'
import { APIError } from 'payload'

export type ScheduleInput = {
  cron?: string
  intervalMinutes?: number
  runAt?: string
  scheduleType?: 'once' | 'interval' | 'cron'
  timezone?: string
}

export const cronForSchedule = (pattern: string, timezone: string) => {
  if (pattern.length > 128 || pattern.trim().split(/\s+/).length !== 5)
    throw new APIError('Use a five-field cron expression (minute hour day month weekday).', 400)
  try {
    return new Cron(pattern, { paused: true, timezone })
  } catch {
    throw new APIError('The cron expression or time zone is invalid.', 400)
  }
}

export const validateScheduleInput = (schedule: ScheduleInput, now = new Date()) => {
  const type = schedule.scheduleType
  const timezone = schedule.timezone || 'UTC'
  if (timezone.length > 128) throw new APIError('Select a valid IANA time zone.', 400)
  try {
    new Intl.DateTimeFormat('en', { timeZone: timezone })
  } catch {
    throw new APIError('Select a valid IANA time zone.', 400)
  }

  if (type === 'once') {
    const runAt = Date.parse(schedule.runAt || '')
    if (!Number.isFinite(runAt)) throw new APIError('A valid one-time run date is required.', 400)
    return new Date(runAt).toISOString()
  }
  if (type === 'interval') {
    const minutes = schedule.intervalMinutes
    if (!Number.isInteger(minutes) || Number(minutes) < 5 || Number(minutes) > 10_080)
      throw new APIError('Intervals must be between 5 minutes and 7 days.', 400)
    return new Date(now.getTime() + Number(minutes) * 60_000).toISOString()
  }
  if (type === 'cron') {
    const job = cronForSchedule(schedule.cron || '', timezone)
    const next = job.nextRun(now)
    job.stop()
    if (!next) throw new APIError('The schedule has no upcoming run.', 400)
    return next.toISOString()
  }
  throw new APIError('Choose a supported schedule type.', 400)
}

export const dueOccurrence = (
  schedule: ScheduleInput & { nextRunAt?: string },
  now = new Date(),
) => {
  const next = Date.parse(schedule.nextRunAt || '')
  if (!Number.isFinite(next) || next > now.getTime()) return undefined

  if (schedule.scheduleType === 'once') return { occurrence: new Date(next), nextRunAt: undefined }
  if (schedule.scheduleType === 'interval') {
    const interval = Number(schedule.intervalMinutes) * 60_000
    if (!Number.isFinite(interval) || interval <= 0) return undefined
    const latest = next + Math.floor((now.getTime() - next) / interval) * interval
    return {
      occurrence: new Date(latest),
      nextRunAt: new Date(latest + interval).toISOString(),
    }
  }
  if (schedule.scheduleType === 'cron') {
    const job = cronForSchedule(schedule.cron || '', schedule.timezone || 'UTC')
    const nextRunAt = job.nextRun(now)
    if (!nextRunAt) {
      job.stop()
      return undefined
    }
    const occurrence = job.previousRuns(1, now)[0]
    job.stop()
    if (!occurrence) return undefined
    return { occurrence, nextRunAt: nextRunAt.toISOString() }
  }
  return undefined
}
