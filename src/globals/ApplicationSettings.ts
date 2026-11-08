import type {
  GlobalAfterChangeHook,
  GlobalBeforeChangeHook,
  GlobalBeforeOperationHook,
  GlobalConfig,
} from 'payload'
import { adminOnly, hideFromNonAdmins } from '../access/authorization'
import { writeAudit } from '../collections/AuditLogs'
import { guardWorkerWrite } from '../integrations/payload/workerContext'
import { primeTransaction } from '../integrations/payload/transactions'
import { validateControllerURL } from '../application/settings'
import {
  CSAF_FEED_TYPES,
  MAX_CUSTOM_CSAF_FEEDS,
  validateCsafFeedURL,
  validateCustomCsafFeeds,
} from '../vulnerabilities/sources'

const normalizeSettings: GlobalBeforeChangeHook = ({ data }) => {
  if (typeof data.controllerURL === 'string') data.controllerURL = data.controllerURL.trim()
  const vulnerabilityFeeds = data.vulnerabilityFeeds
  if (vulnerabilityFeeds && typeof vulnerabilityFeeds === 'object') {
    const customCsafFeeds = (vulnerabilityFeeds as Record<string, unknown>).customCsafFeeds
    if (Array.isArray(customCsafFeeds))
      (vulnerabilityFeeds as Record<string, unknown>).customCsafFeeds = customCsafFeeds.map(
        (feed) => {
          if (!feed || typeof feed !== 'object') return feed
          const row = feed as Record<string, unknown>
          return {
            ...row,
            name: typeof row.name === 'string' ? row.name.trim() : row.name,
            url: typeof row.url === 'string' ? row.url.trim() : row.url,
          }
        },
      )
  }
  return data
}

const startSettingsTransaction: GlobalBeforeOperationHook = async ({ args, operation, req }) => {
  if (operation !== 'update') return args
  await primeTransaction(req)
  await guardWorkerWrite(req)
  return args
}

const auditSettings: GlobalAfterChangeHook = async ({ doc, previousDoc, req }) => {
  await writeAudit({
    action: 'update',
    after: doc,
    before: previousDoc,
    req,
    targetCollection: 'application-settings',
  })
  return doc
}

export const ApplicationSettings: GlobalConfig = {
  slug: 'application-settings',
  label: 'Application settings',
  access: { read: adminOnly, update: adminOnly },
  admin: { group: 'Settings', hidden: hideFromNonAdmins },
  hooks: {
    beforeOperation: [startSettingsTransaction],
    beforeChange: [normalizeSettings],
    afterChange: [auditSettings],
  },
  fields: [
    {
      name: 'vulnerabilityFeeds',
      type: 'group',
      label: 'Vulnerability feeds',
      fields: [
        {
          name: 'automaticUpdates',
          label: 'Enable automatic vulnerability feed updates',
          type: 'checkbox',
          defaultValue: true,
          admin: {
            description:
              'Automatically download feeds. Manual updates and offline imports remain available when this is disabled.',
          },
        },
        {
          name: 'pullIntervalDays',
          label: 'Pull interval (days)',
          type: 'number',
          defaultValue: 7,
          min: 1,
          max: 365,
          admin: {
            step: 1,
            description: 'Automatic updates run at this interval, from 1 to 365 days.',
          },
          validate: (value: unknown) =>
            (typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 365) ||
            'Enter a whole number from 1 to 365.',
        },
        {
          name: 'customCsafFeeds',
          label: 'Additional CSAF feeds',
          type: 'array',
          maxRows: MAX_CUSTOM_CSAF_FEEDS,
          validate: validateCustomCsafFeeds,
          admin: {
            description:
              'Add public HTTPS CSAF aggregators, provider metadata, or ROLIE feeds. Referenced feeds and advisories are discovered automatically.',
          },
          fields: [
            { name: 'name', type: 'text', required: true, maxLength: 120 },
            {
              name: 'type',
              label: 'Format',
              type: 'select',
              required: true,
              options: [
                { label: 'CSAF aggregator', value: CSAF_FEED_TYPES[0] },
                { label: 'Provider metadata', value: CSAF_FEED_TYPES[1] },
                { label: 'JSON ROLIE feed', value: CSAF_FEED_TYPES[2] },
              ],
            },
            {
              name: 'url',
              type: 'text',
              required: true,
              maxLength: 2048,
              validate: validateCsafFeedURL,
            },
          ],
        },
      ],
    },
    {
      name: 'otterReleaseImports',
      label: 'Enable daily Otter release imports',
      type: 'checkbox',
      defaultValue: false,
      admin: {
        description:
          'Import the latest stable GitHub release for all supported platforms every 24 hours. Scanner updates are assigned separately.',
      },
    },
    {
      name: 'metadataImports',
      label: 'Enable daily device metadata updates',
      type: 'checkbox',
      defaultValue: false,
      admin: {
        description:
          'Check OTserver Metadata on GitHub every 24 hours and import validated manufacturer and device records. Existing records missing upstream are retained.',
      },
    },
    {
      name: 'metadataSync',
      type: 'group',
      access: { update: () => false },
      admin: { hidden: true },
      fields: [
        { name: 'requestedAt', type: 'date' },
        { name: 'lastCheckedAt', type: 'date' },
        { name: 'lastSyncedAt', type: 'date' },
        { name: 'commitSHA', type: 'text' },
        { name: 'error', type: 'textarea' },
        { name: 'jobID', type: 'text' },
      ],
    },
    {
      name: 'otterReleaseSync',
      type: 'group',
      access: { update: () => false },
      admin: { hidden: true },
      fields: [
        { name: 'requestedAt', type: 'date' },
        { name: 'lastCheckedAt', type: 'date' },
        { name: 'lastSyncedAt', type: 'date' },
        { name: 'version', type: 'text' },
        { name: 'error', type: 'textarea' },
        { name: 'jobID', type: 'text' },
      ],
    },
    {
      name: 'controllerURL',
      label: 'Public controller URL',
      type: 'text',
      maxLength: 2048,
      validate: validateControllerURL,
      admin: {
        description:
          'Leave blank to use OTSERVER_PUBLIC_URL from the deployment environment. Remote URLs require HTTPS.',
      },
    },
    {
      name: 'queuedImports',
      label: 'Queued imports',
      type: 'select',
      defaultValue: 'deployment',
      options: [
        { label: 'Use deployment default', value: 'deployment' },
        { label: 'Enabled', value: 'enabled' },
        { label: 'Disabled', value: 'disabled' },
      ],
      admin: {
        description:
          'Controls new queued import submissions and retries. Jobs already accepted continue processing. The deployment default uses OTSERVER_QUEUED_IMPORTS.',
      },
    },
  ],
}
