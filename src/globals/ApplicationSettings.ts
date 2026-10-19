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

const normalizeSettings: GlobalBeforeChangeHook = ({ data }) => {
  if (typeof data.controllerURL === 'string') data.controllerURL = data.controllerURL.trim()
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
