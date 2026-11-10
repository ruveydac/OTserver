'use client'

import {
  Banner,
  Button,
  ConfirmationModal,
  useConfig,
  useDocumentInfo,
  useField,
  useModal,
} from '@payloadcms/ui'
import { useEffect, useState } from 'react'
import type { UIFieldClientComponent } from 'payload'
import './index.scss'

type SnmpEntry = {
  version: string
  community: string
  username: string
  contextName: string
  authProtocol: string
  authPassword: string
  privacyProtocol: string
  privacyPassword: string
}
type OpcuaEntry = { username: string; password: string }
type CredentialSummary = {
  id: string
  type: 'snmp' | 'opcua' | 'opcua-fallback'
  version?: string
  username?: string
  contextName?: string
  authProtocol?: string
  privacyProtocol?: string
}
type CredentialState = {
  credentialsConfigured: boolean
  revision: string | null
  entries: CredentialSummary[]
}
const emptySnmp = (): SnmpEntry => ({
  version: '2c',
  community: '',
  username: '',
  contextName: '',
  authProtocol: '',
  authPassword: '',
  privacyProtocol: '',
  privacyPassword: '',
})
const input = (label: string, value: string, onChange: (value: string) => void, type = 'text') => (
  <label className="otter-credentials__field">
    {label}
    <input
      autoComplete={type === 'password' ? 'new-password' : 'off'}
      className="field-type__input"
      onChange={(event) => onChange(event.target.value)}
      type={type}
      value={value}
    />
  </label>
)

const OtterCredentialsField: UIFieldClientComponent = ({ readOnly }) => {
  const {
    config: {
      routes: { api },
    },
  } = useConfig()
  const { id } = useDocumentInfo()
  const { openModal } = useModal()
  const { value: configured } = useField<boolean>({ path: 'credentialsConfigured' })
  const [savedConfigured, setSavedConfigured] = useState<boolean>()
  const [loadedID, setLoadedID] = useState<string>()
  const hasCredentials =
    loadedID === String(id) ? (savedConfigured ?? Boolean(configured)) : Boolean(configured)
  const [entries, setEntries] = useState<CredentialSummary[]>([])
  const [revision, setRevision] = useState<string | null>(null)
  const [failedID, setFailedID] = useState<string>()
  const [loadAttempt, setLoadAttempt] = useState(0)
  const loading = Boolean(id) && loadedID !== String(id) && failedID !== String(id)
  const visibleEntries = id && loadedID === String(id) ? entries : []
  const [editorOpen, setEditorOpen] = useState(false)
  const [replacement, setReplacement] = useState<CredentialSummary>()
  const [snmp, setSnmp] = useState<SnmpEntry[]>([])
  const [opcua, setOpcua] = useState<OpcuaEntry[]>([])
  const [opcuaUsername, setOpcuaUsername] = useState('')
  const [opcuaPassword, setOpcuaPassword] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!id) return
    const controller = new AbortController()
    void fetch(`${api}/otter/v1/profiles/${encodeURIComponent(String(id))}/credentials`, {
      cache: 'no-store',
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          const result = (await response.json()) as { errors?: Array<{ message?: string }> }
          throw new Error(result.errors?.[0]?.message || 'Could not load Otter credentials.')
        }
        return (await response.json()) as CredentialState
      })
      .then((result) => {
        if (controller.signal.aborted) return
        setEntries(result.entries)
        setRevision(result.revision)
        setSavedConfigured(result.credentialsConfigured)
        setLoadedID(String(id))
        setFailedID(undefined)
        setError('')
      })
      .catch((loadError: unknown) => {
        if (!controller.signal.aborted) {
          setError(
            loadError instanceof Error ? loadError.message : 'Could not load Otter credentials.',
          )
          setFailedID(String(id))
        }
      })
    return () => controller.abort()
  }, [api, id, loadAttempt])

  const save = async (
    action: 'add' | 'replace' | 'remove' | 'clear' = 'add',
    entry?: CredentialSummary,
  ) => {
    if (readOnly) return
    setError('')
    if (!id) return setError('Save the configuration before adding credentials.')
    if (loadedID !== String(id))
      return setError('Load the stored credentials before changing them.')
    const settings = snmp
      .map((entry) =>
        Object.fromEntries(
          Object.entries(entry).filter(([key, value]) => key === 'version' || value !== ''),
        ),
      )
      .filter((entry) => Object.keys(entry).length > 1)
    const opcuaCredentials = opcua.filter((item) => item.username || item.password)
    const credentials = {
      ...(settings.length ? { snmp: settings } : {}),
      ...(opcuaCredentials.length ? { opcuaCredentials } : {}),
      ...(opcuaUsername ? { opcuaUsername } : {}),
      ...(opcuaPassword ? { opcuaPassword } : {}),
    }
    if (action === 'add' && !Object.keys(credentials).length)
      return setError('Add at least one SNMP or OPC UA credential before saving.')
    if (action === 'replace' && !replacement)
      return setError('Select a stored credential to replace.')
    if (action === 'remove' && !entry) return setError('Select a stored credential to remove.')

    const replacementCredentials =
      replacement?.type === 'snmp'
        ? settings[0]
        : replacement?.type === 'opcua'
          ? opcuaCredentials[0]
          : replacement
            ? {
                ...(opcuaUsername ? { opcuaUsername } : {}),
                ...(opcuaPassword ? { opcuaPassword } : {}),
              }
            : undefined
    if (
      action === 'replace' &&
      (!replacementCredentials || !Object.keys(replacementCredentials).length)
    )
      return setError('Enter the replacement credential, including a new secret where required.')

    setBusy(true)
    setMessage('')
    try {
      const response = await fetch(
        `${api}/otter/v1/profiles/${encodeURIComponent(String(id))}/credentials`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action,
            revision,
            ...(action === 'add' ? { credentials } : {}),
            ...(action === 'replace'
              ? { id: replacement?.id, credentials: replacementCredentials }
              : {}),
            ...(action === 'remove' ? { id: entry?.id } : {}),
          }),
        },
      )
      if (!response.ok) {
        const result = (await response.json()) as { errors?: Array<{ message?: string }> }
        throw new Error(result.errors?.[0]?.message || 'Could not save Otter credentials.')
      }
      const result = (await response.json()) as CredentialState
      setEntries(result.entries)
      setRevision(result.revision)
      setSavedConfigured(result.credentialsConfigured)
      setSnmp([])
      setOpcua([])
      setOpcuaUsername('')
      setOpcuaPassword('')
      setReplacement(undefined)
      setEditorOpen(false)
      setMessage(
        action === 'clear'
          ? 'Stored credentials cleared.'
          : action === 'remove'
            ? 'Credential removed.'
            : action === 'replace'
              ? 'Credential replaced. Submitted secret values were cleared from this form.'
              : 'Credentials added. Submitted secret values were cleared from this form.',
      )
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Could not save Otter credentials.')
      if (error instanceof Error && error.message.includes('changed in another session')) {
        try {
          const response = await fetch(
            `${api}/otter/v1/profiles/${encodeURIComponent(String(id))}/credentials`,
            { cache: 'no-store' },
          )
          if (response.ok) {
            const result = (await response.json()) as CredentialState
            setEntries(result.entries)
            setRevision(result.revision)
            setSavedConfigured(result.credentialsConfigured)
            setLoadedID(String(id))
            setFailedID(undefined)
          }
        } catch {
          // Keep the conflict message visible if the refresh also fails.
        }
      }
    } finally {
      setBusy(false)
    }
  }

  const beginReplacement = (entry: CredentialSummary) => {
    setError('')
    setMessage('')
    setReplacement(entry)
    setSnmp(
      entry.type === 'snmp'
        ? [
            {
              ...emptySnmp(),
              version: entry.version || 'auto',
              username: entry.username || '',
              contextName: entry.contextName || '',
              authProtocol: entry.authProtocol || '',
              privacyProtocol: entry.privacyProtocol || '',
            },
          ]
        : [],
    )
    setOpcua(entry.type === 'opcua' ? [{ username: entry.username || '', password: '' }] : [])
    setOpcuaUsername(entry.type === 'opcua-fallback' ? entry.username || '' : '')
    setOpcuaPassword('')
    setEditorOpen(true)
  }

  const cancelEditor = () => {
    setSnmp([])
    setOpcua([])
    setOpcuaUsername('')
    setOpcuaPassword('')
    setReplacement(undefined)
    setEditorOpen(false)
  }

  return (
    <fieldset className="otter-credentials">
      <legend>SNMP and OPC UA credentials</legend>
      <p>
        {!id
          ? 'New configurations start with an SNMP v2c credential. Save the configuration to manage or clear this default.'
          : hasCredentials
            ? 'Credentials are encrypted at rest. Secret values are write-only.'
            : 'No credentials are stored for this configuration.'}
      </p>
      {id ? (
        <section className="otter-credentials__section" aria-labelledby="otter-stored-credentials">
          <h4 id="otter-stored-credentials">Stored credentials</h4>
          {loading ? <p role="status">Loading credentials…</p> : null}
          {!loading && failedID === String(id) ? (
            <Button
              buttonStyle="secondary"
              onClick={() => setLoadAttempt((attempt) => attempt + 1)}
              type="button"
            >
              Retry loading credentials
            </Button>
          ) : null}
          {!loading && failedID !== String(id) && visibleEntries.length === 0 ? (
            <p>No credentials are stored.</p>
          ) : null}
          {visibleEntries.map((entry) => {
            const label =
              entry.type === 'snmp'
                ? `SNMP ${entry.version || 'auto'}`
                : entry.type === 'opcua'
                  ? 'OPC UA'
                  : 'OPC UA fallback'
            return (
              <article className="otter-credentials__stored" key={entry.id}>
                <div>
                  <strong>{label}</strong>
                  {entry.username ? <p>Username: {entry.username}</p> : null}
                  {entry.contextName ? <p>Context: {entry.contextName}</p> : null}
                  {entry.authProtocol ? (
                    <p>Authentication: {entry.authProtocol.toUpperCase()}</p>
                  ) : null}
                  {entry.privacyProtocol ? (
                    <p>Privacy: {entry.privacyProtocol.toUpperCase()}</p>
                  ) : null}
                </div>
                {!readOnly ? (
                  <div className="otter-credentials__actions">
                    <Button
                      buttonStyle="secondary"
                      disabled={busy || loading || editorOpen}
                      onClick={() => beginReplacement(entry)}
                      type="button"
                    >
                      Replace {label}
                    </Button>
                    <Button
                      buttonStyle="error"
                      disabled={busy || loading || editorOpen}
                      onClick={() => openModal(`otter-remove-credential-${entry.id}`)}
                      type="button"
                    >
                      Remove {label}
                    </Button>
                    <ConfirmationModal
                      modalSlug={`otter-remove-credential-${entry.id}`}
                      heading={`Remove ${label}?`}
                      body="This stored credential cannot be recovered after removal."
                      confirmLabel="Remove credential"
                      onConfirm={() => void save('remove', entry)}
                    />
                  </div>
                ) : null}
              </article>
            )
          })}
          {!readOnly && visibleEntries.length ? (
            <Button
              buttonStyle="error"
              disabled={busy || loading || editorOpen}
              onClick={() => openModal('otter-clear-credentials')}
              type="button"
            >
              Clear all credentials
            </Button>
          ) : null}
          {!readOnly && visibleEntries.length ? (
            <ConfirmationModal
              modalSlug="otter-clear-credentials"
              heading="Clear all credentials?"
              body="All stored SNMP and OPC UA credentials will be removed and cannot be recovered."
              confirmLabel="Clear all credentials now"
              onConfirm={() => void save('clear')}
            />
          ) : null}
        </section>
      ) : null}
      {!readOnly ? (
        <>
          {id && !editorOpen ? (
            <Button
              disabled={loading || failedID === String(id)}
              onClick={() => setEditorOpen(true)}
              type="button"
            >
              Add credentials
            </Button>
          ) : null}
          {editorOpen && id ? (
            <>
              {replacement?.type !== 'opcua' && replacement?.type !== 'opcua-fallback' ? (
                <section className="otter-credentials__section">
                  <h4>SNMP</h4>
                  {replacement ? (
                    <p>Enter a new community or password. The stored secret cannot be recovered.</p>
                  ) : null}
                  {snmp.map((entry, index) => (
                    <div className="otter-credentials__entry" key={index}>
                      <label className="otter-credentials__field">
                        Version
                        <select
                          className="field-type__input"
                          onChange={(event) =>
                            setSnmp((items) =>
                              items.map((item, i) =>
                                i === index ? { ...item, version: event.target.value } : item,
                              ),
                            )
                          }
                          value={entry.version}
                        >
                          {['auto', '1', '2c', '3'].map((version) => (
                            <option key={version} value={version}>
                              {version}
                            </option>
                          ))}
                        </select>
                      </label>
                      {input(
                        'Community',
                        entry.community,
                        (community) =>
                          setSnmp((items) =>
                            items.map((item, i) => (i === index ? { ...item, community } : item)),
                          ),
                        'password',
                      )}
                      {input('Username', entry.username, (username) =>
                        setSnmp((items) =>
                          items.map((item, i) => (i === index ? { ...item, username } : item)),
                        ),
                      )}
                      {input('Context name', entry.contextName, (contextName) =>
                        setSnmp((items) =>
                          items.map((item, i) => (i === index ? { ...item, contextName } : item)),
                        ),
                      )}
                      <label className="otter-credentials__field">
                        Authentication protocol
                        <select
                          className="field-type__input"
                          onChange={(event) =>
                            setSnmp((items) =>
                              items.map((item, i) =>
                                i === index ? { ...item, authProtocol: event.target.value } : item,
                              ),
                            )
                          }
                          value={entry.authProtocol}
                        >
                          <option value="">None</option>
                          {['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'].map(
                            (protocol) => (
                              <option key={protocol} value={protocol}>
                                {protocol.toUpperCase()}
                              </option>
                            ),
                          )}
                        </select>
                      </label>
                      {input(
                        'Authentication password',
                        entry.authPassword,
                        (authPassword) =>
                          setSnmp((items) =>
                            items.map((item, i) =>
                              i === index ? { ...item, authPassword } : item,
                            ),
                          ),
                        'password',
                      )}
                      <label className="otter-credentials__field">
                        Privacy protocol
                        <select
                          className="field-type__input"
                          onChange={(event) =>
                            setSnmp((items) =>
                              items.map((item, i) =>
                                i === index
                                  ? { ...item, privacyProtocol: event.target.value }
                                  : item,
                              ),
                            )
                          }
                          value={entry.privacyProtocol}
                        >
                          <option value="">None</option>
                          {['des', 'aes128', 'aes192', 'aes256'].map((protocol) => (
                            <option key={protocol} value={protocol}>
                              {protocol.toUpperCase()}
                            </option>
                          ))}
                        </select>
                      </label>
                      {input(
                        'Privacy password',
                        entry.privacyPassword,
                        (privacyPassword) =>
                          setSnmp((items) =>
                            items.map((item, i) =>
                              i === index ? { ...item, privacyPassword } : item,
                            ),
                          ),
                        'password',
                      )}
                      <Button
                        buttonStyle="secondary"
                        onClick={() => setSnmp((items) => items.filter((_, i) => i !== index))}
                        type="button"
                      >
                        Remove SNMP credential
                      </Button>
                    </div>
                  ))}
                  {!replacement ? (
                    <Button
                      buttonStyle="secondary"
                      disabled={snmp.length >= 32}
                      onClick={() => setSnmp((items) => [...items, emptySnmp()])}
                      type="button"
                    >
                      Add SNMP credential
                    </Button>
                  ) : null}
                </section>
              ) : null}

              {replacement?.type !== 'snmp' && replacement?.type !== 'opcua-fallback' ? (
                <section className="otter-credentials__section">
                  <h4>OPC UA</h4>
                  {replacement ? (
                    <p>
                      Enter a new password if this credential uses one. The stored secret cannot be
                      recovered.
                    </p>
                  ) : null}
                  {opcua.map((entry, index) => (
                    <div className="otter-credentials__entry" key={index}>
                      {input('Username', entry.username, (username) =>
                        setOpcua((items) =>
                          items.map((item, i) => (i === index ? { ...item, username } : item)),
                        ),
                      )}
                      {input(
                        'Password',
                        entry.password,
                        (password) =>
                          setOpcua((items) =>
                            items.map((item, i) => (i === index ? { ...item, password } : item)),
                          ),
                        'password',
                      )}
                      <Button
                        buttonStyle="secondary"
                        onClick={() => setOpcua((items) => items.filter((_, i) => i !== index))}
                        type="button"
                      >
                        Remove OPC UA credential
                      </Button>
                    </div>
                  ))}
                  {!replacement ? (
                    <Button
                      buttonStyle="secondary"
                      disabled={opcua.length >= 32}
                      onClick={() =>
                        setOpcua((items) => [...items, { username: '', password: '' }])
                      }
                      type="button"
                    >
                      Add OPC UA credential
                    </Button>
                  ) : null}
                </section>
              ) : null}

              {!replacement ? (
                <section className="otter-credentials__section">
                  <h4>OPC UA fallback</h4>
                  <p>Optional single-credential fallback from otter.json.</p>
                  <div className="otter-credentials__entry">
                    {input('Fallback username', opcuaUsername, setOpcuaUsername)}
                    {input('Fallback password', opcuaPassword, setOpcuaPassword, 'password')}
                  </div>
                </section>
              ) : replacement.type === 'opcua-fallback' ? (
                <section className="otter-credentials__section">
                  <h4>OPC UA fallback</h4>
                  <p>
                    Enter a new password if this credential uses one. The stored secret cannot be
                    recovered.
                  </p>
                  <div className="otter-credentials__entry">
                    {input('Fallback username', opcuaUsername, setOpcuaUsername)}
                    {input('Fallback password', opcuaPassword, setOpcuaPassword, 'password')}
                  </div>
                </section>
              ) : null}

              <div className="otter-credentials__actions">
                <Button
                  disabled={busy || loading}
                  onClick={() => void save(replacement ? 'replace' : 'add')}
                  type="button"
                >
                  {replacement ? 'Replace credential' : 'Add credentials'}
                </Button>
                <Button
                  buttonStyle="secondary"
                  disabled={busy}
                  onClick={cancelEditor}
                  type="button"
                >
                  Cancel
                </Button>
              </div>
            </>
          ) : null}
        </>
      ) : null}
      {error ? (
        <div role="alert">
          <Banner type="error">{error}</Banner>
        </div>
      ) : null}
      {message ? (
        <p aria-live="polite" role="status">
          {message}
        </p>
      ) : null}
    </fieldset>
  )
}

export default OtterCredentialsField
