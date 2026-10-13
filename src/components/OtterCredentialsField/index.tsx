'use client'

import { Button, useDocumentInfo, useField } from '@payloadcms/ui'
import { useState } from 'react'
import type { UIFieldClientComponent } from 'payload'

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
  const { id } = useDocumentInfo()
  const { value: configured } = useField<boolean>({ path: 'credentialsConfigured' })
  const [savedConfigured, setSavedConfigured] = useState<boolean>()
  const hasCredentials = savedConfigured ?? Boolean(configured)
  const [snmp, setSnmp] = useState<SnmpEntry[]>([])
  const [opcua, setOpcua] = useState<OpcuaEntry[]>([])
  const [opcuaUsername, setOpcuaUsername] = useState('')
  const [opcuaPassword, setOpcuaPassword] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)

  const save = async (clear = false) => {
    if (!id) return setMessage('Save the profile before configuring credentials.')
    const settings = snmp
      .map((entry) =>
        Object.fromEntries(
          Object.entries(entry).filter(([key, value]) => key === 'version' || value !== ''),
        ),
      )
      .filter((entry) => Object.keys(entry).length > 1)
    const opcuaCredentials = opcua.filter((entry) => entry.username || entry.password)
    const credentials = {
      ...(settings.length ? { snmp: settings } : {}),
      ...(opcuaCredentials.length ? { opcuaCredentials } : {}),
      ...(opcuaUsername ? { opcuaUsername } : {}),
      ...(opcuaPassword ? { opcuaPassword } : {}),
    }
    if (!clear && !Object.keys(credentials).length)
      return setMessage('Add at least one SNMP or OPC UA credential before saving.')

    setBusy(true)
    setMessage('')
    try {
      const response = await fetch(
        `/api/otter/v1/profiles/${encodeURIComponent(String(id))}/credentials`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(clear ? { clear: true } : { credentials }),
        },
      )
      if (!response.ok) {
        const result = (await response.json()) as { errors?: Array<{ message?: string }> }
        throw new Error(result.errors?.[0]?.message || 'Could not save Otter credentials.')
      }
      const result = (await response.json()) as { credentialsConfigured: boolean }
      setSnmp([])
      setOpcua([])
      setOpcuaUsername('')
      setOpcuaPassword('')
      setSavedConfigured(result.credentialsConfigured)
      setMessage(
        clear
          ? 'Stored credentials cleared.'
          : 'Credentials encrypted and saved. Submitted secret values were cleared from this form.',
      )
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not save Otter credentials.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <fieldset className="otter-credentials">
      <legend>SNMP and OPC UA credentials</legend>
      <p>
        {!id
          ? 'New configurations automatically start with SNMP v2c community public. Save the configuration to replace or clear these defaults.'
          : hasCredentials
            ? 'Credentials are configured and encrypted at rest. Existing values cannot be read.'
            : 'No credentials are stored for this profile.'}
      </p>
      {!readOnly ? (
        <>
          <section className="otter-credentials__section">
            <h4>SNMP</h4>
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
                    {['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'].map((protocol) => (
                      <option key={protocol} value={protocol}>
                        {protocol.toUpperCase()}
                      </option>
                    ))}
                  </select>
                </label>
                {input(
                  'Authentication password',
                  entry.authPassword,
                  (authPassword) =>
                    setSnmp((items) =>
                      items.map((item, i) => (i === index ? { ...item, authPassword } : item)),
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
                          i === index ? { ...item, privacyProtocol: event.target.value } : item,
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
                      items.map((item, i) => (i === index ? { ...item, privacyPassword } : item)),
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
            <Button
              buttonStyle="secondary"
              disabled={snmp.length >= 32}
              onClick={() => setSnmp((items) => [...items, emptySnmp()])}
              type="button"
            >
              Add SNMP credential
            </Button>
          </section>

          <section className="otter-credentials__section">
            <h4>OPC UA</h4>
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
            <Button
              buttonStyle="secondary"
              disabled={opcua.length >= 32}
              onClick={() => setOpcua((items) => [...items, { username: '', password: '' }])}
              type="button"
            >
              Add OPC UA credential
            </Button>
            <p>Optional single-credential fallback from otter.json:</p>
            <div className="otter-credentials__entry">
              {input('Fallback username', opcuaUsername, setOpcuaUsername)}
              {input('Fallback password', opcuaPassword, setOpcuaPassword, 'password')}
            </div>
          </section>

          <div className="otter-credentials__actions">
            <Button disabled={busy} onClick={() => void save()} type="button">
              Encrypt and save credentials
            </Button>
            {hasCredentials ? (
              <Button
                buttonStyle="error"
                disabled={busy}
                onClick={() => void save(true)}
                type="button"
              >
                Clear stored credentials
              </Button>
            ) : null}
          </div>
        </>
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
