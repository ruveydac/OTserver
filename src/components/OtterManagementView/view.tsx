'use client'

import Link from 'next/link'
import { useCallback, useEffect, useState } from 'react'
import { Button, Gutter, Pill } from '@payloadcms/ui'

type Site = { id: string; name: string }
type Scanner = {
  id: string
  name: string
  enabled: boolean
  enrolled: boolean
  lastSeenAt?: string
  nextRunAt?: string
  site: Site | string
  version?: string
  interfaces?: string[]
  computerName?: string
  inventoryReportedAt?: string
  networkAdapters?: Array<{
    name: string
    friendlyName: string
    description: string
    macAddress?: string
    ipAddresses: string[]
  }>
  currentRun?: string
  lastRun?: { id: string; name: string; status: string; completedAt?: string }
}
type Profile = { id: string; name: string; scanner: string; credentialsConfigured: boolean }
type Run = {
  id: string
  name: string
  scanner: string
  status: string
  completedAt?: string
  scheduledFor?: string
  progress?: number
  message?: string
  import?: string
}
type Overview = {
  controllerUrl?: string
  scanners: Scanner[]
  profiles: Profile[]
  sites: Site[]
  writableSites: Site[]
  runs: Run[]
}

const date = (value?: string) => (value ? new Date(value).toLocaleString() : '—')
const errorText = async (response: Response, fallback: string) => {
  try {
    const data = (await response.json()) as {
      errors?: Array<{ message?: string }>
      message?: string
    }
    return data.errors?.[0]?.message || data.message || fallback
  } catch {
    return fallback
  }
}

export default function OtterManagement({ adminRoute }: { adminRoute: string }) {
  const [overview, setOverview] = useState<Overview>({
    scanners: [],
    profiles: [],
    sites: [],
    writableSites: [],
    runs: [],
  })
  const [name, setName] = useState('')
  const [site, setSite] = useState('')
  const [setupScannerID, setSetupScannerID] = useState('')
  const [token, setToken] = useState('')
  const [tokenScannerID, setTokenScannerID] = useState('')
  const [tokenExpiresAt, setTokenExpiresAt] = useState('')
  const [controllerUrl, setControllerUrl] = useState('')
  const [setupRunID, setSetupRunID] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [observedAt, setObservedAt] = useState(0)
  const [selectedProfiles, setSelectedProfiles] = useState<Record<string, string>>({})

  const load = useCallback(async () => {
    const response = await fetch('/api/otter/v1/overview', { cache: 'no-store' })
    if (!response.ok)
      throw new Error(await errorText(response, 'Could not load Otter management data.'))
    const result = (await response.json()) as Overview
    setOverview(result)
    setControllerUrl(result.controllerUrl || '')
    setObservedAt(Date.now())
    setSite((current) => current || result.writableSites[0]?.id || '')
    setSetupScannerID((current) => current || result.scanners[0]?.id || '')
    return result
  }, [])

  const checkEnrollment = useCallback(async () => {
    const result = await load()
    const scanner = result.scanners.find((entry) => entry.id === tokenScannerID)
    if (token && scanner?.enrolled) {
      setToken('')
      setTokenScannerID('')
      setTokenExpiresAt('')
      setMessage(
        `${scanner.name} is connected. Restart Otter without --enroll to use its saved credential.`,
      )
    }
  }, [load, token, tokenScannerID])

  useEffect(() => {
    const abort = new AbortController()
    void fetch('/api/otter/v1/overview', { cache: 'no-store', signal: abort.signal })
      .then(async (response) => {
        if (!response.ok)
          throw new Error(await errorText(response, 'Could not load Otter management data.'))
        return (await response.json()) as Overview
      })
      .then((result) => {
        setOverview(result)
        setObservedAt(Date.now())
        setControllerUrl(result.controllerUrl || '')
        setSite(result.writableSites[0]?.id || '')
        setSetupScannerID(result.scanners[0]?.id || '')
      })
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === 'AbortError'))
          setMessage(
            error instanceof Error ? error.message : 'Could not load Otter management data.',
          )
      })
    return () => abort.abort()
  }, [])

  useEffect(() => {
    const timer = window.setInterval(() => {
      void checkEnrollment().catch(() => undefined)
    }, 15_000)
    return () => window.clearInterval(timer)
  }, [checkEnrollment])

  const request = async (path: string, data?: unknown) => {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      ...(data === undefined ? {} : { body: JSON.stringify(data) }),
    })
    if (!response.ok) throw new Error(await errorText(response, 'The Otter action failed.'))
    return response.json() as Promise<Record<string, unknown>>
  }

  const act = async (work: () => Promise<void>) => {
    setBusy(true)
    setMessage('')
    try {
      await work()
      await load()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The Otter action failed.')
    } finally {
      setBusy(false)
    }
  }

  const createScanner = () =>
    act(async () => {
      const result = await request('/api/otter/v1/scanners', { name, site })
      setToken(String(result.enrollmentToken || ''))
      const scanner = result.scanner as { id?: string; name?: string } | undefined
      setTokenScannerID(String(scanner?.id || ''))
      setTokenExpiresAt(String(result.expiresAt || ''))
      setControllerUrl(String(result.controllerUrl || ''))
      setSetupScannerID(String(scanner?.id || ''))
      setSetupRunID('')
      setMessage(
        `Enrollment token expires ${date(String(result.expiresAt || ''))}. Copy it now; it is shown only once.`,
      )
      setName('')
    })

  const runNow = (scanner: Scanner, chosenProfileID?: string) => {
    const scannerProfiles = overview.profiles.filter((profile) => profile.scanner === scanner.id)
    const profileID = chosenProfileID || selectedProfiles[scanner.id] || scannerProfiles[0]?.id
    if (!profileID) {
      setMessage('Create a scan profile for this scanner before running it.')
      return
    }
    void act(async () => {
      const result = await request('/api/otter/v1/runs', { scannerID: scanner.id, profileID })
      setSetupRunID(String(result.id || ''))
      setMessage('Scan queued. Otter will receive it on its next poll.')
    })
  }

  const siteName = (value: Scanner['site']) =>
    typeof value === 'object'
      ? value.name
      : overview.sites.find((entry) => entry.id === value)?.name || value

  const setupScanner = overview.scanners.find((scanner) => scanner.id === setupScannerID)
  const setupProfiles = overview.profiles.filter((profile) => profile.scanner === setupScannerID)
  const setupProfileID = selectedProfiles[setupScannerID] || setupProfiles[0]?.id || ''
  const setupRun = overview.runs.find(
    (run) => run.id === setupRunID && run.scanner === setupScannerID,
  )
  const scannerOnline = (scanner: Scanner) =>
    Boolean(scanner.lastSeenAt && observedAt - Date.parse(scanner.lastSeenAt) < 120_000)
  const setupSiteID = setupScanner
    ? typeof setupScanner.site === 'string'
      ? setupScanner.site
      : setupScanner.site.id
    : ''
  const canWriteSetup = Boolean(
    setupSiteID && overview.writableSites.some((entry) => entry.id === setupSiteID),
  )
  const setupControllerUrl = controllerUrl
  const linuxEnrollCommand = `otserver-otter controller --server-url ${setupControllerUrl} --enroll --ack-authorized`
  const windowsEnrollCommand = `.\\otserver-otter.exe controller --server-url ${setupControllerUrl} --enroll --ack-authorized`
  const linuxStartCommand = `otserver-otter controller --server-url ${setupControllerUrl} --ack-authorized`
  const windowsStartCommand = `.\\otserver-otter.exe controller --server-url ${setupControllerUrl} --ack-authorized`

  const reenrollSetupScanner = () =>
    act(async () => {
      if (!setupScanner) return
      const result = await request(`/api/otter/v1/scanners/${setupScanner.id}/reenroll`)
      setToken(String(result.enrollmentToken || ''))
      setTokenScannerID(setupScanner.id)
      setTokenExpiresAt(String(result.expiresAt || ''))
      setControllerUrl(String(result.controllerUrl || ''))
      setMessage(
        `New token expires ${date(String(result.expiresAt || ''))}. The previous scanner credential was revoked.`,
      )
    })

  const copy = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value)
      setMessage(`${label} copied.`)
    } catch {
      setMessage('Clipboard access is unavailable. Select and copy the value instead.')
    }
  }

  return (
    <Gutter>
      <main className="otter-management">
        <header className="otter-management__header">
          <div>
            <p className="otter-management__eyebrow">Discovery agents</p>
            <h1>Otter management</h1>
            <p>
              Enroll site-bound scanners, manage their scan profiles, and review scheduled runs.
            </p>
          </div>
          <nav aria-label="Otter configuration">
            <Link href={`${adminRoute}/collections/otter-profiles`}>Scan profiles</Link>
            <Link href={`${adminRoute}/collections/otter-schedules`}>Schedules</Link>
            <Link href={`${adminRoute}/collections/otter-runs`}>Run history</Link>
          </nav>
        </header>

        {message ? (
          <p className="otter-management__message" role="status">
            {message}
          </p>
        ) : null}
        <section className="otter-management__setup">
          <h2>Set up Otter</h2>
          <p>Follow these steps to connect a scanner and run its first inventory scan.</p>
          <ol className="otter-management__steps">
            <li>
              <h3>Download Otter</h3>
              <p>
                Install Otter on the Windows or Linux host that can reach the industrial network.
              </p>
              <a
                href="https://github.com/ruveydac/otserver-otter/releases/latest"
                rel="noreferrer"
                target="_blank"
              >
                Download the latest Otter release
              </a>
            </li>
            <li>
              <h3>Create or choose a scanner</h3>
              <form
                className="otter-management__enroll"
                onSubmit={(event) => {
                  event.preventDefault()
                  void createScanner()
                }}
              >
                <label>
                  Scanner name
                  <input
                    autoComplete="off"
                    className="field-type__input"
                    maxLength={120}
                    onChange={(event) => setName(event.target.value)}
                    required
                    value={name}
                  />
                </label>
                <label>
                  Bound site
                  <select
                    className="field-type__input"
                    onChange={(event) => setSite(event.target.value)}
                    required
                    value={site}
                  >
                    {overview.writableSites.map((entry) => (
                      <option key={entry.id} value={entry.id}>
                        {entry.name}
                      </option>
                    ))}
                  </select>
                </label>
                <Button disabled={busy || !name.trim() || !site} type="submit">
                  Generate enrollment token
                </Button>
              </form>
              {!overview.writableSites.length ? (
                <p>You need write access to a site to create an enrollment token.</p>
              ) : null}
              {overview.scanners.length ? (
                <label className="otter-management__scanner-select">
                  Or continue setup for an existing scanner
                  <select
                    className="field-type__input"
                    aria-label="Scanner to set up"
                    onChange={(event) => {
                      setSetupScannerID(event.target.value)
                      setSetupRunID('')
                    }}
                    value={setupScannerID}
                  >
                    {overview.scanners.map((scanner) => (
                      <option key={scanner.id} value={scanner.id}>
                        {scanner.name} — {siteName(scanner.site)}
                      </option>
                    ))}
                  </select>
                </label>
              ) : null}
            </li>
            {setupScanner ? (
              <>
                <li>
                  <h3>Connect {setupScanner.name}</h3>
                  <p>
                    Status:{' '}
                    <strong>
                      {!setupScanner.enabled
                        ? 'Disabled'
                        : !setupScanner.enrolled
                          ? 'Awaiting enrollment'
                          : scannerOnline(setupScanner)
                            ? 'Connected'
                            : 'Offline'}
                    </strong>
                    {setupScanner.enrolled && setupScanner.version
                      ? ` · Otter ${setupScanner.version}`
                      : ''}
                  </p>
                  {setupScanner.enrolled && setupControllerUrl ? (
                    <div className="otter-management__commands">
                      <p>
                        Otter is enrolled. Run this command on its host to start or restart its
                        controller:
                      </p>
                      <code>{linuxStartCommand}</code>
                      <Button
                        buttonStyle="secondary"
                        onClick={() => void copy(linuxStartCommand, 'Linux command')}
                        type="button"
                      >
                        Copy Linux command
                      </Button>
                      <code>{windowsStartCommand}</code>
                      <Button
                        buttonStyle="secondary"
                        onClick={() => void copy(windowsStartCommand, 'Windows command')}
                        type="button"
                      >
                        Copy Windows command
                      </Button>
                    </div>
                  ) : null}
                  {setupScanner.enrolled && !setupControllerUrl ? (
                    <p>
                      Set <code>OTSERVER_PUBLIC_URL</code> to show the controller restart command.
                    </p>
                  ) : null}
                  {token && tokenScannerID === setupScannerID ? (
                    <div
                      className="otter-management__token"
                      aria-label="Single-use enrollment token"
                    >
                      <div>
                        <strong>Copy this single-use token now</strong>
                        <p>
                          Paste it at the Otter prompt. It expires {date(tokenExpiresAt)} and can
                          only be used once.
                        </p>
                        <p>
                          Controller URL: <code>{controllerUrl}</code>
                        </p>
                      </div>
                      <code>{token}</code>
                      <Button
                        buttonStyle="secondary"
                        onClick={() => void copy(token, 'Enrollment token')}
                        type="button"
                      >
                        Copy token
                      </Button>
                      <div className="otter-management__commands">
                        <p>On Linux, run:</p>
                        <code>{linuxEnrollCommand}</code>
                        <Button
                          buttonStyle="secondary"
                          onClick={() => void copy(linuxEnrollCommand, 'Linux enrollment command')}
                          type="button"
                        >
                          Copy Linux command
                        </Button>
                        <p>On Windows PowerShell, run:</p>
                        <code>{windowsEnrollCommand}</code>
                        <Button
                          buttonStyle="secondary"
                          onClick={() =>
                            void copy(windowsEnrollCommand, 'Windows enrollment command')
                          }
                          type="button"
                        >
                          Copy Windows command
                        </Button>
                      </div>
                    </div>
                  ) : null}
                  {!setupScanner.enrolled && !token ? (
                    <p>
                      Generate a token above, then run the enrollment command on the Otter host.
                      This page checks for the connection automatically.
                    </p>
                  ) : null}
                  {!setupScanner.enrolled ? (
                    <Button disabled={busy} onClick={() => void act(checkEnrollment)} type="button">
                      Check connection now
                    </Button>
                  ) : null}
                  {canWriteSetup ? (
                    <Button
                      buttonStyle="secondary"
                      disabled={busy}
                      onClick={() => void reenrollSetupScanner()}
                      type="button"
                    >
                      Generate a new token (revokes the current credential)
                    </Button>
                  ) : null}
                </li>
                <li>
                  <h3>Choose a scan profile</h3>
                  {setupProfiles.length ? (
                    <label>
                      Profile for the first scan
                      <select
                        className="field-type__input"
                        aria-label="Profile for first scan"
                        onChange={(event) =>
                          setSelectedProfiles((current) => ({
                            ...current,
                            [setupScanner.id]: event.target.value,
                          }))
                        }
                        value={setupProfileID}
                      >
                        {setupProfiles.map((profile) => (
                          <option key={profile.id} value={profile.id}>
                            {profile.name}
                          </option>
                        ))}
                      </select>
                    </label>
                  ) : null}
                  {setupScanner.computerName ? (
                    <p>
                      Computer: <strong>{setupScanner.computerName}</strong> · Adapter details last
                      reported {date(setupScanner.inventoryReportedAt)}
                    </p>
                  ) : (
                    <p>
                      Computer and adapter details will appear after this scanner enrolls and checks
                      in.
                    </p>
                  )}
                  {setupScanner.networkAdapters?.length ? (
                    <div className="otter-management__table-wrap">
                      <table className="table">
                        <thead>
                          <tr>
                            <th>Interface</th>
                            <th>MAC address</th>
                            <th>IP addresses</th>
                          </tr>
                        </thead>
                        <tbody>
                          {setupScanner.networkAdapters.map((adapter) => (
                            <tr key={adapter.name}>
                              <td>
                                {adapter.friendlyName}
                                <small>
                                  {adapter.name} · {adapter.description}
                                </small>
                              </td>
                              <td>{adapter.macAddress || '—'}</td>
                              <td>{adapter.ipAddresses.join(', ') || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : null}
                  {canWriteSetup ? (
                    <p>
                      Create or edit profiles with the{' '}
                      <Link href={`${adminRoute}/collections/otter-profiles`}>
                        Payload profile editor
                      </Link>
                      . It includes adapter selection, every discovery option, OPC UA ports, and
                      encrypted credentials.
                    </p>
                  ) : (
                    <p>
                      You have read access to this scanner. A user with write access can create or
                      edit its profiles.
                    </p>
                  )}
                  <Link href={`${adminRoute}/collections/otter-profiles`}>
                    Manage scan profiles →
                  </Link>
                </li>
                <li>
                  <h3>Run the first scan</h3>
                  <p>
                    Otter receives the queued scan on its next poll. Only scan networks you are
                    authorized to assess.
                  </p>
                  <Button
                    disabled={
                      busy || !setupScanner.enabled || !setupScanner.enrolled || !setupProfileID
                    }
                    onClick={() => runNow(setupScanner, setupProfileID)}
                    type="button"
                  >
                    Run first scan
                  </Button>
                  {!setupScanner.enrolled ? (
                    <small>Enroll and connect the scanner before running its first scan.</small>
                  ) : null}
                  {setupRun ? (
                    <p role="status">
                      First scan: <strong>{setupRun.status}</strong>
                      {typeof setupRun.progress === 'number' ? ` (${setupRun.progress}%)` : ''}
                      {setupRun.message ? ` — ${setupRun.message}` : ''}
                      {setupRun.import ? (
                        <>
                          {' '}
                          ·{' '}
                          <Link href={`${adminRoute}/collections/asset-imports/${setupRun.import}`}>
                            View imported inventory
                          </Link>
                        </>
                      ) : null}
                    </p>
                  ) : null}
                  <p>
                    Optional next step:{' '}
                    <Link href={`${adminRoute}/collections/otter-schedules`}>
                      schedule recurring scans
                    </Link>
                    .
                  </p>
                </li>
              </>
            ) : null}
          </ol>
        </section>

        <section className="otter-management__section">
          <div className="otter-management__section-heading">
            <div>
              <h2>Scanners</h2>
              <p>Configuration and imports remain scoped to each scanner’s site.</p>
            </div>
            <span>{overview.scanners.length} registered</span>
          </div>
          {overview.scanners.length ? (
            <div className="otter-management__table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Scanner</th>
                    <th>Site</th>
                    <th>Connection</th>
                    <th>Next run</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {overview.scanners.map((scanner) => {
                    const online = scannerOnline(scanner)
                    const activeRun = overview.runs.find((run) => run.id === scanner.currentRun)
                    return (
                      <tr key={scanner.id}>
                        <td>
                          <Link href={`${adminRoute}/collections/otter-scanners/${scanner.id}`}>
                            {scanner.name}
                          </Link>
                          <small>
                            {scanner.version ? `Otter ${scanner.version}` : 'Version not reported'}
                          </small>
                        </td>
                        <td>{siteName(scanner.site)}</td>
                        <td>
                          <Pill
                            pillStyle={
                              !scanner.enabled
                                ? 'error'
                                : scanner.enrolled && online
                                  ? 'success'
                                  : 'warning'
                            }
                          >
                            {!scanner.enabled
                              ? 'Disabled'
                              : !scanner.enrolled
                                ? 'Awaiting enrollment'
                                : online
                                  ? 'Online'
                                  : 'Offline'}
                          </Pill>
                          <small>Last seen {date(scanner.lastSeenAt)}</small>
                        </td>
                        <td>
                          {date(scanner.nextRunAt)}
                          {activeRun ? (
                            <small>
                              {activeRun.status}: {activeRun.name}
                            </small>
                          ) : null}
                        </td>
                        <td className="otter-management__actions">
                          {overview.profiles.filter((profile) => profile.scanner === scanner.id)
                            .length ? (
                            <select
                              className="field-type__input"
                              aria-label={`Profile to run on ${scanner.name}`}
                              onChange={(event) =>
                                setSelectedProfiles((current) => ({
                                  ...current,
                                  [scanner.id]: event.target.value,
                                }))
                              }
                              value={
                                selectedProfiles[scanner.id] ||
                                overview.profiles.find((profile) => profile.scanner === scanner.id)
                                  ?.id
                              }
                            >
                              {overview.profiles
                                .filter((profile) => profile.scanner === scanner.id)
                                .map((profile) => (
                                  <option key={profile.id} value={profile.id}>
                                    {profile.name}
                                  </option>
                                ))}
                            </select>
                          ) : null}
                          <Button
                            disabled={busy || !scanner.enabled}
                            onClick={() => runNow(scanner)}
                            type="button"
                          >
                            Run now
                          </Button>
                          <Button
                            buttonStyle="secondary"
                            disabled={busy}
                            onClick={() =>
                              void act(async () => {
                                const result = await request(
                                  `/api/otter/v1/scanners/${scanner.id}/reenroll`,
                                )
                                setToken(String(result.enrollmentToken || ''))
                                setTokenScannerID(scanner.id)
                                setTokenExpiresAt(String(result.expiresAt || ''))
                                setControllerUrl(String(result.controllerUrl || ''))
                                setSetupScannerID(scanner.id)
                                setMessage(
                                  `New enrollment token expires ${date(String(result.expiresAt || ''))}. The existing credential was revoked.`,
                                )
                              })
                            }
                            type="button"
                          >
                            Re-enroll
                          </Button>
                          {scanner.enabled ? (
                            <Button
                              buttonStyle="error"
                              disabled={busy}
                              onClick={() =>
                                void act(async () => {
                                  await request(`/api/otter/v1/scanners/${scanner.id}/revoke`)
                                  if (tokenScannerID === scanner.id) {
                                    setToken('')
                                    setTokenScannerID('')
                                    setTokenExpiresAt('')
                                  }
                                })
                              }
                              type="button"
                            >
                              Revoke
                            </Button>
                          ) : null}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="otter-management__empty">No scanners registered yet.</p>
          )}
        </section>

        <section className="otter-management__section">
          <div className="otter-management__section-heading">
            <div>
              <h2>Recent runs</h2>
              <p>Scheduled and manual scans use the same immutable profile snapshot.</p>
            </div>
            <Link href={`${adminRoute}/collections/otter-runs`}>All runs →</Link>
          </div>
          {overview.runs.length ? (
            <div className="otter-management__table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Run</th>
                    <th>Scanner</th>
                    <th>Status</th>
                    <th>Scheduled</th>
                    <th>Result</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {overview.runs.map((run) => (
                    <tr key={run.id}>
                      <td>
                        <Link href={`${adminRoute}/collections/otter-runs/${run.id}`}>
                          {run.name}
                        </Link>
                      </td>
                      <td>
                        {overview.scanners.find((scanner) => scanner.id === run.scanner)?.name ||
                          run.scanner}
                      </td>
                      <td>
                        <Pill
                          pillStyle={
                            ['completed'].includes(run.status)
                              ? 'success'
                              : ['failed', 'cancelled', 'expired'].includes(run.status)
                                ? 'error'
                                : 'light'
                          }
                        >
                          {run.status}
                        </Pill>
                      </td>
                      <td>{date(run.scheduledFor || run.completedAt)}</td>
                      <td>
                        {run.message ||
                          (run.import ? (
                            <Link href={`${adminRoute}/collections/asset-imports/${run.import}`}>
                              View import
                            </Link>
                          ) : (
                            '—'
                          ))}
                      </td>
                      <td>
                        {['queued', 'assigned', 'running'].includes(run.status) ? (
                          <Button
                            buttonStyle="error"
                            disabled={busy}
                            onClick={() =>
                              void act(async () => {
                                await request(`/api/otter/v1/runs/${run.id}/cancel`)
                              })
                            }
                            type="button"
                          >
                            Cancel
                          </Button>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="otter-management__empty">No scan runs yet.</p>
          )}
        </section>
      </main>
    </Gutter>
  )
}
