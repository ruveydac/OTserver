export const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
export const CSAF_AGGREGATOR_URL =
  'https://aggregator.certvde.com/.well-known/csaf-aggregator/aggregator.json'
export const CISA_CSAF_FEED_URLS = [
  'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json',
  'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json',
] as const
export const ICS_ADVISORY_URL =
  'https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv'
export const NVD_FEED_BASE_URL = 'https://nvd.nist.gov/feeds/json/cve/2.0'
export const FIRST_NVD_YEAR = 2002
export const MAX_CUSTOM_CSAF_FEEDS = 100
export const CSAF_FEED_TYPES = ['aggregator', 'provider-metadata', 'rolie'] as const
export type CsafFeedType = (typeof CSAF_FEED_TYPES)[number]
export type CustomCsafFeed = { name: string; type: CsafFeedType; url: string }

export const validateCsafFeedURL = (value: unknown): true | string => {
  if (typeof value !== 'string' || value.length > 2048 || !URL.canParse(value))
    return 'Enter a valid HTTPS URL.'
  const url = new URL(value)
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !hostname.includes('.') ||
    hostname.includes(':') ||
    /^\d+(?:\.\d+){3}$/.test(hostname) ||
    /\.(?:localhost|local|internal|test|invalid|example)$/.test(hostname)
  )
    return 'Use a public HTTPS URL without credentials, a query, or a fragment.'
  return true
}

export const validateCustomCsafFeeds = (value: unknown): true | string => {
  if (value == null) return true
  if (!Array.isArray(value) || value.length > MAX_CUSTOM_CSAF_FEEDS)
    return `Add no more than ${MAX_CUSTOM_CSAF_FEEDS} custom CSAF feeds.`
  const urls = new Set<string>()
  for (const item of value) {
    const feed = item as Record<string, unknown> | null
    if (
      !feed ||
      typeof feed.name !== 'string' ||
      !feed.name.trim() ||
      feed.name.trim().length > 120 ||
      typeof feed.type !== 'string' ||
      !CSAF_FEED_TYPES.includes(feed.type as CsafFeedType) ||
      validateCsafFeedURL(feed.url) !== true
    )
      return 'Each custom CSAF feed needs a name, supported format, and public HTTPS URL.'
    const url = new URL((feed.url as string).trim()).href
    if (urls.has(url)) return 'Custom CSAF feed URLs must be unique.'
    urls.add(url)
  }
  return true
}

export const normalizeCustomCsafFeeds = (value: unknown): CustomCsafFeed[] => {
  const validation = validateCustomCsafFeeds(value)
  if (validation !== true) throw new Error(validation)
  const feeds = (Array.isArray(value) ? value : []) as CustomCsafFeed[]
  return feeds.map(({ name, type, url }) => ({
    name: name.trim(),
    type,
    url: new URL(url.trim()).href,
  }))
}

export const feedSources = [
  { value: 'cisa-kev', label: 'CISA KEV', urls: [CISA_KEV_URL] },
  { value: 'nvd', label: 'NVD', urls: [] },
  { value: 'ics-advisories', label: 'ICS Advisory Project', urls: [ICS_ADVISORY_URL] },
  { value: 'csaf', label: 'CSAF', urls: [CSAF_AGGREGATOR_URL, ...CISA_CSAF_FEED_URLS] },
] as const
export type FeedSource = (typeof feedSources)[number]['value']
