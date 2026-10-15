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
export const feedSources = [
  { value: 'cisa-kev', label: 'CISA KEV', urls: [CISA_KEV_URL] },
  { value: 'nvd', label: 'NVD', urls: [] },
  { value: 'ics-advisories', label: 'ICS Advisory Project', urls: [ICS_ADVISORY_URL] },
  { value: 'csaf', label: 'CSAF', urls: [CSAF_AGGREGATOR_URL, ...CISA_CSAF_FEED_URLS] },
] as const
export type FeedSource = (typeof feedSources)[number]['value']
