export const assetListURL = (
  adminRoute: string,
  field: 'assetClass' | 'site',
  value: number | string,
) => {
  const query = new URLSearchParams({ [`where[${field}][equals]`]: String(value) })
  return `${adminRoute}/collections/assets?${query}`
}
