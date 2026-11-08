export const matchesRegexValues = (values: unknown[], regex: RegExp, maxLength = 512) =>
  values.some(
    (value) =>
      (typeof value === 'string' || typeof value === 'number') &&
      regex.test(String(value).slice(0, maxLength)),
  )
