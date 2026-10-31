const MAX_REGEX_LENGTH = 256

export const validateAssignmentRegex = (value: null | string | undefined): string | true => {
  if (!value) return 'Enter a regular expression.'
  if (value.length > MAX_REGEX_LENGTH)
    return `Regular expressions are limited to ${MAX_REGEX_LENGTH} characters.`
  if (/\\[1-9]/.test(value)) return 'Backreferences are not supported in assignment rules.'
  if (
    /\((?:[^()]|\\.)*(?:[*+]|\{\d+(?:,\d*)?\})(?:[^()]|\\.)*\)(?:[*+]|\{\d+(?:,\d*)?\})/.test(value)
  )
    return 'Nested quantified groups are not supported in assignment rules.'
  try {
    new RegExp(value, 'i')
    return true
  } catch {
    return 'Enter a valid regular expression.'
  }
}
