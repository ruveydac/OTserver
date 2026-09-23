export const transientFailure = (error: unknown): boolean => {
  const value = error as {
    code?: number | string
    name?: string
    hasErrorLabel?: (label: string) => boolean
  }
  return Boolean(
    value?.hasErrorLabel?.('TransientTransactionError') ||
    value?.hasErrorLabel?.('UnknownTransactionCommitResult') ||
    [
      6,
      7,
      89,
      91,
      112,
      189,
      262,
      9001,
      'ECONNRESET',
      'ETIMEDOUT',
      'ECONNREFUSED',
      'EAI_AGAIN',
    ].includes(value?.code ?? '') ||
    ['MongoNetworkError', 'MongoServerSelectionError', 'AbortError', 'TimeoutError'].includes(
      value?.name ?? '',
    ),
  )
}

// Never put network URLs, database errors, paths, request bodies, or credentials into jobs/logs.
export const safeFailure = (error: unknown): string => {
  if (transientFailure(error))
    return 'A temporary database or network failure interrupted processing.'
  const status = (error as { status?: number })?.status
  if (status === 403 || status === 401)
    return 'The executing user no longer has write permission for this site.'
  if (status === 404) return 'The submitting user, upload, or required record is missing.'
  if (status === 409)
    return 'Processing ownership or state changed. The worker will recover safely.'
  return 'Processing failed validation or an integrity check. Check the file, site, and processing inputs.'
}
