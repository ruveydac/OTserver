import type { PayloadRequest } from 'payload'

export const withRequestContext = async <T>(
  req: PayloadRequest,
  values: Record<string, unknown>,
  work: () => Promise<T>,
): Promise<T> => {
  const previous = new Map(Object.keys(values).map((key) => [key, req.context[key]]))
  Object.assign(req.context, values)
  try {
    return await work()
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete req.context[key]
      else req.context[key] = value
    }
  }
}
