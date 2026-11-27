import { assetSearchFields, maxAssetSearchLength } from './assetSearchFields'

const fields = Object.keys(assetSearchFields).sort()
const commonFields = ['site', 'vendor', 'status', 'tag']

export function assetSearchHints(query: string, caret: number) {
  if (query.trim().length > maxAssetSearchLength) {
    return {
      hint: `Invalid asset search: query is longer than ${maxAssetSearchLength} characters.`,
      suggestions: [],
    }
  }
  const before = query.slice(0, caret)
  const after = query.slice(caret)
  // Ignore escaped characters and completed literals when locating the editable token.
  const context = before.replace(/\\.|"(?:\\.|[^"\\])*"|[[{][^\]}]*[\]}]/g, '_')
  if (/["[{\\]/.test(context)) return { suggestions: [] }
  const emptyField = !after.trim() && context.match(/(?:^|[\s(])(\w+):\s*$/)
  if (emptyField && Object.hasOwn(assetSearchFields, emptyField[1].toLowerCase())) {
    return { hint: `Enter a value for ${emptyField[1]}.`, suggestions: [] }
  }

  const word = context.match(/(?:^|[\s(])([a-z]+)$/i)?.[1] ?? ''
  const operator = /(?:^|\s)(?:AND|OR|NOT)$/.test(context.trimEnd())
  const matches =
    word && !operator ? fields.filter((field) => field.startsWith(word.toLowerCase())) : []
  let start = before
  let end = after
  if (matches.length) {
    const remainder = after.match(/^[a-z]*(?::|(?=[\s()]|$))/i)
    if (!remainder) return { suggestions: [] }
    start = before.slice(0, -word.length)
    end = after.slice(remainder[0].length)
  } else {
    if (after) return { suggestions: [] }
    if (start.trim() && !start.trimEnd().endsWith('(')) {
      if (!/\s$/.test(start)) start += ' '
      if (!operator) start += 'AND '
    }
  }

  const suggestions = (matches.length ? matches.slice(0, 4) : commonFields).map((field) => {
    const inserted = `${start}${field}:`
    return { field, query: inserted + end, caret: inserted.length }
  })
  return { suggestions }
}
