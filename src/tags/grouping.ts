import type { Where, WhereField } from 'payload'

export type TagGroupOption = { id: string; name: string }

export const groupTags = <T extends { group?: TagGroupOption }>(tags: T[]) => {
  const groups = new Map<string, { id: string; name: string; tags: T[] }>()
  for (const tag of tags) {
    const id = tag.group?.id || 'ungrouped'
    const group = groups.get(id) || {
      id,
      name: tag.group?.name || 'Ungrouped',
      tags: [],
    }
    group.tags.push(tag)
    groups.set(id, group)
  }
  return [...groups.values()].sort((left, right) => left.name.localeCompare(right.name))
}

const withoutTagGroup = (where: Where): Where => {
  const result: Where = {}
  for (const [field, value] of Object.entries(where)) {
    if (field === 'group') continue
    if (field === 'and' || field === 'or') {
      const branches = (value as Where[])
        .map(withoutTagGroup)
        .filter((branch) => Object.keys(branch).length)
      if (branches.length) result[field] = branches
    } else {
      result[field] = value
    }
  }
  return result
}

const groupFilter = (where: Where): WhereField | undefined => {
  if (where.group && !Array.isArray(where.group)) return where.group
  for (const branch of [...(where.and || []), ...(where.or || [])]) {
    const found = groupFilter(branch)
    if (found) return found
  }
}

export const selectedTagGroup = (where?: Where) => {
  const filter = where ? groupFilter(where) : undefined
  if (filter?.equals !== undefined) return String(filter.equals)
  if (filter?.exists === false) return 'ungrouped'
  return 'all'
}

export const filterTagsByGroup = (where: Where | undefined, groupID: string): Where | undefined => {
  const base = where ? withoutTagGroup(where) : {}
  if (groupID === 'all') return Object.keys(base).length ? base : undefined

  const group = groupID === 'ungrouped' ? { exists: false } : { equals: groupID }
  return Object.keys(base).length ? { and: [base, { group }] } : { group }
}
