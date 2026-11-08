'use client'

import './TagGroupTabs.scss'

export type TagGroupTabOption = { id: string; name: string }

export default function TagGroupTabs({
  groups,
  label,
  onSelect,
  selected,
}: {
  groups: TagGroupTabOption[]
  label: string
  onSelect: (id: string) => void
  selected: string
}) {
  return groups.length ? (
    <div aria-label={label} className="tag-group-tabs" role="group">
      {groups.map((group) => (
        <button
          aria-pressed={selected === group.id}
          className="tag-group-tabs__button"
          key={group.id}
          onClick={() => onSelect(group.id)}
          type="button"
        >
          {group.name}
        </button>
      ))}
    </div>
  ) : null
}
