export const purdueLevels = [
  { value: '0', label: 'Level 0: Physical process and field devices' },
  { value: '1', label: 'Level 1: Basic control' },
  { value: '2', label: 'Level 2: Supervisory control' },
  { value: '3', label: 'Level 3: Site operations' },
  { value: '4', label: 'Level 4: Business planning and logistics' },
  { value: '5', label: 'Level 5: Corporate systems' },
]

export const purdueLabel = (levels?: null | string[]) =>
  levels?.length
    ? purdueLevels
        .filter(({ value }) => levels.includes(value))
        .map(({ label }) => label)
        .join('; ')
    : 'Unclassified'
