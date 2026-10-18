import * as migration_20260922_205151_queued_import_baseline from './20260922_205151_queued_import_baseline'
import * as migration_20260926_111902_site_paths from './20260926_111902_site_paths'
import * as migration_20261010_164200_otter_indexes from './20261010_164200_otter_indexes'
import * as migration_20261013_130000_legacy_identity from './20261013_130000_legacy_identity'
import * as migration_20261018_120000_site_types from './20261018_120000_site_types'

export const migrations = [
  {
    up: migration_20260922_205151_queued_import_baseline.up,
    down: migration_20260922_205151_queued_import_baseline.down,
    name: '20260922_205151_queued_import_baseline',
  },
  {
    up: migration_20260926_111902_site_paths.up,
    down: migration_20260926_111902_site_paths.down,
    name: '20260926_111902_site_paths',
  },
  {
    up: migration_20261010_164200_otter_indexes.up,
    down: migration_20261010_164200_otter_indexes.down,
    name: '20261010_164200_otter_indexes',
  },
  {
    up: migration_20261013_130000_legacy_identity.up,
    down: migration_20261013_130000_legacy_identity.down,
    name: '20261013_130000_legacy_identity',
  },
  {
    up: migration_20261018_120000_site_types.up,
    down: migration_20261018_120000_site_types.down,
    name: '20261018_120000_site_types',
  },
]
