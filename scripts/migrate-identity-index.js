/* global db, print */
// Run with mongosh during the documented maintenance window, before starting the new manager.
// Idempotent: drops only the obsolete single-field UNIQUE MAC index, never documents.
for (const index of db.getCollection('assets').getIndexes()) {
  if (index.unique && index.key.macAddress === 1 && Object.keys(index.key).length === 1) {
    db.getCollection('assets').dropIndex(index.name)
    print(`Removed legacy unique MAC index: ${index.name}`)
  }
}
