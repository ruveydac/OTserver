import { createCatalogMatcher, metadataGroups, type Catalog } from '../../src/metadata/catalog'
import { catalogRevision } from '../../src/metadata/runtime'

export const catalog: Catalog = {
  manufacturers: [
    {
      id: '01a17c04-0342-71cd-a42d-edbdc92e6bb8',
      data: {
        name: 'Bosch Rexroth',
        aliases: ['Rexroth'],
        website: 'https://example.test/manufacturer',
      },
      rules: {
        any: [
          { field: 'manufacturer', operator: 'equals', value: 'Bosch Rexroth' },
          { field: 'manufacturer', operator: 'equals', value: 'Rexroth' },
        ],
      },
    },
    {
      id: '01a17c04-0336-7491-9d90-dfe4903aa9d3',
      data: { name: 'Siemens', aliases: ['Siemens AG'] },
      rules: {
        any: [
          { field: 'manufacturer', operator: 'equals', value: 'Siemens' },
          { field: 'manufacturer', operator: 'equals', value: 'Siemens AG' },
        ],
      },
    },
  ],
  devices: [
    {
      id: '01a17f24-1a24-72b7-a1f8-bf7c5e98bc6f',
      manufacturer_id: '01a17c04-0342-71cd-a42d-edbdc92e6bb8',
      device_type_id: '019a34b0-0000-7000-8000-000000000003',
      data: {
        model: 'ACTIVE Shuttle',
        device_type: 'Robotics',
        source_url: 'https://example.test/product',
        description: 'Synthetic product reference for importer tests.',
      },
      rules: { all: [{ field: 'model', operator: 'equals', value: 'ACTIVE Shuttle' }] },
    },
    {
      id: '01a17c83-695b-7f83-8cf0-ebf1b58d4c68',
      manufacturer_id: '01a17c04-0336-7491-9d90-dfe4903aa9d3',
      device_type_id: '019a34b0-0000-7000-8000-000000000001',
      data: { model: 'S7-1500', device_type: 'PLC', version_kind: 'firmware', version: 'V3.1' },
      rules: {
        all: [
          { field: 'model', operator: 'equals', value: 'S7-1500' },
          { field: 'version_kind', operator: 'equals', value: 'firmware' },
          {
            any: [
              { field: 'version', operator: 'equals', value: 'V3.1' },
              { field: 'firmware_version', operator: 'equals', value: 'V3.1' },
              { field: 'software_version', operator: 'equals', value: 'V3.1' },
            ],
          },
        ],
      },
    },
    {
      id: '019a34b0-1000-7000-8000-000000000001',
      manufacturer_id: '01a17c04-0336-7491-9d90-dfe4903aa9d3',
      device_type_id: '019a34b0-0000-7000-8000-000000000001',
      data: { product_family: 'SIMATIC test family', device_type: 'PLC' },
      rules: {
        all: [{ field: 'product_family', operator: 'equals', value: 'SIMATIC test family' }],
      },
    },
  ],
  groups: metadataGroups,
}

export const catalogManifest = { sha256: catalogRevision(catalog) }
export const matchDeviceMetadata = createCatalogMatcher(catalog, catalogManifest.sha256)
