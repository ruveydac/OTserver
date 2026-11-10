import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'
import Ajv2020 from 'ajv/dist/2020'
import addFormats from 'ajv-formats'
import { describe, expect, it } from 'vitest'
import manufacturersSchema from '../../src/data/device-metadata/schema/ot-manufacturers.schema.json'
import devicesSchema from '../../src/data/device-metadata/schema/ot-devices.schema.json'
import groupsSchema from '../../src/data/device-metadata/schema/ot-device-types.schema.json'

const metadataRoot = resolve(process.cwd(), 'otserver-metadata')
const readJSON = (path: string) => JSON.parse(readFileSync(path, 'utf8'))

describe('OTserver metadata schema compatibility', () => {
  it('validates every record published by the embedded metadata repository', () => {
    const ajv = new Ajv2020({ allErrors: true })
    addFormats(ajv)
    ajv.addSchema(groupsSchema)

    const validateManufacturers = ajv.compile(manufacturersSchema)
    const validateDevices = ajv.compile(devicesSchema)
    const dataRoot = resolve(metadataRoot, 'data')

    expect(
      ajv.compile(groupsSchema)(
        readJSON(
          resolve(metadataRoot, 'schema/ot-device-types.schema.json'),
        ).$defs.deviceType.oneOf.map((item: { const: unknown }) => item.const),
      ),
    ).toBe(true)
    expect(validateManufacturers(readJSON(resolve(dataRoot, 'ot-manufacturers.json')))).toBe(true)

    for (const name of readdirSync(dataRoot).filter((name) => name.startsWith('ot-devices-'))) {
      expect(
        validateDevices(readJSON(resolve(dataRoot, name))),
        JSON.stringify(validateDevices.errors),
      ).toBe(true)
    }
  })
})
