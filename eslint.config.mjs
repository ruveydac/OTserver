import nextVitals from 'eslint-config-next/core-web-vitals'
import nextTypescript from 'eslint-config-next/typescript'

const eslintConfig = [
  ...nextVitals,
  ...nextTypescript,
  {
    files: [
      'src/domain/**/*.ts',
      'src/vulnerabilities/{matching,parsers}.ts',
      'src/importers/{nmap,proneta,otserverOtter,assetQuality}.ts',
      'src/identity/{keys,evidence}.ts',
    ],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: [
                'payload',
                '@payloadcms/*',
                'next',
                'next/*',
                '**/collections/**',
                '**/payload-types',
                '**/payload.config',
              ],
              message: 'Pure rules must not depend on framework or persistence types.',
            },
          ],
        },
      ],
    },
  },
  {
    ignores: ['.next/**', 'src/payload-types.ts'],
  },
]

export default eslintConfig
