import { defineConfig } from 'vitest/config'
import tsconfigPaths from 'vite-tsconfig-paths'

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    coverage: {
      exclude: [
        'src/app/**',
        'src/environment.d.ts',
        'src/importers/types.ts',
        'src/payload-types.ts',
        'src/types/**',
      ],
      include: ['src/**/*.{ts,tsx}'],
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      thresholds: { branches: 90, functions: 90, lines: 90, statements: 90 },
    },
    environment: 'node',
    fileParallelism: false,
    include: ['tests/int/**/*.int.spec.ts'],
    setupFiles: ['./vitest.setup.ts'],
  },
})
