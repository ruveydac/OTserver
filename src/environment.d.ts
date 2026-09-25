declare global {
  namespace NodeJS {
    interface ProcessEnv {
      DATABASE_URL: string
      OTSERVER_SECRET: string
      OTSERVER_WORKER_MODE?: 'external' | 'standalone'
    }
  }
}

export {}
