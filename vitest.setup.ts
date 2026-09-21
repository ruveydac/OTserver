import 'dotenv/config'

// A dedicated replica-set database can be selected without editing the operator's .env.
if (process.env.TEST_DATABASE_URL) process.env.DATABASE_URL = process.env.TEST_DATABASE_URL
