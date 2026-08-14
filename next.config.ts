import { withPayload } from '@payloadcms/next/withPayload'
import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  allowedDevOrigins: ['192.168.50.*'],
  output: 'standalone',
  reactStrictMode: true,
}

export default withPayload(nextConfig)
