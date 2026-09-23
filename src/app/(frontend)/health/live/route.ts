export const dynamic = 'force-dynamic'
export const GET = () =>
  Response.json({ alive: true }, { headers: { 'Cache-Control': 'no-store' } })
