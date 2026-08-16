export const Brand = ({ height = '32px', alt = 'OTserver' }: { height?: string; alt?: string }) => (
  <img src="/otserver.svg" alt={alt} style={{ height, width: 'auto' }} />
)

export const Icon = () => <Brand />
export const Logo = () => <Brand height="36px" alt="otserver.org" />
