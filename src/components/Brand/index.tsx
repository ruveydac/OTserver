import Image from 'next/image'

export const Brand = ({ height = '32px', alt = 'OTserver' }: { height?: string; alt?: string }) => (
  <Image
    src="/otserver.svg"
    alt={alt}
    width={160}
    height={32}
    style={{ height, width: 'auto' }}
    unoptimized
  />
)

export const Icon = () => <Brand />
export const Logo = () => <Brand height="36px" alt="otserver.org" />
