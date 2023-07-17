/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/fastapi',
        destination: 'http://localhost:8000',
      },
    ]
  },
}

module.exports = nextConfig
