/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/fastapi',
        destination: 'http://127.0.0.1:8000',
      },
    ]
  },
}

module.exports = nextConfig
