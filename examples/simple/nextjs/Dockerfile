# syntax=docker/dockerfile:1.4
FROM node:18-alpine

RUN apk add --no-cache libc6-compat
WORKDIR /app

# Install dependencies
COPY --link package.json package-lock.json* ./
RUN npm ci

COPY --link . ./

EXPOSE 3000

ENV NEXT_TELEMETRY_DISABLED 1
ENV PORT 3000
ENV HOSTNAME localhost

CMD ["npm", "run", "dev"]
