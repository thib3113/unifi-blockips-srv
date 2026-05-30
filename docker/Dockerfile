# Stage 1: Build
FROM node:lts-alpine AS builder

# Install build dependencies for potential native modules
RUN apk add --no-cache build-base python3

# Install pnpm
RUN npm install -g pnpm

WORKDIR /app

# Copy dependency manifests
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Install all dependencies
RUN pnpm install --frozen-lockfile

# Copy source code
COPY . .

# Build the project
RUN pnpm build

# Remove development dependencies
RUN pnpm prune --prod

# Stage 2: Run
FROM node:lts-alpine

WORKDIR /app

# Set environment to production
ENV NODE_ENV=production

# Create a non-privileged user to run the app
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy built assets and production dependencies from builder
COPY --from=builder /app/build ./build
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/ecosystem.config.js ./ecosystem.config.js

# Copy and prepare the entrypoint script
COPY docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Switch to the non-privileged user
USER appuser

ENTRYPOINT ["docker-entrypoint.sh"]
