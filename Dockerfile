# Multi-arch slim Node image
FROM node:18-alpine

# App dir
WORKDIR /app

# Install deps
COPY package*.json ./
# Prefer ci when lockfile exists, fallback to install
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --production; fi \
    && npm cache clean --force

# Copy sources
COPY . .

# Environment
ENV NODE_ENV=production
ENV PORT=3000
# DATA_DIR is provided by render.yaml to a persistent disk mounted at /data

EXPOSE 3000

# Start server
CMD ["node", "server.js"]
