# Multi-arch slim Node image
FROM node:18-alpine

# App dir
WORKDIR /app

# Install deps
COPY package*.json ./
# Harden npm for Render builder (retries, no progress) and avoid cache clean
RUN npm config set fetch-retries 5 \
 && npm config set fetch-retry-maxtimeout 120000 \
 && npm config set fund false \
 && npm config set audit false \
 && if [ -f package-lock.json ]; then npm ci --omit=dev --no-audit --no-fund --no-progress; else npm install --omit=dev --no-audit --no-fund --no-progress; fi

# Copy sources
COPY . .

# Environment
ENV NODE_ENV=production
ENV PORT=3000
# DATA_DIR is provided by render.yaml to a persistent disk mounted at /data

EXPOSE 3000

# Start server
CMD ["node", "server.js"]
