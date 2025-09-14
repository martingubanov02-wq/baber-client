# Use Debian-based image (more reliable npm on Render than alpine)
FROM node:18-bullseye-slim

# App dir
WORKDIR /app

# Install deps
# Copy only package.json to avoid strict lockfile mismatch with npm ci
COPY package.json ./
# Install without dev deps; set CI=false to relax peer deps
ENV CI=false
RUN npm set progress=false \
 && npm config set fund false \
 && npm config set audit false \
 && npm install --omit=dev

# Copy sources
COPY . .

# Environment
ENV NODE_ENV=production
ENV PORT=3000
# DATA_DIR is provided by render.yaml to a persistent disk mounted at /data

EXPOSE 3000

# Start server
CMD ["node", "server.js"]
