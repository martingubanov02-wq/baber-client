# Use Debian-based image (more reliable npm on Render than alpine)
FROM node:18-bullseye-slim

# App dir
WORKDIR /app

# Install deps
COPY package*.json ./
# Install without dev deps; set CI=false to relax peer deps
ENV CI=false
RUN npm set progress=false \
 && npm config set fund false \
 && npm config set audit false \
 && if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# Copy sources
COPY . .

# Environment
ENV NODE_ENV=production
ENV PORT=3000
# DATA_DIR is provided by render.yaml to a persistent disk mounted at /data

EXPOSE 3000

# Start server
CMD ["node", "server.js"]
