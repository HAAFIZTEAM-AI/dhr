# HAAFIZ backend (Express + SQLite)
FROM node:20-slim

WORKDIR /srv/haafiz

# sqlite3 has a native build step; these are needed for node-gyp and absent from
# the slim image. Build deps are dropped in the same layer they were added.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 make g++ curl \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

RUN apt-get purge -y python3 make g++ && apt-get autoremove -y

COPY . .

# The database lives on a named volume, not in the image. Committing haafiz.db
# was how a user's password hash ended up in a public repository.
RUN useradd --create-home --uid 10001 haafiz \
    && mkdir -p /srv/haafiz/data \
    && chown -R haafiz:haafiz /srv/haafiz
USER haafiz

ENV NODE_ENV=production \
    PORT=3001 \
    DB_PATH=/srv/haafiz/data/haafiz.db

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:3001/health || exit 1

CMD ["node", "server.js"]
