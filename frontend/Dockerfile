# HAAFIZ frontend — build stage then nginx to serve static assets.
FROM node:20-slim AS build
WORKDIR /srv/haafiz
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY . .
# Vite inlines VITE_* at build time, so these must be build args, not runtime env.
ARG VITE_API_URL=/api
ARG VITE_AI_URL=
ENV VITE_API_URL=$VITE_API_URL VITE_AI_URL=$VITE_AI_URL
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /srv/haafiz/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://localhost/ >/dev/null || exit 1
