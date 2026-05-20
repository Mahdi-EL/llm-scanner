# ── Build Stage ───────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci --legacy-peer-deps

COPY . .

# Injected at build time: docker build --build-arg REACT_APP_API_URL=https://…
ARG REACT_APP_API_URL=http://localhost:8000
ENV REACT_APP_API_URL=$REACT_APP_API_URL

RUN npm run build


# ── Runtime Stage (nginx) ─────────────────────────────────────
FROM nginx:1.27-alpine

COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
