FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# VITE_API_URL is injected at build time by Railway
ARG VITE_API_URL
ENV VITE_API_URL=${VITE_API_URL}

RUN npm run build

# Production - nginx
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx config as a template for automatic envsubst replacement at startup
COPY nginx.conf /etc/nginx/templates/default.conf.template

# Default port env var in case it is not provided
ENV PORT=80
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
