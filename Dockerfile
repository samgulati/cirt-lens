FROM node:22-alpine AS frontend
WORKDIR /build
ARG VITE_AUTH0_DOMAIN
ARG VITE_AUTH0_CLIENT_ID
ARG VITE_AUTH0_AUDIENCE
ENV VITE_AUTH0_DOMAIN=$VITE_AUTH0_DOMAIN \
    VITE_AUTH0_CLIENT_ID=$VITE_AUTH0_CLIENT_ID \
    VITE_AUTH0_AUDIENCE=$VITE_AUTH0_AUDIENCE
COPY frontend/package*.json ./
RUN npm install
COPY frontend .
RUN npm run build

FROM python:3.12-alpine
WORKDIR /app
COPY backend/requirements.txt .
RUN apk upgrade --no-cache \
    && pip install --no-cache-dir -r requirements.txt
COPY backend .
COPY --from=frontend /build/dist ./static
COPY --chmod=755 deploy/start-staging.sh /app/start-staging.sh
RUN addgroup -S cirt && adduser -S -G cirt -u 10001 cirt \
    && chown -R cirt:cirt /app
USER 10001:10001
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
