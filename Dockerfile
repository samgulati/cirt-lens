FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm install
COPY frontend .
RUN npm run build

FROM python:3.14-alpine
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend .
COPY --from=frontend /build/dist ./static
RUN addgroup -S cirt && adduser -S -G cirt -u 10001 cirt \
    && chown -R cirt:cirt /app
USER 10001:10001
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
