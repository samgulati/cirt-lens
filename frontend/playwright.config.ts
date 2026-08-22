import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./e2e',use:{baseURL:'http://127.0.0.1:5174'},webServer:[
  {command:'.venv/bin/alembic upgrade head && .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8011',cwd:'../backend',url:'http://127.0.0.1:8011/api/ready',reuseExistingServer:false},
  {command:'npm run dev -- --host 127.0.0.1 --port 5174',env:{VITE_API_PROXY:'http://127.0.0.1:8011'},url:'http://127.0.0.1:5174',reuseExistingServer:false},
]});
