import { defineConfig } from '@playwright/test';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
const python = process.env.E2E_PYTHON || '.venv/bin/python';
const databaseUrl = `sqlite:///${join(tmpdir(), `cirt-lens-e2e-${process.pid}.db`)}`;
export default defineConfig({
  testDir: './e2e',
  use: { baseURL: 'http://127.0.0.1:5174' },
  webServer: [
    {
      command: `${python} -m alembic upgrade head && ${python} -m uvicorn app.main:app --host 127.0.0.1 --port 8011`,
      cwd: '../backend',
      env: {
        ...process.env,
        DATABASE_URL: databaseUrl,
        AUTH_REQUIRED: 'false',
        AUTH_MODE: 'local',
      },
      url: 'http://127.0.0.1:8011/api/ready',
      reuseExistingServer: false,
    },
    {
      command: 'npm run dev -- --host 127.0.0.1 --port 5174',
      env: { VITE_API_PROXY: 'http://127.0.0.1:8011' },
      url: 'http://127.0.0.1:5174',
      reuseExistingServer: false,
    },
  ],
});
