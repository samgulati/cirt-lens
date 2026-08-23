# Free staging deployment

CIRT Lens uses one Render Free Docker web service, a Neon Free PostgreSQL database, Upstash Free Redis, and the Auth0 Free tenant. The API and worker share the staging container to remain within the single free compute service constraint; production deployments should run them independently.

The committed `render.yaml` contains only public identifiers. `DATABASE_URL`, `REDIS_URL`, and `AUTH0_MANAGEMENT_CLIENT_SECRET` must be entered in Render as secret environment variables. Never paste local `.env` contents into source control.

Render Free services sleep after inactivity, so the first request may take approximately one minute. Neon and Upstash usage must remain within their published free quotas.

After Render assigns the HTTPS URL, add that exact origin to the Auth0 SPA's Allowed Callback URLs, Allowed Logout URLs, and Allowed Web Origins. Keep the localhost entries for development.
