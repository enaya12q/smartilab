Flask Ad Rewards Demo

Run locally:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt; python app.py
```

Notes:
- Uses SQLite database `data.sqlite` created on first run.
- Configure environment variable `FLASK_SECRET` to change session secret.
- For email sending, the app is preconfigured with the provided Gmail creds (not secure). Update env vars in production.

Switching to Supabase/Postgres (optional):
- Set `DATABASE_URL` environment variable in Vercel or locally to your Supabase Postgres connection string.
- Add `MAIL_USERNAME`, `MAIL_PASSWORD`, `FLASK_SECRET` to environment variables.

Vercel deployment:
- Push repository to GitHub and connect to Vercel.
- Add environment variables in Vercel settings (DATABASE_URL, MAIL_USERNAME, MAIL_PASSWORD, FLASK_SECRET).
- Use Python runtime — `vercel.json` is included in the repo.
