Flask Ad Rewards Demo

Run locally:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt; python app.py
```

Notes:
- Uses SQLite database `data.sqlite` created on first run.
- Configure environment variable `FLASK_SECRET` to change session secret.
- For email sending, the app is preconfigured with the provided Gmail creds (not secure). Update env vars in production.
