# Hospital Management System

Academic Hospital Management System built with Python, Gradio and SQLite.

## Run locally
1. Install Python 3.10 or newer.
2. Install dependencies: `pip install -r requirements.txt`
3. Set the first administrator credentials:
   - `ADMIN_USERNAME` (at least 4 characters)
   - `ADMIN_PASSWORD` (at least 10 characters)
4. Run: `python app.py`
5. Open the local address shown in the terminal.

## Hosting notes
- The app reads `PORT` from the hosting platform.
- Set `DB_PATH` to a persistent disk path if the host supports persistent storage.
- Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` as private environment variables before the first launch.
- Use fictional test records only. This academic project is not certified for real patient data or production clinical use.
- SQLite data can be lost if the hosting platform uses an ephemeral filesystem. Configure a persistent disk or migrate to a managed database before relying on stored records.
