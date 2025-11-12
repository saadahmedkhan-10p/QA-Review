Local email setup and testing

1) Create a `.env` file in the project root (copy `.env.example`):

   cp .env.example .env

   Fill in your Gmail address and app password for `MAIL_USERNAME` and `MAIL_PASSWORD`.

2) For local testing across domains, either set `ALLOW_ALL_EMAILS=true` in `.env` or run the app with `FLASK_ENV=development`.

3) To send a specific invitation again, use the included utility:

   python send_inv_now.py

   (It will look for the token hard-coded in that script; you can edit it to use another token.)

4) To persist environment variables on Windows, set them in System Properties or use a process manager. Using `.env` with python-dotenv is convenient for local development.

Notes:
- The app now logs email send attempts via `app.logger`. SMTP exceptions will be logged with stack traces.
- Be careful with credentials. Do not commit `.env` to source control.
