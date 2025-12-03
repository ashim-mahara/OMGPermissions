# Open Microsoft Graph Permissions

OMGPermissions is a detection and alerting system for **Microsoft Graph API permissions**. It identifies risky application permissions, analyzes changes over time, and notifies defenders about abnormal or potentially dangerous permission grants. It also provides a lightweight Azure AD sign-in portal to simulate and investigate user-consent flows.

---

## 🔍 What It Does

- **Detects elevated or risky permissions** (e.g., `Mail.Read`, `Directory.Read.All`) granted to apps in your tenant.
- **Monitors changes** over time using a lightweight SQLite database.
- **Sends alerts** to Slack when new apps or permission changes are detected.
- **Includes an authentication portal** using FastAPI for testing Azure OAuth login flows.

---

## 🏗️ Architecture

```text
.
├── detection_app/         → Main logic for scanning Graph API permissions
│   └── src/
│       ├── main.py        → Entry point for detection
│       ├── graph_client.py → Graph API queries
│       ├── detection_logic.py → Change tracking
│       ├── slack_notifier.py → Sends alerts
│       └── config.py      → Loads credentials from .env
├── azure_auth_app/        → Lightweight FastAPI auth portal (MSAL)
│   └── main.py
├── prompts/               → Prompt templates for analysis
├── utils/                 → Reusable helpers
├── .env                   → Your secret configuration (see below)
├── install.sh             → Linux installer (with cron setup)
├── setup_env.sh           → Interactive .env generator
└── README.md              → This file
````

---

## ⚙️ Setup

### 1. Clone and Install

```bash
git clone https://github.com/your-username/OMGPermissions.git
cd OMGPermissions
sudo bash install.sh
```

This will:

* Install the app to `/opt/OMGPermissions` (or a custom location),
* Set up a Python virtual environment,
* Install required packages,
* Prompt for credentials (see `.env`),
* Schedule a **cron job** to run the detection hourly.

> ✅ Logs are saved to `/opt/OMGPermissions/detection.log`.

---

### 2. Required Environment Variables

The app uses a `.env` file for secrets. You'll be prompted for:

| Variable            | Description                                          |
| ------------------- | ---------------------------------------------------- |
| `AZ_TENANT_ID`      | Azure AD Tenant ID for Graph API app                 |
| `AZ_CLIENT_ID`      | App ID (client) for Graph API                        |
| `AZ_CLIENT_SECRET`  | Secret for the above app                             |
| `CLIENT_ID`         | Client ID for Azure auth portal                      |
| `CLIENT_SECRET`     | Secret for the auth portal                           |
| `TENANT_ID`         | (optional) Tenant ID override                        |
| `REDIRECT_URI`      | (optional) Default: `http://localhost:8000/callback` |
| `SLACK_WEBHOOK_URL` | (optional) Slack webhook for alerts                  |

Example `.env`:

```
AZ_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZ_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZ_CLIENT_SECRET=super-secret
CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CLIENT_SECRET=also-secret
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

---

### 3. Run Detection Manually

```bash
cd /opt/OMGPermissions
source venv/bin/activate
python -m detection_app.src.main
```

---

## 🧪 Auth Portal (Optional)

You can run the FastAPI-based Azure auth portal to test user sign-in flows:

```bash
cd /opt/OMGPermissions/azure_auth_app
uvicorn main:app --reload
```

Then visit `http://localhost:8000` in your browser to test login.

---

## 📦 Logs and State

* `detection.log` — Log output from each cron run.
* `permission_analysis.db` — Snapshot of known app permissions.
* `detection_state.db` — Tracks detected changes and alerts.

You can safely delete these files to reset state (they'll be recreated).

---

## 🛡️ Security Notes

* Be sure to **use strong secrets** in your `.env` file.
* Do not expose your `.env` or database files publicly.
* Set correct permissions on install dir: `chmod 700 /opt/OMGPermissions`.

---

## 📌 Roadmap / Ideas

* [ ] Export detections to JSON or SIEM
* [ ] Better risk scoring on permission sets
* [ ] Auto-remediation via Graph API
* [ ] Add log rotation and retention

---

## 🤝 Contributions

Pull requests welcome — especially around detection logic and integrations with alerting tools (e.g. email, SIEM).

---

## 🧠 Credits

Built for a cybersecurity capstone. Designed for defenders investigating cloud identity risks.

---

## 📝 License

MIT

```

---

Let me know if you’d like me to also generate the `requirements.txt` or prep a `systemd` alternative instead of `cron`.
```
