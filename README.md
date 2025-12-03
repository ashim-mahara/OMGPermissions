# Open Microsoft Graph Permissions

OMGPermissions is a detection and alerting system for **Microsoft Graph application permissions**. It inventories apps in an Azure AD tenant, evaluates the risk of the permissions they have been granted, detects changes over time, and sends alerts when suspicious or high-risk permission activity is observed. It also includes a lightweight Azure AD authentication portal used to simulate and test OAuth consent flows.

---

## Overview

OMGPermissions performs three core tasks:

1. **Collects all enterprise and third-party apps**
   - Queries Microsoft Graph for service principals, delegated grants, and app role assignments.
   - Identifies internal vs external applications.

2. **Evaluates permission risk**
   - Looks up permissions in a local risk database (`permission_analysis.db`).
   - Applies rule-based floors (e.g., any `*.ReadWrite.All` permission is automatically high-risk).
   - Computes app-level risk tiers (low / medium / high / critical).

3. **Detects changes over time**
   - Compares current permissions to previously seen state in `detection_state.db`.
   - Generates alerts for:
     - New applications
     - Newly granted permissions
     - Risk tier increases
     - Sudden risk score spikes

Alerts can be sent to Slack via an incoming webhook URL.

The repository also includes an **Azure AD Login Portal** built with FastAPI + MSAL that allows multi-tenant OAuth login for experimentation with delegated permissions.

---

## Project Structure

```

OMGPermissions/
├── detection_app/
│   └── src/
│       ├── main.py                 # Entry point for detection pipeline
│       ├── graph_client.py         # MSAL client credentials auth + Graph queries
│       ├── consent_collector.py    # Collects app & permission grant data
│       ├── detection_pipeline.py   # Risk scoring, state comparison, alerting
│       ├── alert_notification.py   # Slack notifier wrapper
│       ├── external_app_resolver.py# Maps service principals to real apps
│       ├── models.py               # Typed models used across pipeline
│       └── config.py               # Loads Azure secrets from environment
│
├── azure_auth_app/
│   ├── main.py                     # FastAPI OAuth login portal
│   ├── auth_handler.py             # MSAL multi-tenant auth logic
│   ├── config.py                   # Portal client config + scopes
│   ├── templates/                  # HTML templates (Jinja2)
│   └── static/                     # Static assets
│
├── prompts/
│   └── long-prompt/
│       └── permission_risk_score.py# LLM-based permission risk generator (optional)
│
├── utils/
│   └── download_oauth_azure_permissions.py  # Fetches MS Graph permission catalog
│
├── install.sh                      # Automated Linux installer (cron + venv)
├── setup_env.sh                    # Interactive .env generator
└── README.md

````

---

## Installation (Linux)

Run the automated installer:

```bash
git clone https://github.com/your-username/OMGPermissions.git
cd OMGPermissions
sudo bash install.sh
````

The installer will:

* Copy the project into `/opt/OMGPermissions` (or a custom path).
* Create a Python virtual environment.
* Install required dependencies.
* Prompt you for Azure & Slack configuration and generate `.env`.
* Install an **hourly cron job** that runs:

  ```
  python -m detection_app.src.main
  ```

Detection logs appear in:

```
/opt/OMGPermissions/detection.log
```

---

## Configuration (.env)

The application requires a `.env` file containing:

| Variable            | Purpose                                                                                    |
| ------------------- | ------------------------------------------------------------------------------------------ |
| `AZ_TENANT_ID`      | Azure AD Tenant ID used for Graph API scanning (client credentials).                       |
| `AZ_CLIENT_ID`      | Client ID of the Azure AD **app registration** with Graph API **application** permissions. |
| `AZ_CLIENT_SECRET`  | Secret for the above client.                                                               |
| `CLIENT_ID`         | Client ID for the optional OAuth login portal (delegated login).                           |
| `CLIENT_SECRET`     | Secret for the OAuth portal.                                                               |
| `TENANT_ID`         | Optional. Defaults to multi-tenant (`organizations`).                                      |
| `REDIRECT_URI`      | Optional. Defaults to `http://localhost:8000/callback`.                                    |
| `SLACK_WEBHOOK_URL` | Optional. Enables Slack alerting.                                                          |

Example:

```bash
AZ_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZ_CLIENT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeffffffff
AZ_CLIENT_SECRET=your-client-secret
CLIENT_ID=11111111-2222-3333-4444-555555555555
CLIENT_SECRET=your-auth-portal-secret
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
```

**Do not commit this file.**

---

## Running the Detection Pipeline Manually

```bash
cd /opt/OMGPermissions
source venv/bin/activate
python -m detection_app.src.main
```

This performs:

* Graph API collection
* Permission risk scoring
* Change detection
* Alerting
* State database update

---

## Azure AD OAuth Portal (Optional)

Start the portal:

```bash
cd /opt/OMGPermissions/azure_auth_app
uvicorn main:app --reload
```

Navigate to:

```
http://localhost:8000
```

You can test:

* Multi-tenant OAuth login
* Delegated permission consent
* Viewing user profile & token details

Tokens are stored in `tokens.json`.

---

## Databases & Logs

OMGPermissions uses three types of persistent files:

| File                     | Purpose                                                              |
| ------------------------ | -------------------------------------------------------------------- |
| `detection_state.db`     | Tracks previously seen apps & permissions.                           |
| `permission_analysis.db` | Risk scores for individual Graph permissions (optional / generated). |
| `detection.log`          | Pipeline output from cron & manual execution.                        |

Output JSON/JSONL files of collected consents also appear in:

```
outputs/
```

---

## Optional: Generate Permission Risk Scores

If you want AI-generated risk context for each Microsoft Graph permission:

```bash
python utils/download_oauth_azure_permissions.py
python prompts/long-prompt/permission_risk_score.py -f permissions.jsonl -k <YOUR_API_KEY>
```

This populates `permission_analysis.db` with:

* Numerical risk score
* Natural-language reasoning

The detection engine automatically uses these values.

---

## Limitations / Roadmap

* SIEM export not yet implemented.
* No built-in log rotation.
* Risk scoring is extensible but may require rebuilding `permission_analysis.db`.
* UI is minimal (CLI + Slack).

---

## License

MIT License. You are free to use, modify, and extend OMGPermissions.

---

## Author

Created as part of a cybersecurity capstone with a focus on Azure AD / Microsoft Entra ID identity threat detection.
