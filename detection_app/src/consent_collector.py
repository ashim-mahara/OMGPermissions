import json
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import List, Dict, Optional
from .graph_client import GraphClient
from .config import GRAPH_BASE, OUTPUT_DIR
from .models import UserConsent, ApplicationSummary


class ConsentCollector:
    def __init__(self):
        self.client = GraphClient()

    def list_users(self) -> List[Dict]:
        url = f"{GRAPH_BASE}/users"
        return self.client.paged_get(
            url, params={"$select": "id,displayName,userPrincipalName"}
        )

    def get_user_consents(self, user_id: str) -> List[Dict]:
        url = f"{GRAPH_BASE}/users/{user_id}/oauth2PermissionGrants"
        return self.client.paged_get(url)

    def collect_signins(
        self,
        start: datetime,
        end: datetime,
        step_days: int = 2,
    ) -> List[Dict]:
        """Iteratively collect sign-ins between date ranges to avoid 504 errors."""
        all_logs = []
        current = start
        while current < end:
            next_cursor = min(current + timedelta(days=step_days), end)
            filter_query = f"createdDateTime ge {current.isoformat()} and createdDateTime lt {next_cursor.isoformat()}"
            url = f"{GRAPH_BASE}/auditLogs/signIns"
            params = {"$filter": filter_query, "$top": 100}
            logging.info(f"Fetching sign-ins {current} → {next_cursor}")
            try:
                logs = self.client.paged_get(url, params=params)
                all_logs.extend(logs)
                logging.info(f"  +{len(logs)} logs fetched in window.")
            except Exception as e:
                logging.warning(
                    f"Failed fetching logs for {current}–{next_cursor}: {e}"
                )
            current = next_cursor
        logging.info(f"Total collected sign-ins: {len(all_logs)}")
        return all_logs

    def collect_external_consents(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        output_file: str = "external_consents.json",
    ) -> List[ApplicationSummary]:
        """Collect user consented external applications within a time window."""
        users = self.list_users()
        user_consents: List[UserConsent] = []

        for user in users:
            grants = self.get_user_consents(user["id"])
            for g in grants:
                consent_time = g.get("consentType")
                # date filter if needed
                if start and end:
                    created = g.get("createdDateTime")
                    if created:
                        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        if not (start <= dt <= end):
                            continue
                user_consents.append(
                    UserConsent(
                        user_id=user["id"],
                        user_principal_name=user.get("userPrincipalName", ""),
                        user_display_name=user.get("displayName", ""),
                        app_id=g.get("clientId", ""),
                        resource_id=g.get("resourceId", ""),
                        scope=g.get("scope", ""),
                    )
                )

        app_map: Dict[str, ApplicationSummary] = defaultdict(
            lambda: ApplicationSummary("", "", [], [])
        )
        for uc in user_consents:
            app = app_map[uc.app_id]
            app.app_id = uc.app_id
            app.permissions.append(uc.scope)
            app.users.append(uc.user_principal_name)

        for app in app_map.values():
            app.permissions = sorted(set(app.permissions))
            app.users = sorted(set(app.users))
            try:
                sp_data = self.client.get(
                    f"{GRAPH_BASE}/servicePrincipals?$filter=appId eq '{app.app_id}'"
                )
                if sp_data.get("value"):
                    app.display_name = sp_data["value"][0].get("displayName", "")
            except Exception:
                app.display_name = "External or Unknown"

        results = [a.__dict__ for a in app_map.values()]
        out_path = f"{OUTPUT_DIR}/{output_file}"
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
        logging.info(f"Saved {len(results)} apps to {out_path}")

        return list(app_map.values())
