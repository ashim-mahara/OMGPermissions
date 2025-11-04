import json
import csv
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Optional, Any
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

    def _write_outputs(self, data: List[Dict], base_name: str, mode: str):
        """Write results to JSON + JSONL in outputs directory."""
        json_path = f"{OUTPUT_DIR}/{base_name}-{mode}.json"
        jsonl_path = f"{OUTPUT_DIR}/{base_name}-{mode}.jsonl"

        # Convert dataclass objects → dicts (safe for serialization)
        serialized = [d.__dict__ if hasattr(d, "__dict__") else d for d in data]

        # JSON
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(serialized, f, indent=2, ensure_ascii=False)

        # JSONL
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for item in serialized:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")

        logging.info(f"Saved outputs:\n  JSON → {json_path}\n  JSONL → {jsonl_path}")

    def collect_internal_consents(
        self, start: Optional[datetime] = None, end: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Collect details about internal applications registered within the tenant.
        Includes metadata about app creation, permissions, and consent.
        """
        # Get all applications
        url = f"{GRAPH_BASE}/applications?$select=id,appId,displayName,createdDateTime,signInAudience,publisherDomain,createdBy"
        apps = self.client.paged_get(url)
        internal_apps = [a for a in apps if a.get("signInAudience") == "AzureADMyOrg"]

        results = []
        for app in internal_apps:
            app_id = app.get("appId")
            if not app_id:
                logging.warning("Skipping app with missing appId")
                continue

            app_data = {
                "appId": app_id,
                "displayName": app.get("displayName"),
                "createdDateTime": app.get("createdDateTime"),
                "signInAudience": app.get("signInAudience"),
                "publisherDomain": app.get("publisherDomain"),
                "createdBy": app.get("createdBy", {})
                .get("user", {})
                .get("displayName"),
                "createdByUserId": app.get("createdBy", {}).get("user", {}).get("id"),
            }

            # Filter by creation date if range specified
            if start and end and app_data["createdDateTime"]:
                created = datetime.fromisoformat(
                    app_data["createdDateTime"].replace("Z", "+00:00")
                )
                if not (start <= created <= end):
                    continue

            # Get service principal (enterprise app object)
            try:
                sp_resp = self.client.get(
                    f"{GRAPH_BASE}/servicePrincipals?$filter=appId eq '{app_id}'"
                )
                if sp_resp.get("value"):
                    sp = sp_resp["value"][0]
                    app_data["servicePrincipalId"] = sp.get("id")
            except Exception as e:
                logging.warning(
                    f"Failed to get service principal for appId {app_id}: {e}"
                )
                app_data["servicePrincipalId"] = None

            # Get assigned permissions / roles
            try:
                grants = self.client.paged_get(
                    f"{GRAPH_BASE}/oauth2PermissionGrants?$filter=clientId eq '{app_id}'"
                )
                app_data["oauth2PermissionGrants"] = [g.get("scope") for g in grants]
            except Exception as e:
                logging.warning(
                    f"Failed to get OAuth2 permission grants for appId {app_id}: {e}"
                )
                app_data["oauth2PermissionGrants"] = []

            try:
                if not app_data["servicePrincipalId"]:
                    continue

                roles = self.client.paged_get(
                    f"{GRAPH_BASE}/servicePrincipals/{app_data['servicePrincipalId']}/appRoleAssignedTo"
                )
                app_data["appRoleAssignments"] = [
                    r.get("principalDisplayName") for r in roles
                ]
            except Exception as e:
                logging.warning(
                    f"Failed to get app role assignments for servicePrincipalId {app_data['servicePrincipalId']}: {e}"
                )
                app_data["appRoleAssignments"] = []

            results.append(app_data)

        return results

    def collect_external_consents(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[ApplicationSummary]:
        """Collect user consented external applications within a time window."""
        users = self.list_users()
        user_consents: List[UserConsent] = []

        for user in users:
            grants = self.get_user_consents(user["id"])
            for g in grants:
                if start and end and g.get("createdDateTime"):
                    dt = datetime.fromisoformat(
                        g["createdDateTime"].replace("Z", "+00:00")
                    )
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
            app.permissions = sorted(
                {p.strip() for p in app.permissions if isinstance(p, str)}
            )
            app.users = sorted(set(app.users))
            try:
                sp_data = self.client.get(
                    f"{GRAPH_BASE}/servicePrincipals?$filter=appId eq '{app.app_id}'"
                )
                if sp_data.get("value"):
                    app.display_name = sp_data["value"][0].get("displayName", "")
            except Exception:
                app.display_name = "External or Unknown"

        return list(app_map.values())
