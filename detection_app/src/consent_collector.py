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
        Internal apps: returns registration metadata + declared perms (requiredResourceAccess),
        delegated grants (oauth2PermissionGrants), and *granted app perms* (applicationGrants).
        """
        # small cache to avoid repeating lookups per resourceAppId
        perm_schema_cache: Dict[
            str, Dict[str, Dict[str, str]]
        ] = {}  # resourceAppId -> {"scopes": {id:value}, "roles": {id:value}}

        def resolve_perm_names(resource_app_id: str) -> Dict[str, Dict[str, str]]:
            if resource_app_id in perm_schema_cache:
                return perm_schema_cache[resource_app_id]
            try:
                resp = self.client.get(
                    f"{GRAPH_BASE}/servicePrincipals?$filter=appId eq '{resource_app_id}'"
                )
                sp = (resp.get("value") or [None])[0]
                scopes = (
                    {
                        s["id"]: s.get("value")
                        for s in sp.get("oauth2PermissionScopes", [])
                    }
                    if sp
                    else {}
                )
                roles = (
                    {r["id"]: r.get("value") for r in sp.get("appRoles", [])}
                    if sp
                    else {}
                )
                perm_schema_cache[resource_app_id] = {"scopes": scopes, "roles": roles}
            except Exception as e:
                logging.warning(
                    "Failed resolving schema for resourceAppId %s: %s",
                    resource_app_id,
                    e,
                )
                perm_schema_cache[resource_app_id] = {"scopes": {}, "roles": {}}
            return perm_schema_cache[resource_app_id]

        # 1) Pull internal application registrations (we’ll expand per-app)
        apps = self.client.paged_get(
            f"{GRAPH_BASE}/applications"
            "?$select=id,appId,displayName,createdDateTime,signInAudience,publisherDomain,createdBy"
        )
        internal_apps = [a for a in apps if a.get("signInAudience") == "AzureADMyOrg"]

        results: List[Dict[str, Any]] = []
        for app in internal_apps:
            app_obj_id = app.get("id")
            app_id = app.get("appId")
            if not app_obj_id or not app_id:
                logging.warning(
                    "Skipping application missing id or appId: %s",
                    app.get("displayName"),
                )
                continue

            record: Dict[str, Any] = {
                "applicationObjectId": app_obj_id,
                "appId": app_id,
                "displayName": app.get("displayName"),
                "createdDateTime": app.get("createdDateTime"),
                "signInAudience": app.get("signInAudience"),
                "publisherDomain": app.get("publisherDomain"),
                "createdBy": (
                    app.get("createdBy", {}).get("user", {}).get("displayName")
                    or app.get("createdBy", {})
                    .get("application", {})
                    .get("displayName")
                    or "Unknown"
                ),
                "createdByUserId": (
                    app.get("createdBy", {}).get("user", {}).get("id")
                    or app.get("createdBy", {}).get("application", {}).get("id")
                    or None
                ),
                "servicePrincipalId": None,
                "owners": [],
                # declared perms in registration (IDs resolved to values)
                "requiredResourceAccess": [],
                # delegated grants issued to this app (clientId == SP id)
                "oauth2PermissionGrants": [],
                # application-level perms GRANTED to this app (as principal)
                "applicationGrants": [],  # [{resourceAppId, resourceDisplayName, appRoleId, appRoleValue}]
                # assignments where others are assigned to *this* app (rarely needed, but kept)
                "appRoleAssignedTo": [],
            }

            # optional date filter (registration time)
            if start and end and record["createdDateTime"]:
                try:
                    created = datetime.fromisoformat(
                        record["createdDateTime"].replace("Z", "+00:00")
                    )
                    if not (start <= created <= end):
                        continue
                except Exception:
                    pass

            # 2) Full application object: requiredResourceAccess + owners
            try:
                app_full = self.client.get(f"{GRAPH_BASE}/applications/{app_obj_id}")
                # owners
                try:
                    owners = self.client.paged_get(
                        f"{GRAPH_BASE}/applications/{app_obj_id}/owners"
                    )
                    record["owners"] = [
                        o.get("userPrincipalName")
                        or o.get("displayName")
                        or o.get("id")
                        for o in owners
                    ]
                except Exception as e:
                    logging.warning("Owners lookup failed for %s: %s", app_id, e)

                # declared permissions
                rra = app_full.get("requiredResourceAccess", []) or []
                resolved_rra: List[Dict[str, Any]] = []
                for rr in rra:
                    resource_app_id = rr.get("resourceAppId")
                    resource_access = rr.get("resourceAccess", []) or []
                    if not resource_app_id or not resource_access:
                        continue
                    schema = resolve_perm_names(resource_app_id)
                    out_ra = []
                    for ra in resource_access:
                        rid = ra.get("id")
                        rtype = ra.get("type")
                        value = (
                            schema["scopes"].get(rid)
                            if rtype == "Scope"
                            else schema["roles"].get(rid)
                        )
                        out_ra.append({"id": rid, "type": rtype, "value": value})
                    resolved_rra.append(
                        {"resourceAppId": resource_app_id, "resourceAccess": out_ra}
                    )
                record["requiredResourceAccess"] = resolved_rra
            except Exception as e:
                logging.warning("Failed to read full application %s: %s", app_id, e)

            # 3) Map to service principal
            try:
                sp_resp = self.client.get(
                    f"{GRAPH_BASE}/servicePrincipals?$filter=appId eq '{app_id}'"
                )
                sp = (sp_resp.get("value") or [None])[0]
                sp_id = sp.get("id") if sp else None
                record["servicePrincipalId"] = sp_id
            except Exception as e:
                logging.warning("SP lookup failed for appId %s: %s", app_id, e)
                sp_id = None
                record["servicePrincipalId"] = None

            if not sp_id:
                results.append(record)
                continue

            # 4) Delegated grants to this app (clientId == SP id)
            try:
                grants = self.client.paged_get(
                    f"{GRAPH_BASE}/oauth2PermissionGrants?$filter=clientId eq '{sp_id}'"
                )
                record["oauth2PermissionGrants"] = [
                    {
                        "scope": (g.get("scope") or "").strip(),
                        "consentType": g.get("consentType"),
                        "resourceId": g.get("resourceId"),
                        "principalId": g.get("principalId"),
                    }
                    for g in grants
                    if g.get("scope") or g.get("consentType")
                ]
            except Exception as e:
                logging.warning("oauth2PermissionGrants failed for SP %s: %s", sp_id, e)

            # 5) Application-level perms GRANTED to this app ⇒ /servicePrincipals/{sp_id}/appRoleAssignments
            try:
                app_role_assignments = self.client.paged_get(
                    f"{GRAPH_BASE}/servicePrincipals/{sp_id}/appRoleAssignments"
                )
                # resolve each appRoleId via the *resource* SP’s appRoles
                # build a small cache from resourceId -> {appRoleId:value}
                resource_role_cache: Dict[str, Dict[str, str]] = {}
                for a in app_role_assignments:
                    resource_id = a.get("resourceId")
                    app_role_id = a.get("appRoleId")
                    if not resource_id or not app_role_id:
                        continue
                    if resource_id not in resource_role_cache:
                        try:
                            r_sp = self.client.get(
                                f"{GRAPH_BASE}/servicePrincipals/{resource_id}?$select=appRoles,displayName,appId"
                            )
                            role_map = {
                                r["id"]: r.get("value")
                                for r in r_sp.get("appRoles", [])
                            }
                            resource_role_cache[resource_id] = role_map
                        except Exception as e:
                            logging.warning(
                                "Role schema fetch failed for resource SP %s: %s",
                                resource_id,
                                e,
                            )
                            resource_role_cache[resource_id] = {}
                    role_value = resource_role_cache[resource_id].get(app_role_id)
                    record["applicationGrants"].append(
                        {
                            "resourceId": resource_id,
                            "appRoleId": app_role_id,
                            "appRoleValue": role_value,
                        }
                    )
            except Exception as e:
                logging.warning(
                    "appRoleAssignments (grants) failed for SP %s: %s", sp_id, e
                )

            # 6) (Optional) who/what is assigned to *this* app (rarely used for your use-case)
            try:
                assigned_to = self.client.paged_get(
                    f"{GRAPH_BASE}/servicePrincipals/{sp_id}/appRoleAssignedTo"
                )
                record["appRoleAssignedTo"] = [
                    {
                        "principalId": x.get("principalId"),
                        "principalDisplayName": x.get("principalDisplayName"),
                        "resourceDisplayName": x.get("resourceDisplayName"),
                        "appRoleId": x.get("appRoleId"),
                    }
                    for x in assigned_to
                ]
            except Exception as e:
                logging.warning("appRoleAssignedTo failed for SP %s: %s", sp_id, e)

            results.append(record)

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
