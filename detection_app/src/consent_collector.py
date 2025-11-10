import json
import logging
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Optional, Any
from .graph_client import GraphClient
from .config import GRAPH_BASE, OUTPUT_DIR
from .models import ApplicationSummary
from .external_app_resolver import ExternalAppResolver


def _split_scopes(scope_blob: str) -> List[str]:
    if not isinstance(scope_blob, str) or not scope_blob.strip():
        return []
    # support space- or comma-separated
    toks = scope_blob.replace(",", " ").split()
    return [t.strip() for t in toks if t.strip()]


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
        Collects internal (tenant-owned) applications with detailed permission data.
        Includes:
        - requiredResourceAccess: permissions the app declares (requested)
        - oauth2PermissionGrants: delegated (user) permissions granted
        - applicationGrants: admin-consented application permissions granted
        """

        perm_schema_cache = {}
        resource_cache = {}
        resource_spid_cache = {}

        def resolve_perm_schema(resource_app_id: str):
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
                return perm_schema_cache[resource_app_id]
            except Exception as e:
                logging.warning(
                    f"Failed to resolve permission schema for {resource_app_id}: {e}"
                )
                perm_schema_cache[resource_app_id] = {"scopes": {}, "roles": {}}
                return perm_schema_cache[resource_app_id]

        def resolve_resource_sp_by_appid(resource_app_id: str) -> Optional[str]:
            """Translate a global appId (like Microsoft Graph) to the tenant-specific SP objectId."""
            if resource_app_id in resource_spid_cache:
                return resource_spid_cache[resource_app_id]
            try:
                res = self.client.get(
                    f"{GRAPH_BASE}/servicePrincipals?$filter=appId eq '{resource_app_id}'&$select=id"
                )
                vals = res.get("value")
                if vals and len(vals) > 0:
                    spid = vals[0].get("id")
                    resource_spid_cache[resource_app_id] = spid
                    return spid
            except Exception as e:
                logging.warning(
                    f"Failed to resolve SP for resourceAppId {resource_app_id}: {e}"
                )
            resource_spid_cache[resource_app_id] = None
            return None

        # Get all internal tenant applications
        apps = self.client.paged_get(
            f"{GRAPH_BASE}/applications?$select=id,appId,displayName,createdDateTime,signInAudience,publisherDomain"
        )
        internal_apps = [a for a in apps if a.get("signInAudience") == "AzureADMyOrg"]

        results = []
        for app in internal_apps:
            app_id = app.get("appId")
            app_obj_id = app.get("id")
            if not app_id or not app_obj_id:
                continue

            rec = {
                "applicationObjectId": app_obj_id,
                "appId": app_id,
                "displayName": app.get("displayName"),
                "createdDateTime": app.get("createdDateTime"),
                "publisherDomain": app.get("publisherDomain"),
                "servicePrincipalId": None,
                "requiredResourceAccess": [],
                "oauth2PermissionGrants": [],
                "applicationGrants": [],
            }

            # Optional date filter
            if start and end and rec["createdDateTime"]:
                dt = datetime.fromisoformat(
                    rec["createdDateTime"].replace("Z", "+00:00")
                )
                if not (start <= dt <= end):
                    continue

            # --- Declared permissions (what the app requests) ---
            try:
                app_full = self.client.get(f"{GRAPH_BASE}/applications/{app_obj_id}")
                rra = app_full.get("requiredResourceAccess", []) or []
                for rr in rra:
                    schema = resolve_perm_schema(rr["resourceAppId"])
                    ra_out = []
                    for ra in rr.get("resourceAccess", []):
                        rid, typ = ra.get("id"), ra.get("type")
                        val = (
                            schema["scopes"].get(rid)
                            if typ == "Scope"
                            else schema["roles"].get(rid)
                        )
                        ra_out.append({"id": rid, "type": typ, "value": val})
                    res_info = resolve_resource_sp_by_appid(rr["resourceAppId"])
                    display = "Unknown"
                    if res_info:
                        try:
                            res_detail = self.client.get(
                                f"{GRAPH_BASE}/servicePrincipals/{res_info}?$select=displayName"
                            )
                            display = res_detail.get("displayName", "Unknown")
                        except Exception:
                            pass
                    rec["requiredResourceAccess"].append(
                        {
                            "resourceAppId": rr["resourceAppId"],
                            "resourceDisplayName": display,
                            "resourceAccess": ra_out,
                        }
                    )
            except Exception as e:
                logging.warning(
                    f"Failed reading requiredResourceAccess for {app_id}: {e}"
                )

            # Service principal lookup
            try:
                sp_resp = self.client.get(
                    f"{GRAPH_BASE}/servicePrincipals?$filter=appId eq '{app_id}'"
                )
                sp = (sp_resp.get("value") or [None])[0]
                if sp:
                    rec["servicePrincipalId"] = sp.get("id")
            except Exception as e:
                logging.warning(f"SP lookup failed for {app_id}: {e}")

            sp_id = rec["servicePrincipalId"]
            if not sp_id:
                results.append(rec)
                continue

            # Delegated (user) grants
            try:
                grants = self.client.paged_get(
                    f"{GRAPH_BASE}/oauth2PermissionGrants?$filter=clientId eq '{sp_id}'"
                )
                rec["oauth2PermissionGrants"] = [
                    {"scope": g.get("scope"), "consentType": g.get("consentType")}
                    for g in grants
                ]
            except Exception as e:
                logging.warning(
                    f"Failed to fetch oauth2PermissionGrants for {sp_id}: {e}"
                )

            # Application-level (admin) grants
            try:
                assigns = self.client.paged_get(
                    f"{GRAPH_BASE}/servicePrincipals/{sp_id}/appRoleAssignments"
                )
                resource_role_cache = {}

                for a in assigns:
                    resource_id = a.get("resourceId")
                    app_role_id = a.get("appRoleId")
                    if not resource_id or not app_role_id:
                        continue

                    # If resourceId looks like an appId (e.g., Graph), resolve SP ID first
                    sp_lookup_id = (
                        resource_id
                        if "-" in resource_id and not resource_id.startswith("00000003")
                        else resolve_resource_sp_by_appid(resource_id)
                    )
                    if not sp_lookup_id:
                        continue

                    if sp_lookup_id not in resource_role_cache:
                        try:
                            r_sp = self.client.get(
                                f"{GRAPH_BASE}/servicePrincipals/{sp_lookup_id}?$select=displayName,appId,appRoles"
                            )
                            resource_role_cache[sp_lookup_id] = {
                                "displayName": r_sp.get("displayName"),
                                "appId": r_sp.get("appId"),
                                "roles": {
                                    r["id"]: r.get("value")
                                    for r in r_sp.get("appRoles", [])
                                },
                            }
                        except Exception as e:
                            logging.warning(
                                f"Failed resolving roles for resource {sp_lookup_id}: {e}"
                            )
                            resource_role_cache[sp_lookup_id] = {
                                "displayName": "Unknown",
                                "appId": None,
                                "roles": {},
                            }

                    resource = resource_role_cache[sp_lookup_id]
                    role_value = resource["roles"].get(app_role_id)
                    rec["applicationGrants"].append(
                        {
                            "resourceAppId": resource["appId"],
                            "resourceDisplayName": resource["displayName"],
                            "appRoleId": app_role_id,
                            "appRoleValue": role_value,
                        }
                    )
            except Exception as e:
                logging.warning(f"Failed to read appRoleAssignments for {sp_id}: {e}")

            results.append(rec)

        return results

    def collect_external_consents(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[ApplicationSummary]:
        """
        Build external application summaries by:
        - Translating oauth2PermissionGrant.clientId (SP objectId) to (appId, displayName)
        - Filtering OUT tenant-owned apps (internal) via /applications?appId=...
        - Aggregating scopes and users per external appId
        """
        resolver = ExternalAppResolver(self.client)
        users = self.list_users()
        app_map: Dict[str, ApplicationSummary] = defaultdict(
            lambda: ApplicationSummary(
                app_id="", display_name="", permissions=[], users=[]
            )
        )
        # keep a preferred display name per app_id
        name_cache: Dict[str, str] = {}

        for user in users:
            grants = self.get_user_consents(user["id"])
            for g in grants:
                # optional time window
                if start and end and g.get("createdDateTime"):
                    try:
                        dt = datetime.fromisoformat(
                            g["createdDateTime"].replace("Z", "+00:00")
                        )
                        if not (start <= dt <= end):
                            continue
                    except Exception:
                        pass

                client_sp_id = g.get("clientId")
                if not client_sp_id:
                    continue

                # Resolve SP → (global appId, displayName)
                app_id, disp = resolver.resolve_client_sp(client_sp_id)
                if not app_id:
                    # can't identify the app globally; skip
                    continue

                # Keep only EXTERNAL: skip if this appId is tenant-owned
                if resolver.is_tenant_owned(app_id):
                    continue

                # Aggregate scopes and users
                scopes = _split_scopes(g.get("scope", ""))
                summ = app_map[app_id]
                summ.app_id = app_id
                # set or keep a decent display name for the app_id
                if app_id not in name_cache and disp:
                    name_cache[app_id] = disp
                summ.display_name = name_cache.get(app_id, summ.display_name)

                if scopes:
                    summ.permissions.extend(scopes)
                # Add the consenting user
                summ.users.append(user.get("userPrincipalName", ""))

        # de-dup + sort
        out: List[ApplicationSummary] = []
        for app in app_map.values():
            app.permissions = sorted(
                {p for p in app.permissions if isinstance(p, str) and p}
            )
            app.users = sorted({u for u in app.users if u})
            out.append(app)

        return out
