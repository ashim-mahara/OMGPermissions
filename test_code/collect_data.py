import os
import json
import csv
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta, timezone

import msal
import requests

## Configuration
TENANT_ID = os.environ.get("AZ_TENANT_ID", "4bdc93f9-8510-45ea-9913-11f9f55ac337")
CLIENT_ID = os.environ.get("AZ_CLIENT_ID", "c2357e4e-06a0-4466-8fc7-7902568e0f4a")
CLIENT_SECRET = os.environ.get("AZ_CLIENT_SECRET", "None")
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

OUTPUT_DIR = "./outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


## Authenticate the application
def get_app_token() -> str:
    app = msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
    )
    scopes = ["https://graph.microsoft.com/.default"]
    result = app.acquire_token_for_client(scopes=scopes)
    if "access_token" not in result:
        logging.error("Failed to acquire token: %s", result)
        raise SystemExit(
            "Auth failure - check client id/secret/tenant and that permissions are granted"
        )
    return result["access_token"]


## Pagination
def paged_get(
    url: str, token: str, params: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    "Generic paging for Graph v1.0; returns list of items across pages."
    items = []
    headers = {"Authorization": f"Bearer {token}"}
    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=120)
        if resp.status_code >= 400:
            logging.error("GET %s -> %s : %s", url, resp.status_code, resp.text)
            raise RuntimeError(f"Graph API error {resp.status_code}: {resp.text}")
        data = resp.json()
        page_items = data.get("value", [])
        items.extend(page_items)
        next_link = data.get("@odata.nextLink")
        url = next_link
        # params only for first request
        params = None
    return items


## Collect sign-in logs
def collect_signins(
    token: str, filter_query: Optional[str] = None, top: int = 100
) -> List[Dict[str, Any]]:
    """
    Collect sign-in logs.
      - filter_query: OData $filter string (e.g., "createdDateTime ge 2025-10-01T00:00:00Z")
      - top: page size (Graph supports $top but server may override)
    Returns list of sign-in records.
    """
    url = f"{GRAPH_BASE}/auditLogs/signIns"
    params = {}
    if filter_query:
        params["$filter"] = filter_query
    params["$top"] = top
    logging.info("Fetching sign-ins (this may take a while depending on date range)...")
    return paged_get(url, token, params=params)


## Get grouped sign-ins by application
def group_signins_by_app(signins: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Returns dict keyed by appId (or resourceDisplayName fallback) with counts and sample records.
    """
    grouped = {}
    for s in signins:
        app_id = s.get("appId") or s.get("resourceDisplayName") or "unknown"
        display = (
            s.get("resourceDisplayName") or s.get("appDisplayName") or "Unknown App"
        )
        key = f"{app_id}"
        if key not in grouped:
            grouped[key] = {
                "appId": app_id,
                "displayName": display,
                "count": 0,
                "sample_signins": [],
            }
        grouped[key]["count"] += 1
        if len(grouped[key]["sample_signins"]) < 5:
            grouped[key]["sample_signins"].append(
                {
                    "id": s.get("id"),
                    "userDisplayName": s.get("userDisplayName"),
                    "createdDateTime": s.get("createdDateTime"),
                    "ipAddress": s.get("ipAddress"),
                    "status": s.get("status"),
                    "conditionalAccessPolicies": s.get("conditionalAccessStatus"),
                }
            )
    return grouped


## Get permissions for service principals
def list_service_principals(
    token: str, filter_query: Optional[str] = None
) -> List[Dict[str, Any]]:
    url = f"{GRAPH_BASE}/servicePrincipals"
    params = {}
    if filter_query:
        params["$filter"] = filter_query
    params["$top"] = 100
    logging.info("Listing service principals (enterprise apps)...")
    return paged_get(url, token, params=params)


## Get app role assignments and oauth2 permission grants
def get_app_role_assignments_for_sp(sp_id: str, token: str) -> List[Dict[str, Any]]:
    url = f"{GRAPH_BASE}/servicePrincipals/{sp_id}/appRoleAssignedTo"
    return paged_get(url, token)


## Get oauth2 permission grants
def get_oauth2_permission_grants_for_sp(sp_id: str, token: str) -> List[Dict[str, Any]]:
    # oauth2PermissionGrants is tenant-scoped; filter by clientId
    url = f"{GRAPH_BASE}/oauth2PermissionGrants"
    params = {"$filter": f"clientId eq '{sp_id}'", "$top": "100"}
    headers = {"Authorization": f"Bearer {token}"}
    items = []
    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code >= 400:
            logging.error("GET %s -> %s : %s", url, resp.status_code, resp.text)
            raise RuntimeError(f"Graph API error {resp.status_code}: {resp.text}")
        data = resp.json()
        items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        params = None
    return items


def main():
    token = get_app_token()

    # 1) Collect sign-ins. Example: last 30 days.
    # Use ISO8601 timestamp - adjust range as needed.

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=30)

    all_signins = []
    chunk = timedelta(days=3)
    cursor = start
    while cursor < end:
        next_cursor = min(cursor + chunk, end)
        filter_str = f"createdDateTime ge {cursor.isoformat()} and createdDateTime lt {next_cursor.isoformat()}"
        logging.info(f"Fetching sign-ins from {cursor} to {next_cursor}")
        try:
            batch = collect_signins(token, filter_query=filter_str)
            all_signins.extend(batch)
            logging.info("Got %d sign-ins in this window", len(batch))
        except Exception as e:
            logging.warning("Failed to fetch window %s–%s: %s", cursor, next_cursor, e)
        cursor = next_cursor

    signins = all_signins
    logging.info("Fetched %d sign-in records (last 30d).", len(signins))

    grouped = group_signins_by_app(signins)

    # Save signins and grouping
    with open(os.path.join(OUTPUT_DIR, "signins_raw.json"), "w") as f:
        json.dump(signins, f, default=str, indent=2)
    with open(os.path.join(OUTPUT_DIR, "signins_grouped.json"), "w") as f:
        json.dump(grouped, f, default=str, indent=2)

    # 2) For each enterprise app that had signins, fetch permissions
    # First map appId -> servicePrincipal id(s). Note: appId is the application (client) id;
    # servicePrincipal objects in a tenant have appId property equal to the application's client id.
    app_ids = list(grouped.keys())
    # Some entries may be "unknown" or resourceDisplayName-only. We'll list all service principals and match.
    sps = list_service_principals(token)
    logging.info("Retrieved %d service principals in tenant.", len(sps))

    # Build map: appId -> list of sp objects
    appid_to_sps = {}
    for sp in sps:
        appid = sp.get("appId")
        if not appid:
            continue
        if appid not in appid_to_sps:
            appid_to_sps[appid] = []
        appid_to_sps[appid].append(sp)

    permissions_summary = {}

    # Limit to service principals that appear in sign-in groups; also show unmatched sps optionally
    for appid in app_ids:
        # if it's "unknown" skip
        if appid == "unknown":
            continue
        sp_list = appid_to_sps.get(appid, [])
        if not sp_list:
            logging.info(
                "No service principal found for appId %s (maybe external app).", appid
            )
            permissions_summary[appid] = {
                "servicePrincipals": [],
                "note": "no matching sp in tenant",
            }
            continue

        sp_entries = []
        for sp in sp_list:
            sp_id = sp.get("id")
            sp_display = sp.get("displayName")
            logging.info("Collecting permissions for SP %s (%s)", sp_id, sp_display)
            # app role assignments (application permissions)
            try:
                approle_assigns = get_app_role_assignments_for_sp(sp_id, token)
            except Exception as e:
                logging.exception(
                    "Failed getting appRoleAssignedTo for %s: %s", sp_id, e
                )
                approle_assigns = []
            # delegated tenant grants
            try:
                oauth2_grants = get_oauth2_permission_grants_for_sp(sp_id, token)
            except Exception as e:
                logging.exception(
                    "Failed getting oauth2PermissionGrants for %s: %s", sp_id, e
                )
                oauth2_grants = []

            sp_entries.append(
                {
                    "id": sp_id,
                    "displayName": sp_display,
                    "appRoleAssignedTo_count": len(approle_assigns),
                    "sample_appRoleAssignedTo": approle_assigns[:5],
                    "oauth2PermissionGrants_count": len(oauth2_grants),
                    "sample_oauth2PermissionGrants": oauth2_grants[:5],
                    "raw_sp": sp,
                }
            )
        permissions_summary[appid] = {"servicePrincipals": sp_entries}

    # Save permissions summary
    with open(os.path.join(OUTPUT_DIR, "permissions_summary.json"), "w") as f:
        json.dump(permissions_summary, f, default=str, indent=2)

    # Optional: write CSV that connects appId, displayName, sign-in count, permission counts
    csv_rows = []
    for appid, info in grouped.items():
        row = {
            "appId": appid,
            "displayName": info.get("displayName"),
            "signInCount": info.get("count"),
        }
        perms = permissions_summary.get(appid, {})
        # aggregate permission counts if available
        sps_info = perms.get("servicePrincipals", [])
        total_approle = sum(sp.get("appRoleAssignedTo_count", 0) for sp in sps_info)
        total_oauth2 = sum(sp.get("oauth2PermissionGrants_count", 0) for sp in sps_info)
        row["appRoleAssignments"] = total_approle
        row["oauth2PermissionGrants"] = total_oauth2
        csv_rows.append(row)

    csv_path = os.path.join(OUTPUT_DIR, "apps_signin_permission_summary.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "appId",
                "displayName",
                "signInCount",
                "appRoleAssignments",
                "oauth2PermissionGrants",
            ],
        )
        writer.writeheader()
        for r in csv_rows:
            writer.writerow(r)

    logging.info("Done. Outputs written to %s", OUTPUT_DIR)
    logging.info(
        "Files: signins_raw.json, signins_grouped.json, permissions_summary.json, %s",
        os.path.basename(csv_path),
    )


if __name__ == "__main__":
    main()
