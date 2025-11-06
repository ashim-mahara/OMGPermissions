# in consent_collector.py (or a new module near it)
import logging
from typing import Optional, Tuple, Dict
from .graph_client import GraphClient
from .config import GRAPH_BASE


class ExternalAppResolver:
    """
    Resolve external app identity from oauth2PermissionGrant.clientId (SP objectId)
    → (global appId, displayName), and determine if that appId is tenant-owned.
    """

    def __init__(self, client: GraphClient):
        self.client = client
        self._sp_cache: Dict[
            str, Tuple[Optional[str], str]
        ] = {}  # spId -> (appId, displayName)
        self._owned_cache: Dict[str, bool] = {}  # appId -> is_owned_by_tenant

    def resolve_client_sp(self, service_principal_id: str) -> Tuple[Optional[str], str]:
        if service_principal_id in self._sp_cache:
            return self._sp_cache[service_principal_id]

        app_id, display_name = None, ""
        try:
            sp = self.client.get(
                f"{GRAPH_BASE}/servicePrincipals/{service_principal_id}?$select=appId,displayName"
            )
            app_id = sp.get("appId")
            display_name = sp.get("displayName", "") or ""
        except Exception as e:
            logging.warning(f"Failed to resolve SP {service_principal_id}: {e}")

        self._sp_cache[service_principal_id] = (app_id, display_name)
        return app_id, display_name

    def is_tenant_owned(self, app_id: Optional[str]) -> bool:
        if not app_id:
            return False
        if app_id in self._owned_cache:
            return self._owned_cache[app_id]
        try:
            resp = self.client.get(
                f"{GRAPH_BASE}/applications?$filter=appId eq '{app_id}'&$select=id"
            )
            owned = bool(resp.get("value"))
        except Exception as e:
            logging.warning(f"Owned check failed for appId={app_id}: {e}")
            owned = False
        self._owned_cache[app_id] = owned
        return owned
