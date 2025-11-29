# external_app_resolver.py
import logging
from typing import Optional, Tuple, Dict
from .graph_client import GraphClient
from .config import GRAPH_BASE


class ExternalAppResolver:
    """
    Resolve app identity from a servicePrincipal objectId and determine if it's tenant-owned.

    Responsibilities:
    - servicePrincipalId → (appId, displayName)
    - appId → is_tenant_owned (backed by /applications?appId=...)
    - aggressive caching to avoid hammering Graph
    """

    def __init__(self, client: GraphClient):
        self.client = client

        # Cache: spId -> (appId, displayName)
        self._sp_cache: Dict[str, Tuple[Optional[str], str]] = {}

        # Cache: appId -> is_owned_by_tenant
        self._owned_cache: Dict[str, bool] = {}

    # --------------------------------------------------------
    # Resolve SP → (appId, displayName)
    # --------------------------------------------------------
    def resolve_client_sp(self, service_principal_id: str) -> Tuple[Optional[str], str]:
        if service_principal_id in self._sp_cache:
            return self._sp_cache[service_principal_id]

        app_id, display_name = None, ""
        try:
            sp = self.client.get(
                f"{GRAPH_BASE}/servicePrincipals/{service_principal_id}"
                "?$select=appId,displayName,servicePrincipalType"
            )
            app_id = sp.get("appId")
            display_name = sp.get("displayName", "") or ""
        except Exception as e:
            logging.warning(
                f"[ExternalAppResolver] Failed to resolve SP {service_principal_id}: {e}"
            )

        self._sp_cache[service_principal_id] = (app_id, display_name)
        return app_id, display_name

    # --------------------------------------------------------
    # Determine if appId is tenant-owned
    # --------------------------------------------------------
    def is_tenant_owned(self, app_id: Optional[str]) -> bool:
        """
        Checks if this global appId corresponds to an Application in this tenant.
        If yes → internal/tenant-owned.
        If no  → external (multi-tenant SaaS or another tenant's line-of-business app).
        """
        if not app_id:
            return False

        if app_id in self._owned_cache:
            return self._owned_cache[app_id]

        owned = False
        try:
            resp = self.client.get(
                f"{GRAPH_BASE}/applications?$filter=appId eq '{app_id}'&$select=id"
            )
            owned = bool(resp.get("value"))
        except Exception as e:
            logging.warning(
                f"[ExternalAppResolver] Owned check failed for appId={app_id}: {e}"
            )
            owned = False

        self._owned_cache[app_id] = owned
        return owned
