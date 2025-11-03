import requests
import msal
import logging
from typing import List, Dict, Any, Optional
from .config import TENANT_ID, CLIENT_ID, CLIENT_SECRET


class GraphClient:
    def __init__(self):
        self.token = self._get_token()

    def _get_token(self) -> str:
        app = msal.ConfidentialClientApplication(
            CLIENT_ID,
            authority=f"https://login.microsoftonline.com/{TENANT_ID}",
            client_credential=CLIENT_SECRET,
        )
        result = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        if "access_token" not in result:
            raise RuntimeError(f"Failed to acquire token: {result}")
        return result["access_token"]

    def get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = requests.get(url, headers=headers, params=params, timeout=120)
        if resp.status_code >= 400:
            logging.error("Graph API error %s: %s", resp.status_code, resp.text)
            raise RuntimeError(f"Graph API error {resp.status_code}: {resp.text}")
        return resp.json()

    def paged_get(
        self, url: str, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        items = []
        while url:
            data = self.get(url, params)
            items.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = None
        return items
