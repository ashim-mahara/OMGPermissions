import json
import os
from datetime import datetime, timedelta
import msal
from config import config


class AzureAuthHandler:
    """
    Multi-tenant Azure authentication handler.
    Each customer (tenant) gets its own tokens, stored separately.
    """

    def __init__(self):
        # tenant_id -> token bundle
        self.tokens = {}
        self.load_tokens()

        # Use multi-tenant authority for SaaS
        self.authority = "https://login.microsoftonline.com/organizations"

        self.app = msal.ConfidentialClientApplication(
            client_id=config.CLIENT_ID,
            authority=self.authority,
            client_credential=config.CLIENT_SECRET,
        )

    # ----------------------------------------------------------------------
    # Persistent token storage
    # ----------------------------------------------------------------------

    def load_tokens(self):
        """Load all tenants' tokens from file"""
        try:
            if os.path.exists(config.TOKEN_FILE):
                with open(config.TOKEN_FILE, "r") as f:
                    self.tokens = json.load(f)
        except Exception as e:
            print(f"Error loading tokens: {e}")
            self.tokens = {}

    def save_all_tokens(self):
        """Persist all tenant tokens to disk"""
        try:
            with open(config.TOKEN_FILE, "w") as f:
                json.dump(self.tokens, f, indent=2)
        except Exception as e:
            print(f"Error saving token file: {e}")

    def save_tenant_tokens(self, tenant_id, token_response):
        """Save a token bundle for one tenant"""
        self.tokens[tenant_id] = {
            "access_token": token_response.get("access_token"),
            "refresh_token": token_response.get("refresh_token"),
            "id_token": token_response.get("id_token"),
            "expires_in": token_response.get("expires_in"),
            "token_type": token_response.get("token_type"),
            "scope": token_response.get("scope"),
            "acquired_at": datetime.utcnow().isoformat(),
        }
        self.save_all_tokens()
        return True

    # ----------------------------------------------------------------------
    # OAuth flows
    # ----------------------------------------------------------------------

    def get_auth_url(self):
        """
        Multi-tenant authorization URL.
        NOTE: Do NOT use your tenant-specific authority here.
        """
        auth_url = self.app.get_authorization_request_url(
            scopes=config.SCOPES,
            redirect_uri=config.REDIRECT_URI,
            prompt="select_account",
        )
        return auth_url

    def acquire_token_by_authorization_code(self, code: str):
        """
        After Azure redirects back with ?code=...
        Exchange it for tokens and store per-tenant.
        """
        token_response = self.app.acquire_token_by_authorization_code(
            code=code,
            scopes=config.SCOPES,
            redirect_uri=config.REDIRECT_URI,
        )

        print("token_response:", token_response)

        if "id_token_claims" not in token_response:
            raise RuntimeError("No id_token_claims – cannot determine tenant.")

        tenant_id = token_response["id_token_claims"]["tid"]
        print(f"Authenticated tenant: {tenant_id}")

        self.save_tenant_tokens(tenant_id, token_response)
        return tenant_id, token_response

    # ----------------------------------------------------------------------
    # Refresh & token retrieval
    # ----------------------------------------------------------------------

    def get_valid_access_token(self, tenant_id):
        """
        Get a valid access token for a specific tenant.
        """
        if tenant_id not in self.tokens:
            return None

        t = self.tokens[tenant_id]

        # 1. Use existing access token if still valid
        if t.get("access_token"):
            try:
                acquired_at = datetime.fromisoformat(t.get("acquired_at"))
            except Exception:
                acquired_at = datetime.utcnow()

            expires_in = t.get("expires_in", 3600)
            if datetime.utcnow() < acquired_at + timedelta(seconds=expires_in - 300):
                return t["access_token"]

        # 2. Try refresh token
        if t.get("refresh_token"):
            token_response = self.app.acquire_token_by_refresh_token(
                refresh_token=t["refresh_token"],
                scopes=config.SCOPES,
            )

            if token_response and "access_token" in token_response:
                print("Refreshing tenant token:", tenant_id)
                self.save_tenant_tokens(tenant_id, token_response)
                return token_response["access_token"]

        return None

    # ----------------------------------------------------------------------

    def logout_tenant(self, tenant_id):
        """Remove tokens for a specific tenant"""
        if tenant_id in self.tokens:
            del self.tokens[tenant_id]
            self.save_all_tokens()
            return True
        return False

    def logout_all(self):
        """Remove everything"""
        self.tokens = {}
        try:
            if os.path.exists(config.TOKEN_FILE):
                os.remove(config.TOKEN_FILE)
            return True
        except Exception as e:
            print(f"Error removing token file: {e}")
            return False
