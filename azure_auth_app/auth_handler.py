import json
import os
from datetime import datetime, timedelta
import msal
from config import config


class AzureAuthHandler:
    def __init__(self):
        self.tokens = {}
        self.load_tokens()

        # Create a confidential client application
        self.app = msal.ConfidentialClientApplication(
            config.CLIENT_ID,
            authority=config.AUTHORITY,
            client_credential=config.CLIENT_SECRET,
            token_cache=self._build_msal_cache(),
        )

    def _build_msal_cache(self):
        """Build MSAL cache from stored tokens"""
        cache = msal.SerializableTokenCache()
        cache_data = {}
        if self.tokens.get("access_token"):
            # Calculate expiration time
            acquired_at = datetime.fromisoformat(
                self.tokens.get("acquired_at", datetime.now().isoformat())
            )
            expires_in = self.tokens.get("expires_in", 3600)
            expires_on = (acquired_at + timedelta(seconds=expires_in)).timestamp()

            # Build cache data structure

            cache_data["AccessToken"] = {
                f"https://graph.microsoft.com/{config.SCOPES[0]}": {
                    "secret": self.tokens["access_token"],
                    "expires_on": expires_on,
                    "refresh_on": expires_on
                    - 300,  # Refresh 5 minutes before expiration
                }
            }

        if self.tokens.get("refresh_token"):
            cache_data["RefreshToken"] = {
                "https://login.microsoftonline.com/common/oauth2/v2.0": {
                    "secret": self.tokens["refresh_token"]
                }
            }

        cache.deserialize(json.dumps(cache_data))

        return cache

    def load_tokens(self):
        """Load tokens from file if exists"""
        try:
            if os.path.exists(config.TOKEN_FILE):
                with open(config.TOKEN_FILE, "r") as f:
                    self.tokens = json.load(f)
        except Exception as e:
            print(f"Error loading tokens: {e}")
            self.tokens = {}

    def save_tokens(self, token_response):
        """Save tokens from MSAL response"""
        if token_response and "access_token" in token_response:
            self.tokens = {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token"),
                "id_token": token_response.get("id_token"),
                "expires_in": token_response.get("expires_in"),
                "token_type": token_response.get("token_type"),
                "scope": token_response.get("scope"),
                "acquired_at": datetime.now().isoformat(),
            }
            print(f"tokens to be saved: {self.tokens}")
            try:
                with open(config.TOKEN_FILE, "w") as f:
                    json.dump(self.tokens, f, indent=2)
                return True
            except Exception as e:
                print(f"Error saving tokens: {e}")

        return False

    def get_auth_url(self):
        """Generate Azure AD authorization URL"""
        auth_url = self.app.get_authorization_request_url(
            scopes=config.SCOPES, redirect_uri=config.REDIRECT_URI
        )
        return auth_url

    def acquire_token_by_authorization_code(self, code):
        """Exchange authorization code for tokens"""
        token_response = self.app.acquire_token_by_authorization_code(
            code=code, scopes=config.SCOPES, redirect_uri=config.REDIRECT_URI
        )
        print(
            f"token_response from acquire_token_by_authorization_code is {token_response}"
        )
        self.save_tokens(token_response)
        return token_response

    def acquire_token_silent(self):
        """Acquire token silently using refresh token if available"""
        accounts = self.app.get_accounts()
        if accounts:
            token_response = self.app.acquire_token_silent(
                scopes=config.SCOPES, account=accounts[0]
            )

            if token_response and "access_token" in token_response:
                self.save_tokens(token_response)
                return token_response.get("access_token")

        return None

    def get_valid_access_token(self):
        """Get valid access token, refresh if necessary"""
        # First try to get token silently
        token = self.acquire_token_silent()
        if token:
            return token

        # If silent acquisition fails, try using refresh token
        if self.tokens.get("refresh_token"):
            token_response = self.app.acquire_token_by_refresh_token(
                refresh_token=self.tokens["refresh_token"], scopes=config.SCOPES
            )

            if token_response and "access_token" in token_response:
                self.save_tokens(token_response)

                print(f"token response from get_valid_access_token {token_response}")
                return token_response.get("access_token")

        return None

    def logout(self):
        """Clear stored tokens (local logout)"""
        self.tokens = {}
        try:
            if os.path.exists(config.TOKEN_FILE):
                os.remove(config.TOKEN_FILE)
            return True
        except Exception as e:
            print(f"Error removing token file: {e}")
            return False
