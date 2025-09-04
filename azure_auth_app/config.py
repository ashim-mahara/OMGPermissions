import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Azure AD Configuration
    CLIENT_ID = os.getenv("CLIENT_ID", "your-client-id-here")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET", "your-client-secret-here")
    TENANT_ID = os.getenv("TENANT_ID", "your-tenant-id-here")
    REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8000/callback")

    # Scopes for Microsoft Graph API
    SCOPES = ["User.Read"]

    # Authority URL
    AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

    # Token storage
    TOKEN_FILE = "tokens.json"

    # Server configuration
    HOST = "localhost"
    PORT = 8000


config = Config()
