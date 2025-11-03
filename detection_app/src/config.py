import os
import dotenv

dotenv.load_dotenv()

TENANT_ID = os.environ["AZ_TENANT_ID"]
CLIENT_ID = os.environ["AZ_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZ_CLIENT_SECRET"]

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
OUTPUT_DIR = "./outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)
