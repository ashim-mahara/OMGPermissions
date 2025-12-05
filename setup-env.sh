#!/bin/bash
echo "Configure omgpermissions environment variables:"
# Prompt for Azure AD application (for detection pipeline)
read -p "Azure Tenant ID (for Graph API app): " AZ_TENANT_ID
read -p "Azure Client ID (for Graph API app): " AZ_CLIENT_ID
read -s -p "Azure Client Secret (for Graph API app): " AZ_CLIENT_SECRET; echo

# # Prompt for Azure AD app (for user authentication, FastAPI)
# read -p "Azure Auth App Client ID (for interactive login): " CLIENT_ID
# read -s -p "Azure Auth App Client Secret (for interactive login): " CLIENT_SECRET; echo
# read -p "Azure Auth App Tenant ID (if single-tenant, else leave blank for 'organizations'): " TENANT_ID
# if [[ -z "$TENANT_ID" ]]; then
#     TENANT_ID="organizations"
# fi
# read -p "Auth App Redirect URI [http://localhost:8000/callback]: " REDIRECT_URI
# if [[ -z "$REDIRECT_URI" ]]; then
#     REDIRECT_URI="http://localhost:8000/callback"
# fi

# Prompt for Slack (optional)
read -p "Slack Webhook URL (optional, press Enter to skip): " SLACK_WEBHOOK_URL

# Write variables to .env file
ENV_FILE=".env"
echo "AZ_TENANT_ID=$AZ_TENANT_ID"    > $ENV_FILE
echo "AZ_CLIENT_ID=$AZ_CLIENT_ID"   >> $ENV_FILE
echo "AZ_CLIENT_SECRET=$AZ_CLIENT_SECRET" >> $ENV_FILE
echo "CLIENT_ID=$CLIENT_ID"         >> $ENV_FILE
echo "CLIENT_SECRET=$CLIENT_SECRET" >> $ENV_FILE
echo "TENANT_ID=$TENANT_ID"         >> $ENV_FILE
echo "REDIRECT_URI=$REDIRECT_URI"   >> $ENV_FILE
if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
    echo "SLACK_WEBHOOK_URL=$SLACK_WEBHOOK_URL" >> $ENV_FILE
fi

echo "Environment variables saved to $ENV_FILE"
