from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from urllib.parse import urlencode
import uvicorn
import requests
import json

from auth_handler import AzureAuthHandler
from config import config

app = FastAPI(title="Azure AD Authentication App", version="1.0.0")

# NOTE: use a strong secret key in production
app.add_middleware(SessionMiddleware, secret_key="some-random-string")

# Static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Initialize auth handler (multi-tenant)
auth_handler = AzureAuthHandler()

favicon_path = "static/favicon.ico"


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(favicon_path)


@app.get("/")
async def root(request: Request):
    """
    Home page.
    - If a tenant is in session and has a valid token, show profile.
    - Otherwise, show login page.
    """
    tenant_id = request.session.get("tenant_id")

    if not tenant_id:
        # No tenant selected / authenticated yet
        return templates.TemplateResponse("login.html", {"request": request})

    try:
        access_token = auth_handler.get_valid_access_token(tenant_id)
        print(f"[/] tenant_id={tenant_id}, access_token_present={bool(access_token)}")
        print(f"[/] auth_handler tokens: {auth_handler.tokens}")
    except Exception as e:
        print(f"Error getting access token for tenant {tenant_id}: {e}")
        access_token = None

    if access_token:
        # Try to get user profile from the customer's tenant
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me", headers=headers
            )
            response.raise_for_status()
            profile = json.loads(response.content)

            return templates.TemplateResponse(
                "profile.html",
                {
                    "request": request,
                    "profile": profile,
                    "tenant_id": tenant_id,
                    "tokens": auth_handler.tokens.get(tenant_id, {}),
                    "known_tenants": list(auth_handler.tokens.keys()),
                },
            )
        except Exception as e:
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": f"Failed to get profile from /: {str(e)}",
                },
            )
    else:
        # No valid token for this tenant; force re-login
        return templates.TemplateResponse("login.html", {"request": request})


@app.get("/login")
async def login():
    """
    Redirect to Azure AD login page (multi-tenant).
    The tenant will be determined at callback time from id_token_claims['tid'].
    """
    try:
        auth_url = auth_handler.get_auth_url()
        print(f"Redirecting from /login to {auth_url}")
        return RedirectResponse(auth_url)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to generate auth URL: {str(e)}"
        )


@app.get("/close")
async def close(request: Request):
    """Close the authentication window"""
    return templates.TemplateResponse(
        "close.html",
        {"request": request, "error": "Authentication failed. Please try again."},
    )


@app.get("/callback")
async def callback(
    request: Request, code: str = None, error: str = None, error_description: str = None
):
    """
    Handle Azure AD redirect after authentication.
    In the multi-tenant handler, acquire_token_by_authorization_code returns:
        tenant_id, token_response
    """
    print(
        f"Callback received: code={code}, error={error}, error_description={error_description}"
    )

    if error:
        print(f"error is {error}")
        print("Erroring in /callback")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": f"{error}: {error_description}"}
        )

    if not code:
        print("No code received")
        try:
            json_req = await request.json()
            print(f"request json is {json_req}")
        except Exception as e:
            print(f"Error parsing JSON request: {e}")

        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": "No authorization code received"},
        )

    try:
        # NEW: auth_handler now returns (tenant_id, token_response)
        tenant_id, token_result = auth_handler.acquire_token_by_authorization_code(code)
        print("token result is", token_result)
        print("authenticated tenant_id:", tenant_id)

        # Store tenant_id in session so subsequent requests know which tenant to use
        request.session["tenant_id"] = tenant_id

        if "error" in token_result:
            error_msg = token_result.get(
                "error_description", "Unknown error during token acquisition"
            )
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": f"Failed to exchange authorization code for tokens: {error_msg}",
                },
            )

        # If we reach here, tokens for this tenant are already saved in the handler
        return RedirectResponse("/")
    except Exception as e:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": f"Unexpected error during authentication: {str(e)}",
            },
        )


@app.get("/logout")
async def logout(request: Request):
    """
    Clear local tokens for the current tenant and redirect to Azure AD logout.
    This only affects the session's tenant_id, not all tenants in the token store.
    """
    tenant_id = request.session.get("tenant_id")

    if tenant_id:
        auth_handler.logout_tenant(tenant_id)
    else:
        # No tenant in session; you can optionally clear all
        auth_handler.logout_all()

    # Clear session
    request.session.pop("tenant_id", None)

    # Multi-tenant logout endpoint
    logout_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/logout"
    params = {"post_logout_redirect_uri": config.POST_LOGOUT_REDIRECT_URI}

    return RedirectResponse(f"{logout_url}?{urlencode(params)}")


@app.get("/api/tokens")
async def get_tokens(request: Request):
    """
    API endpoint to get token information for the current tenant (truncated).
    """
    tenant_id = request.session.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="No tenant selected in session")

    tenant_tokens = auth_handler.tokens.get(tenant_id, {}).copy()

    # Truncate tokens for security
    if "access_token" in tenant_tokens:
        tenant_tokens["access_token"] = tenant_tokens["access_token"][:20] + "..."
    if "refresh_token" in tenant_tokens:
        tenant_tokens["refresh_token"] = tenant_tokens["refresh_token"][:20] + "..."
    if "id_token" in tenant_tokens:
        tenant_tokens["id_token"] = tenant_tokens["id_token"][:20] + "..."

    return JSONResponse(
        content={
            "tenant_id": tenant_id,
            "tokens": tenant_tokens,
            "known_tenants": list(auth_handler.tokens.keys()),
        }
    )


@app.get("/api/profile")
async def get_profile(request: Request):
    """
    API endpoint to get user profile for the current tenant.
    """
    tenant_id = request.session.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="No tenant selected in session")

    access_token = auth_handler.get_valid_access_token(tenant_id)
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated for this tenant")

    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get profile: {str(e)}")


@app.get("/api/debug/capabilities")
async def delegated_capability_check(request: Request):
    """
    Check what Graph capabilities the SaaS app has in the CURRENT customer tenant
    using delegated access.
    """

    tenant_id = request.session.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="No tenant selected in session")

    # Get a delegated user access token for this tenant
    access_token = auth_handler.get_valid_access_token(tenant_id)
    if not access_token:
        raise HTTPException(status_code=401, detail="No delegated token available")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "ConsistencyLevel": "eventual",
    }

    # Test endpoints the SaaS app may depend on
    endpoints = {
        "me": "https://graph.microsoft.com/v1.0/me",
        "users_list": "https://graph.microsoft.com/v1.0/users?$top=1",
        "sp_list": "https://graph.microsoft.com/v1.0/servicePrincipals?$top=1",
        "oauth2_grants": "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=1",
        "app_role_assignments": "https://graph.microsoft.com/v1.0/me/appRoleAssignments",
        "my_permissions": "https://graph.microsoft.com/v1.0/me/checkMemberGroups",
    }

    results = {}

    for name, url in endpoints.items():
        try:
            r = requests.get(url, headers=headers)
            try:
                payload = r.json()
            except:
                payload = None

            results[name] = {
                "status": r.status_code,
                "ok": r.ok,
                "allowed": r.status_code in (200, 201),
                "forbidden": r.status_code == 403,
                "unauthorized": r.status_code == 401,
                "payload": payload,
            }
        except Exception as e:
            results[name] = {
                "status": "error",
                "ok": False,
                "error": str(e),
            }

    return {
        "tenant_id": tenant_id,
        "delegated_capabilities": results,
        "message": "Checked delegated access only — no app-only tokens used.",
    }


if __name__ == "__main__":
    uvicorn.run(app, host=config.HOST, port=config.PORT)
