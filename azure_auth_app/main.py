from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from urllib.parse import urlencode, unquote
import uvicorn
import requests

from auth_handler import AzureAuthHandler
from config import config

app = FastAPI(title="Azure AD Authentication App", version="1.0.0")
app.add_middleware(SessionMiddleware, secret_key="some-random-string")
# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Initialize auth handler
auth_handler = AzureAuthHandler()
# auth_handler = AuthHandler()

favicon_path = "static/favicon.ico"


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(favicon_path)


@app.get("/")
async def root(request: Request):
    """Home page with login/logout options"""
    try:
        access_token = auth_handler.get_valid_access_token()
        print(f"access token from / {access_token}")
        print(f"tokens in auth_handler from / {auth_handler.tokens}")
    except Exception as e:
        print(f"Error getting access token: {e}")
        access_token = None

    if access_token:
        # Try to get user profile
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me", headers=headers
            )
            response.raise_for_status()
            profile = response.json()

            print(f"tokens in auth_handler from / {auth_handler.tokens}")

            return templates.TemplateResponse(
                "profile.html",
                {"request": request, "profile": profile, "tokens": auth_handler.tokens},
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
        return templates.TemplateResponse("login.html", {"request": request})


@app.get("/login")
async def login():
    """Redirect to Azure AD login page"""
    try:
        auth_url = auth_handler.get_auth_url()
        print(f"Redirecting from login to {auth_url}")
        return RedirectResponse(auth_url)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to generate auth URL: {str(e)}"
        )


@app.get("/callback")
async def callback(
    request: Request, code: str = None, error: str = None, error_description: str = None
):
    """Handle Azure AD redirect after authentication"""
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
        print(f"request is {request.json()}")

        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": "No authorization code received"},
        )

    try:
        # Exchange authorization code for tokens
        token_result = auth_handler.acquire_token_by_authorization_code(code)
        print("token result is", token_result)
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

        # Token acquisition successful - store tokens in session or database
        # For now, we'll just redirect to home page
        access_token = token_result.get("access_token")
        id_token = token_result.get("id_token")
        refresh_token = token_result.get("refresh_token")

        print(f"access_token: {access_token}")
        print(f"id_token: {id_token}")
        print(f"refresh_token: {refresh_token}")

        # Store tokens in session (you might want to use cookies or a proper session management)
        request.session["access_token"] = access_token
        request.session["id_token"] = id_token
        request.session["refresh_token"] = refresh_token

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
async def logout():
    """Clear local tokens and redirect to Azure AD logout if needed"""
    auth_handler.logout()

    # Optionally, redirect to Azure AD logout endpoint to clear session there too
    logout_url = (
        f"https://login.microsoftonline.com/{config.TENANT_ID}/oauth2/v2.0/logout"
    )
    params = {"post_logout_redirect_uri": "http://google.com/"}

    return RedirectResponse(f"{logout_url}?{urlencode(params)}")


@app.get("/api/tokens")
async def get_tokens():
    """API endpoint to get token information (truncated for security)"""
    tokens = auth_handler.tokens.copy()

    # Truncate tokens for security
    if "access_token" in tokens:
        tokens["access_token"] = tokens["access_token"][:20] + "..."
    if "refresh_token" in tokens:
        tokens["refresh_token"] = tokens["refresh_token"][:20] + "..."
    if "id_token" in tokens:
        tokens["id_token"] = tokens["id_token"][:20] + "..."

    return JSONResponse(content=tokens)


@app.get("/api/profile")
async def get_profile():
    """API endpoint to get user profile"""
    access_token = auth_handler.get_valid_access_token()
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get profile: {str(e)}")


if __name__ == "__main__":
    uvicorn.run(app, host=config.HOST, port=config.PORT)
