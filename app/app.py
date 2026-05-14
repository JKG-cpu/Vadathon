import os
import secrets
import requests
from flask import Flask, render_template, redirect, url_for, session, request, abort
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

App = Flask(__name__)
App.secret_key = os.getenv("SECRET_KEY", "fallback-dev-secret-change-me")

# ── Hack Club Auth Config ─────────────────────────────────────────────────────
HC_CLIENT_ID     = os.getenv("HACKCLUB_CLIENT_ID")
HC_CLIENT_SECRET = os.getenv("HACKCLUB_CLIENT_SECRET")
HC_AUTHORIZE_URL = "https://auth.hackclub.com/oauth/authorize"
HC_TOKEN_URL     = "https://auth.hackclub.com/oauth/token"
HC_ME_URL        = "https://auth.hackclub.com/api/v1/me"
HC_SCOPES        = "openid profile email"

# ── Pages ─────────────────────────────────────────────────────────────────────
@App.route("/")
def home():
    user = session.get("user")
    return render_template("index.html", user=user)

@App.route("/login")
def login():
    return render_template("login.html")

# ── Hack Club OAuth Flow ──────────────────────────────────────────────────────

@App.route("/login/hackclub")
def login_hackclub():
    # Generate a random state token to prevent CSRF attacks
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    # Build the redirect URL to Hack Club's authorize page
    callback_url = url_for("callback", _external=True)
    auth_url = (
        f"{HC_AUTHORIZE_URL}"
        f"?client_id={HC_CLIENT_ID}"
        f"&redirect_uri={callback_url}"
        f"&response_type=code"
        f"&scope={HC_SCOPES}"
        f"&state={state}"
    )
    return redirect(auth_url)


@App.route("/callback")
def callback():
    # ── Step 1: Verify the state to prevent CSRF ──────────────────────────────
    returned_state = request.args.get("state")
    saved_state    = session.pop("oauth_state", None)

    if not saved_state or returned_state != saved_state:
        abort(400, "OAuth state mismatch — possible CSRF attack.")

    # ── Step 2: Check for errors from Hack Club ───────────────────────────────
    error = request.args.get("error")
    if error:
        return f"Hack Club Auth error: {error}", 400

    # ── Step 3: Exchange the code for an access token ─────────────────────────
    code         = request.args.get("code")
    callback_url = url_for("callback", _external=True)

    token_response = requests.post(
        HC_TOKEN_URL,
        json={
            "client_id":     HC_CLIENT_ID,
            "client_secret": HC_CLIENT_SECRET,
            "redirect_uri":  callback_url,
            "code":          code,
            "grant_type":    "authorization_code",
        },
    )

    if not token_response.ok:
        return f"Failed to get token: {token_response.text}", 400

    token_data   = token_response.json()
    access_token = token_data.get("access_token")

    # ── Step 4: Fetch user info from /api/v1/me ───────────────────────────────
    me_response = requests.get(
        HC_ME_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )

    if not me_response.ok:
        return f"Failed to get user info: {me_response.text}", 400

    user_info = me_response.json()
    session["user"] = user_info

    return redirect(url_for("home"))


@App.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))