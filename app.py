
import os
import secrets
import time
from datetime import timedelta
from functools import wraps
from urllib.parse import urlencode

import jwt
import requests

from flask import (
    Flask,
    redirect,
    url_for,
    session,
    render_template_string,
    abort,
    request,
)
from jwt import PyJWKClient
from dotenv import load_dotenv

# ==================================================
# 1. CONFIGURATION
# ==================================================

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Session security: require reauthentication after five minutes.
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)
app.config["SESSION_REFRESH_EACH_REQUEST"] = False
# Local HTTP lab only. Set True when deploying behind HTTPS.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

if not app.secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY is missing from .env"
    )

KEYCLOAK_URL = os.getenv(
    "KEYCLOAK_URL",
    "http://localhost:8080"
).rstrip("/")

REALM = os.getenv("KEYCLOAK_REALM", "Contoso")

CLIENT_ID = os.getenv(
    "KEYCLOAK_CLIENT_ID",
    "finance-portal"
)

CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")

if not CLIENT_SECRET:
    raise RuntimeError(
        "KEYCLOAK_CLIENT_SECRET is missing from .env"
    )

ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"

AUTHORIZATION_ENDPOINT = (
    f"{ISSUER}/protocol/openid-connect/auth"
)

TOKEN_ENDPOINT = (
    f"{ISSUER}/protocol/openid-connect/token"
)

LOGOUT_ENDPOINT = (
    f"{ISSUER}/protocol/openid-connect/logout"
)

JWKS_URL = (
    f"{ISSUER}/protocol/openid-connect/certs"
)

# IMPORTANT:
# Use localhost consistently in the browser and
# redirect URI. Do not mix localhost and 127.0.0.1.

REDIRECT_URI = "http://localhost:3000/callback"

REQUIRED_ROLE = "view-reports"


# ==================================================
# 2. KEYCLOAK SIGNING KEY VALIDATION
# ==================================================

jwks_client = PyJWKClient(JWKS_URL)


# ==================================================
# 2A. LOCAL SESSION / TOKEN EXPIRY CHECK
# ==================================================

@app.before_request
def validate_login_session():
    """Enforce Flask's local session lifetime and the
    expiration time of the verified Keycloak ID token.

    This does NOT instantly revoke a session when a user
    is disabled in Keycloak. It limits the lifetime of
    the application's local login session.
    """
    # Routes that must remain reachable without login.
    if request.endpoint in ("home", "login", "callback", "static", "logout"):
        return None

    claims = session.get("id_token_claims")
    if not claims:
        return None

    token_expiry = claims.get("exp")
    if not token_expiry or time.time() >= token_expiry:
        session.clear()
        return redirect(url_for("login"))

    return None


def verify_id_token(id_token, expected_nonce):
    """
    Verify Keycloak's signed ID token and validate
    its issuer, audience, expiry and nonce.
    """

    signing_key = jwks_client.get_signing_key_from_jwt(
        id_token
    )

    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=ISSUER,
        options={
            "require": [
                "exp",
                "iat",
                "iss",
                "sub",
                "aud",
            ]
        },
    )

    # Prevent replay or substitution of an ID token
    # from another authentication request.
    if claims.get("nonce") != expected_nonce:
        raise ValueError("OIDC nonce validation failed")

    return claims


# ==================================================
# 3. AUTHENTICATION DECORATOR
# ==================================================

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("user"):
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


# ==================================================
# 4. ROLE-BASED ACCESS CONTROL
# ==================================================

def role_required(role_name):
    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if not session.get("user"):
                return redirect(url_for("login"))

            user_roles = session.get(
                "client_roles", []
            )

            if role_name not in user_roles:
                return (
                    render_template_string(
                        """
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>Access Denied</title>
                        </head>
                        <body>
                            <h1>403 - Access Denied</h1>

                            <p>
                                You are authenticated,
                                but you do not have
                                permission to view
                                this resource.
                            </p>

                            <p>
                                Required role:
                                <strong>{{ role }}</strong>
                            </p>

                            <a href="/">Back to home</a>
                        </body>
                        </html>
                        """,
                        role=role_name,
                    ),
                    403,
                )

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ==================================================
# 5. HOME PAGE
# ==================================================

@app.route("/")
def home():

    user = session.get("user")

    if not user:
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Contoso Finance Portal</title>
        </head>
        <body>
            <h1>Contoso Finance Portal</h1>

            <p>
                Please sign in to continue.
            </p>

            <a href="/login">
                Login with Keycloak
            </a>
        </body>
        </html>
        """

    return render_template_string(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Contoso Finance Portal</title>
        </head>
        <body>
            <h1>Contoso Finance Portal</h1>

            <h3>
                Welcome,
                {{ user.get(
                    'name',
                    user.get('preferred_username', 'User')
                ) }}
            </h3>

            <p>
                Username:
                {{ user.get('preferred_username', 'Unknown') }}
            </p>

            <p>
                Email:
                {{ user.get('email', 'Not available') }}
            </p>

            <h3>Your application roles</h3>

            {% if roles %}
                <ul>
                {% for role in roles %}
                    <li>{{ role }}</li>
                {% endfor %}
                </ul>
            {% else %}
                <p>
                    No finance-portal client roles
                    were found in your ID token.
                </p>
            {% endif %}

            <hr>

            <p>
                <a href="/reports">
                    View Finance Reports
                </a>
            </p>

            <p>
                <a href="/logout">
                    Logout
                </a>
            </p>
        </body>
        </html>
        """,
        user=user,
        roles=roles_for_client(
            session.get("id_token_claims", {})
        ),
    )


# ==================================================
# 6. EXTRACT CLIENT ROLES
# ==================================================

def roles_for_client(claims):

    resource_access = claims.get(
        "resource_access", {}
    )

    client_access = resource_access.get(
        CLIENT_ID, {}
    )

    return client_access.get("roles", [])


# ==================================================
# 7. START KEYCLOAK LOGIN
# ==================================================

@app.route("/login")
def login():

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    session["oidc_state"] = state
    session["oidc_nonce"] = nonce

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "nonce": nonce,
    }

    authorization_url = (
        AUTHORIZATION_ENDPOINT
        + "?"
        + urlencode(params)
    )

    return redirect(authorization_url)


# ==================================================
# 8. KEYCLOAK CALLBACK
# ==================================================

@app.route("/callback")
def callback():

    # ----------------------------------------------
    # A. Check for Keycloak errors
    # ----------------------------------------------

    error = request_value("error")

    if error:
        description = request_value(
            "error_description"
        )

        return (
            f"Keycloak login failed: "
            f"{error}: {description}",
            400,
        )

    # ----------------------------------------------
    # B. Validate OIDC state
    # ----------------------------------------------

    returned_state = request_value("state")
    expected_state = session.pop(
        "oidc_state", None
    )

    if (
        not expected_state
        or not returned_state
        or returned_state != expected_state
    ):
        return (
            "Invalid or missing OIDC state. "
            "Please start login again.",
            400,
        )

    # ----------------------------------------------
    # C. Retrieve authorization code
    # ----------------------------------------------

    code = request_value("code")

    if not code:
        return "Authorization code is missing.", 400

    expected_nonce = session.pop(
        "oidc_nonce", None
    )

    if not expected_nonce:
        return (
            "OIDC nonce is missing. "
            "Please start login again.",
            400,
        )

    # ----------------------------------------------
    # D. Exchange code for tokens
    # ----------------------------------------------

    try:
        response = requests.post(
            TOKEN_ENDPOINT,
            auth=(CLIENT_ID, CLIENT_SECRET),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
            timeout=15,
        )

        response.raise_for_status()

        token_data = response.json()

    except requests.RequestException as exc:
        app.logger.exception(
            "Keycloak token exchange failed"
        )

        return (
            "Could not exchange authorization code "
            "with Keycloak. Check the Flask terminal "
            "for details.",
            502,
        )

    id_token = token_data.get("id_token")

    if not id_token:
        return (
            "Keycloak did not return an ID token. "
            "Check the client's OpenID Connect "
            "configuration.",
            400,
        )

    # ----------------------------------------------
    # E. Verify the ID token
    # ----------------------------------------------

    try:
        claims = verify_id_token(
            id_token,
            expected_nonce,
        )

    except Exception:
        app.logger.exception(
            "ID token verification failed"
        )

        return (
            "ID token verification failed. "
            "Check the Flask terminal for details.",
            401,
        )

    # ----------------------------------------------
    # F. Store verified identity and roles
    # ----------------------------------------------

    user = {
        "sub": claims.get("sub"),
        "preferred_username": claims.get(
            "preferred_username"
        ),
        "name": claims.get("name"),
        "email": claims.get("email"),
    }

    client_roles = roles_for_client(claims)

    session.clear()
    session.permanent = True

    session["user"] = user
    session["client_roles"] = client_roles
    session["id_token"] = id_token
    session["id_token_claims"] = claims

    return redirect(url_for("home"))


# ==================================================
# 9. CALLBACK QUERY HELPER
# ==================================================


def request_value(name):
    return request.args.get(name, "")


# ==================================================
# 10. PROTECTED FINANCE REPORTS
# ==================================================

@app.route("/reports")
@login_required
@role_required(REQUIRED_ROLE)
def reports():

    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Finance Reports</title>
    </head>
    <body>
        <h1>Finance Reports</h1>

        <p>
            Access granted!
        </p>

        <p>
            Your verified Keycloak ID token
            contains the view-reports client role.
        </p>

        <p>
            This is sample data for your IAM lab.
        </p>

        <a href="/">Back to home</a>
    </body>
    </html>
    """


# ==================================================
# 11. LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    id_token = session.get("id_token")

    # Clear the local application session.
    session.clear()

    params = {
        "client_id": CLIENT_ID,
        "post_logout_redirect_uri": (
            "http://localhost:3000/"
        ),
    }

    if id_token:
        params["id_token_hint"] = id_token

    logout_url = (
        LOGOUT_ENDPOINT
        + "?"
        + urlencode(params)
    )

    return redirect(logout_url)


# ==================================================
# 12. RUN APPLICATION
# ==================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=3000,
        debug=True,
    )