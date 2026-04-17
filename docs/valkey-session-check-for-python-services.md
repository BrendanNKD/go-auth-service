# Valkey Session Check for Python Services

This note is for services that receive the auth-service cookies and need to check the login session in Valkey before verifying the access-token JWT signature.

## Current Auth-Service Behavior

The auth service sets two cookies after login and refresh:

| Cookie | Default name | Stored in Valkey | Purpose |
| --- | --- | --- | --- |
| Access token | `access_token` | No | RS256 JWT used for request authorization. |
| Refresh token | `refresh_token` | Yes, as a SHA-256 hash | Opaque session token used to refresh and revoke sessions. |

Important: the `access_token` cookie is not stored in Valkey. If a Python service only receives `access_token`, there is no Valkey key it can check before signature verification with the current token format.

If the Python service receives both cookies, it may use the `refresh_token` cookie as a session-presence check before verifying the `access_token` JWT. This check does not authenticate the request by itself. The service must still verify the access-token signature, issuer, expiration, and not-before claims before trusting any JWT claims.

## Shared Configuration

Use the same Valkey settings as auth-service:

| Setting | Default | Notes |
| --- | --- | --- |
| `VALKEY_ADDR` | `localhost:6379` | Host and port. |
| `VALKEY_PASSWORD` | empty | Omit when empty. |
| `VALKEY_DB` | `0` | Database number. |
| `VALKEY_PREFIX` | `auth:refresh` | Prefix for all refresh/session keys. |
| `VALKEY_USE_TLS` | `false` | Use TLS in production when enabled. |
| `AUTH_ACCESS_COOKIE_NAME` | `access_token` | JWT cookie. |
| `AUTH_REFRESH_COOKIE_NAME` | `refresh_token` | Opaque refresh cookie. |
| `JWT_ISSUER` | `auth-service` | Expected JWT issuer. |

## Valkey Key Format

The auth service hashes the raw refresh token before using it as a Valkey key:

```text
token_hash = hex(sha256(raw_refresh_token))
```

Given `VALKEY_PREFIX=auth:refresh`, the keys are:

```text
auth:refresh:token:<token_hash>
auth:refresh:session:<session_id>
auth:refresh:revoked:<token_hash>
```

`auth:refresh:token:<token_hash>` stores JSON like:

```json
{
  "session_id": "session id",
  "username": "alice",
  "role": "user",
  "issued_at": "2026-04-13T10:00:00Z"
}
```

`auth:refresh:session:<session_id>` stores JSON like:

```json
{
  "current_token_hash": "sha256 hex refresh token hash",
  "username": "alice",
  "role": "user",
  "issued_at": "2026-04-13T10:00:00Z"
}
```

`auth:refresh:revoked:<token_hash>` stores the session id for a token that was rotated or revoked.

## Check Order

For a Python service that receives both cookies:

1. Read `refresh_token` from the request cookies.
2. Hash it with SHA-256 hex.
3. Reject if `auth:refresh:revoked:<token_hash>` exists.
4. Load `auth:refresh:token:<token_hash>`. Reject if missing or invalid JSON.
5. Load `auth:refresh:session:<session_id>`. Reject if missing or invalid JSON.
6. Reject if `session.current_token_hash != token_hash`.
7. Read `access_token` from the request cookies.
8. Verify the access-token JWT signature and claims with the auth-service JWKS endpoint.
9. Only after JWT verification should the Python service trust `username`, `role`, `iss`, `exp`, or any other JWT claim.

## Python Example

Install dependencies:

```bash
pip install redis pyjwt cryptography
```

Session-presence check:

```python
import hashlib
import json
import os
from dataclasses import dataclass

import redis


@dataclass(frozen=True)
class RefreshSession:
    session_id: str
    username: str
    role: str


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def build_valkey_client() -> redis.Redis:
    addr = os.getenv("VALKEY_ADDR", "localhost:6379")
    host, port = addr.rsplit(":", 1)

    return redis.Redis(
        host=host,
        port=int(port),
        db=int(os.getenv("VALKEY_DB", "0")),
        password=os.getenv("VALKEY_PASSWORD") or None,
        ssl=_env_bool("VALKEY_USE_TLS", False),
        decode_responses=True,
        socket_connect_timeout=0.5,
        socket_timeout=0.5,
    )


def refresh_token_hash(raw_refresh_token: str) -> str:
    return hashlib.sha256(raw_refresh_token.encode("utf-8")).hexdigest()


def check_refresh_session(
    valkey: redis.Redis,
    raw_refresh_token: str,
    prefix: str | None = None,
) -> RefreshSession | None:
    if not raw_refresh_token:
        return None

    key_prefix = prefix or os.getenv("VALKEY_PREFIX", "auth:refresh")
    token_hash = refresh_token_hash(raw_refresh_token)

    revoked_key = f"{key_prefix}:revoked:{token_hash}"
    token_key = f"{key_prefix}:token:{token_hash}"

    if valkey.exists(revoked_key):
        return None

    token_payload = valkey.get(token_key)
    if not token_payload:
        return None

    try:
        token_metadata = json.loads(token_payload)
    except json.JSONDecodeError:
        return None

    session_id = token_metadata.get("session_id")
    if not session_id:
        return None

    session_payload = valkey.get(f"{key_prefix}:session:{session_id}")
    if not session_payload:
        return None

    try:
        session = json.loads(session_payload)
    except json.JSONDecodeError:
        return None

    if session.get("current_token_hash") != token_hash:
        return None

    return RefreshSession(
        session_id=session_id,
        username=token_metadata.get("username", ""),
        role=token_metadata.get("role", ""),
    )
```

JWT verification after the Valkey check:

```python
import os

import jwt
from jwt import PyJWKClient


JWKS_URL = os.getenv(
    "AUTH_SERVICE_JWKS_URL",
    "http://auth-service:8080/api/v1/.well-known/jwks.json",
)
JWT_ISSUER = os.getenv("JWT_ISSUER", "auth-service")

_jwks_client = PyJWKClient(JWKS_URL)


def verify_access_token(access_token: str) -> dict:
    signing_key = _jwks_client.get_signing_key_from_jwt(access_token)
    return jwt.decode(
        access_token,
        signing_key.key,
        algorithms=["RS256"],
        issuer=JWT_ISSUER,
        options={"require": ["exp", "iat", "nbf", "iss"]},
    )


def authenticate_request(request) -> dict | None:
    refresh_cookie_name = os.getenv("AUTH_REFRESH_COOKIE_NAME", "refresh_token")
    access_cookie_name = os.getenv("AUTH_ACCESS_COOKIE_NAME", "access_token")

    valkey = build_valkey_client()
    session = check_refresh_session(
        valkey,
        request.cookies.get(refresh_cookie_name, ""),
    )
    if session is None:
        return None

    access_token = request.cookies.get(access_cookie_name, "")
    if not access_token:
        return None

    try:
        claims = verify_access_token(access_token)
    except jwt.PyJWTError:
        return None

    return claims
```

## Operational Notes

Do not log raw refresh tokens, access tokens, or full cookie headers. If logging is needed, log only a short prefix of the SHA-256 hash.

For protected endpoints, fail closed if Valkey is unavailable or the check times out. Use short Valkey timeouts so authentication failures do not hold request threads for long.

Do not treat the refresh-token Valkey check as a replacement for JWT verification. The current access token contains `username`, `role`, `iss`, `iat`, `nbf`, and `exp`, but it does not contain a `session_id` or `jti`. If another service must check the access token directly against Valkey, the auth service needs a token-format change to add a session id or JWT id and store that mapping in Valkey.
