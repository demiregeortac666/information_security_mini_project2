"""
auth.py - Everything authentication-related lives here.

  * generate_token / decode_token  ........ JWT helpers (Task 2)
  * token_required decorator  ............. validates JWTs on protected routes (Task 3)
  * role_required decorator  .............. enforces RBAC (Task 4)
  * TOKEN_BLACKLIST + revoke_token  ....... token revocation (Task 5)
  * log_security_event  ................... defensive logging (Task 6)
"""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, request, jsonify, g


# ----------------------------------------------------------------------
# Task 5 - Token Blacklist (in-memory)
# ----------------------------------------------------------------------
# We add the token's `jti` (JWT ID) to this set on /logout. Any subsequent
# request carrying a token whose jti is in this set is rejected, even if
# the JWT itself is otherwise valid and unexpired.
TOKEN_BLACKLIST: set = set()


def revoke_token(jti: str) -> None:
    if jti:
        TOKEN_BLACKLIST.add(jti)


def is_token_revoked(jti: str) -> bool:
    return jti in TOKEN_BLACKLIST


# ----------------------------------------------------------------------
# Task 6 - Security Logger
# ----------------------------------------------------------------------
_security_logger = logging.getLogger("secureshield.security")
if not _security_logger.handlers:
    _security_logger.setLevel(logging.WARNING)
    _file_handler = logging.FileHandler("security.log")
    _file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )
    _security_logger.addHandler(_file_handler)
    _security_logger.propagate = False


def log_security_event(event: str, username: str, path: str,
                       method: str, status: int, extra: str = "") -> None:
    """Write a single line to security.log describing an auth/authz failure."""
    ip = request.remote_addr if request else "-"
    msg = (f"[{event}] status={status} user={username} ip={ip} "
           f"method={method} path={path}")
    if extra:
        msg += f" details={extra}"
    _security_logger.warning(msg)


# ----------------------------------------------------------------------
# Task 2 - JWT helpers
# ----------------------------------------------------------------------
def generate_token(username: str, role: str) -> str:
    """Mint a signed JWT carrying username (sub) + role."""
    secret = current_app.config["SECRET_KEY"]
    hours = current_app.config["JWT_EXPIRY_HOURS"]
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,                      # subject = username
        "role": role,                         # used for RBAC
        "jti": str(uuid.uuid4()),             # unique id, used for revocation
        "iat": now,                           # issued at
        "exp": now + timedelta(hours=hours),  # expires at
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token: str) -> dict:
    """Decode + verify a JWT. Raises jwt.* exceptions on failure."""
    secret = current_app.config["SECRET_KEY"]
    return jwt.decode(token, secret, algorithms=["HS256"])


# ----------------------------------------------------------------------
# Task 3 - @token_required decorator
# ----------------------------------------------------------------------
def token_required(f):
    """
    Reject the request unless the Authorization header carries a valid,
    non-expired, non-revoked JWT signed with our secret.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            log_security_event("MISSING_TOKEN", "-",
                               request.path, request.method, 401)
            return jsonify({"error": "Authorization header missing or malformed"}), 401

        token = auth_header.split(" ", 1)[1].strip()

        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            log_security_event("EXPIRED_TOKEN", "-",
                               request.path, request.method, 401)
            return jsonify({"error": "token has expired"}), 401
        except jwt.InvalidTokenError as exc:
            # Catches tampered signatures, malformed tokens, wrong algo, etc.
            log_security_event("INVALID_TOKEN", "-",
                               request.path, request.method, 401,
                               extra=str(exc))
            return jsonify({"error": "invalid token signature or payload"}), 401

        if is_token_revoked(payload.get("jti")):
            log_security_event("REVOKED_TOKEN", payload.get("sub", "-"),
                               request.path, request.method, 401)
            return jsonify({"error": "token has been revoked"}), 401

        # Stash the JWT payload on Flask's request-scoped `g` for later handlers
        g.current_user = payload
        return f(*args, **kwargs)
    return wrapper


# ----------------------------------------------------------------------
# Task 4 - @role_required decorator
# ----------------------------------------------------------------------
def role_required(*allowed_roles):
    """
    Reject the request with 403 Forbidden unless the JWT's `role` claim is in
    `allowed_roles`. Must be applied AFTER @token_required.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                log_security_event("NO_USER_CONTEXT", "-",
                                   request.path, request.method, 401)
                return jsonify({"error": "authentication required"}), 401

            if user.get("role") not in allowed_roles:
                # Task 6 - this is the canonical 403 case requested in the spec
                log_security_event(
                    "FORBIDDEN_ACCESS",
                    user.get("sub", "-"),
                    request.path,
                    request.method,
                    403,
                    extra=f"role={user.get('role')}, required={list(allowed_roles)}",
                )
                return jsonify({"error": "insufficient privileges"}), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator
