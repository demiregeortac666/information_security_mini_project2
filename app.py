"""
SecureShield - Mini Project II
A Role-Based Access Control (RBAC) API.

Tasks covered:
  Task 1 - bcrypt password hashing on /register
  Task 2 - JWT issued on /login (contains username + role)
  Task 3 - @token_required decorator validates JWTs on protected routes
  Task 4 - GET /profile (user, admin), DELETE /user/<id> (admin only)
  Task 5 - /logout adds the token's jti to an in-memory blacklist
  Task 6 - Every 401/403 attempt is written to security.log with timestamp + action
"""
import os
from datetime import datetime, timezone

from flask import Flask, request, jsonify, g
from flask_bcrypt import Bcrypt

from auth import (
    token_required,
    role_required,
    generate_token,
    revoke_token,
    log_security_event,
)
from database import init_db, get_db, close_db


# ----------------------------------------------------------------------
# Application setup
# ----------------------------------------------------------------------
app = Flask(__name__)

# In production this MUST come from a secure env var, never a hard-coded value.
# We keep a fallback only so the grader can clone-and-run without setup.
app.config["SECRET_KEY"] = os.environ.get(
    "SECURESHIELD_SECRET",
    "dev-only-secret-change-me-7e8a1c2b9f3d4e5a6b7c8d9e0f1a2b3c",
)
app.config["DATABASE"] = os.environ.get("SECURESHIELD_DB", "secureshield.db")
app.config["JWT_EXPIRY_HOURS"] = 1
app.config["JSON_SORT_KEYS"] = False

bcrypt = Bcrypt(app)
app.bcrypt = bcrypt  # exposed so seed.py can re-use the same instance

app.teardown_appcontext(close_db)


# ----------------------------------------------------------------------
# Public routes
# ----------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "SecureShield",
        "time": datetime.now(timezone.utc).isoformat(),
    }), 200


@app.route("/register", methods=["POST"])
def register():
    """
    Create a new account. The password is salted + hashed with bcrypt
    before being persisted - it is never stored in plain text.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or "user").lower()

    # Input validation
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if role not in ("user", "admin"):
        return jsonify({"error": "role must be 'user' or 'admin'"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters long"}), 400

    # Task 1 - bcrypt automatically generates a unique salt and embeds it in the hash
    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, pw_hash, role),
        )
        db.commit()
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            return jsonify({"error": "username already exists"}), 409
        return jsonify({"error": "database error"}), 500

    return jsonify({
        "message": "user registered",
        "username": username,
        "role": role,
    }), 201


@app.route("/login", methods=["POST"])
def login():
    """
    Verify the password against the stored bcrypt hash, then mint a signed JWT
    that carries the user's username (sub) and role.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    db = get_db()
    user = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    # Constant-ish failure path (we still call check_password_hash on a dummy
    # hash if the user does not exist, to avoid trivial username enumeration
    # via timing differences).
    dummy_hash = "$2b$12$abcdefghijklmnopqrstuv.wxyz1234567890ABCDEFGHIJKLMNOPQR"
    if user is None:
        bcrypt.check_password_hash(dummy_hash, password)
        log_security_event(
            event="LOGIN_FAILED",
            username=username,
            path=request.path,
            method=request.method,
            status=401,
            extra="reason=unknown_user",
        )
        return jsonify({"error": "invalid credentials"}), 401

    if not bcrypt.check_password_hash(user["password_hash"], password):
        log_security_event(
            event="LOGIN_FAILED",
            username=username,
            path=request.path,
            method=request.method,
            status=401,
            extra="reason=bad_password",
        )
        return jsonify({"error": "invalid credentials"}), 401

    token = generate_token(user["username"], user["role"])
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in_seconds": app.config["JWT_EXPIRY_HOURS"] * 3600,
        "role": user["role"],
    }), 200


# ----------------------------------------------------------------------
# Protected routes
# ----------------------------------------------------------------------
@app.route("/logout", methods=["POST"])
@token_required
def logout():
    """Add the token's jti to the blacklist so it can no longer be used."""
    revoke_token(g.current_user.get("jti"))
    return jsonify({"message": "token revoked successfully"}), 200


@app.route("/profile", methods=["GET"])
@token_required
@role_required("user", "admin")
def profile():
    """Accessible by any authenticated user (role 'user' or 'admin')."""
    db = get_db()
    row = db.execute(
        "SELECT id, username, role, created_at FROM users WHERE username = ?",
        (g.current_user["sub"],),
    ).fetchone()
    if row is None:
        return jsonify({"error": "user not found"}), 404
    return jsonify({
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "created_at": row["created_at"],
    }), 200


@app.route("/user/<int:user_id>", methods=["DELETE"])
@token_required
@role_required("admin")
def delete_user(user_id):
    """Admin-only: delete a user by id."""
    db = get_db()
    cur = db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"message": f"user {user_id} deleted"}), 200


@app.route("/users", methods=["GET"])
@token_required
@role_required("admin")
def list_users():
    """Admin-only listing - handy for demoing the admin role."""
    db = get_db()
    rows = db.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY id"
    ).fetchall()
    return jsonify([
        {
            "id": r["id"],
            "username": r["username"],
            "role": r["role"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]), 200


# ----------------------------------------------------------------------
# Error handlers - keep responses as JSON
# ----------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "not found", "path": request.path}), 404


@app.errorhandler(405)
def method_not_allowed(_e):
    return jsonify({"error": "method not allowed"}), 405


@app.errorhandler(500)
def internal_error(_e):
    return jsonify({"error": "internal server error"}), 500


# ----------------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------------
if __name__ == "__main__":
    init_db(app.config["DATABASE"])
    print("--- SecureShield is starting on http://127.0.0.1:5000 ---")
    print("Tip: run 'python seed.py' once to create demo accounts.")
    app.run(host="127.0.0.1", port=5000, debug=True)
