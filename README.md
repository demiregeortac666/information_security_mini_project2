# SecureShield - Mini Project II

A Role-Based Access Control (RBAC) API built with Flask.
Demonstrates secure authentication using bcrypt-salted password hashing,
signed JSON Web Tokens, in-memory token revocation (blacklisting), and
defensive logging of every unauthorized access attempt.

> Course: SENG / Mini Project II
> Team name: _<fill in>_
> Members: _<fill in>_

---

## Mapping to the project tasks

| Task | Requirement | Where it lives |
|------|-------------|----------------|
| 1 | Salted + hashed password storage (bcrypt, never plain-text) | `app.py` `register()` / `login()` |
| 2 | `/login` issues a JWT containing `username` + `role` | `auth.generate_token`, `app.login` |
| 3 | Decorator validates JWT on every protected route | `auth.token_required` |
| 4 | `GET /profile` (user, admin) ; `DELETE /user/<id>` (admin only) | `app.profile`, `app.delete_user` |
| 5 | `/logout` revokes a token via in-memory blacklist (`jti` claim) | `auth.TOKEN_BLACKLIST`, `app.logout` |
| 6 | Every 401 / 403 attempt logged to `security.log` (timestamp + action) | `auth.log_security_event` |

The "Principle of Least Privilege" is enforced by stacking
`@token_required` + `@role_required('admin')` on every privileged route.
A token whose signature was not produced with the server-side secret is
rejected during decode, *before* the role check ever runs.

---

## Setup

Requires Python 3.10+.

```bash
git clone <your-repo-url>
cd SecureShield

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt

# (optional) set a strong secret in production:
export SECURESHIELD_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"

python seed.py                      # creates demo users
python app.py                       # starts on http://127.0.0.1:5000
```

### Demo accounts (created by `seed.py`)

| username | password    | role  |
|----------|-------------|-------|
| admin    | Admin@1234  | admin |
| alice    | Alice@1234  | user  |
| bob      | Bob@123456  | user  |

---

## Endpoints

| Method | Path           | Auth     | Role       | Purpose                    |
|--------|----------------|----------|------------|----------------------------|
| GET    | `/health`      | -        | -          | Liveness check             |
| POST   | `/register`    | -        | -          | Create account             |
| POST   | `/login`       | -        | -          | Get a JWT                  |
| POST   | `/logout`      | Bearer   | any        | Revoke current token       |
| GET    | `/profile`     | Bearer   | user/admin | Read own profile           |
| GET    | `/users`       | Bearer   | admin      | List all users             |
| DELETE | `/user/<id>`   | Bearer   | admin      | Delete a user (admin-only) |

Tokens go in the `Authorization` header:
`Authorization: Bearer <access_token>`

---

## Demo walk-through (use these commands in the YouTube video)

The demo proves all three things the spec asks for: a successful
login, a 403 access denial, and a tamper-rejection.

### 1. Successful login (gets you a token)

```bash
curl -s -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Alice@1234"}'
```

Save the returned `access_token`:

```bash
USER_TOKEN="<paste here>"
```

### 2. Access denied - User hits an admin route -> 403

```bash
curl -i -X DELETE http://127.0.0.1:5000/user/3 \
  -H "Authorization: Bearer $USER_TOKEN"
```

You get `HTTP/1.1 403 FORBIDDEN` and `{"error": "insufficient privileges"}`.
A line is appended to `security.log`:

```
2026-04-30 14:26:32 | WARNING | [FORBIDDEN_ACCESS] status=403 user=alice
ip=127.0.0.1 method=DELETE path=/user/3 details=role=user, required=['admin']
```

### 3. Tamper test - manually edit the role in jwt.io

1.  Paste `$USER_TOKEN` into <https://jwt.io>.
2.  Change `"role": "user"` to `"role": "admin"` in the payload.
3.  Copy the new (still showing red "Invalid Signature") encoded token.
4.  Send it:

    ```bash
    curl -i -X DELETE http://127.0.0.1:5000/user/3 \
      -H "Authorization: Bearer <tampered-token>"
    ```

5.  Server returns `401 Unauthorized` and
    `{"error": "invalid token signature or payload"}` because the
    tampered payload was not re-signed with the server's secret key.
    PyJWT's `jwt.decode()` raises `InvalidSignatureError` and our
    `@token_required` decorator translates that to a 401.

### 4. (Bonus) Token revocation via /logout

```bash
curl -X POST http://127.0.0.1:5000/logout \
  -H "Authorization: Bearer $USER_TOKEN"

# Reuse the now-revoked token:
curl -i http://127.0.0.1:5000/profile \
  -H "Authorization: Bearer $USER_TOKEN"
# -> 401 {"error":"token has been revoked"}
```

### 5. Admin happy-path

```bash
ADMIN_TOKEN=$(curl -s -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@1234"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl    http://127.0.0.1:5000/users    -H "Authorization: Bearer $ADMIN_TOKEN"
curl -X DELETE http://127.0.0.1:5000/user/3 \
                                     -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

## Project layout

```
SecureShield/
├── app.py            # Flask app + all routes
├── auth.py           # JWT helpers, decorators, blacklist, security logger
├── database.py       # SQLite connection & schema
├── seed.py           # creates demo accounts
├── requirements.txt
├── REPORT.md         # 2-page report (salting & JWT-payload risks)
└── README.md
```

Generated at runtime (gitignored):

- `secureshield.db` - SQLite database
- `security.log`    - defensive log of unauthorized attempts
