"""
seed.py - Populate the SQLite database with demo accounts.

Run once after cloning:   python seed.py
"""
from app import app
from database import init_db, get_db


DEMO_USERS = [
    # username, plaintext password, role
    ("admin", "Admin@1234", "admin"),
    ("alice", "Alice@1234", "user"),
    ("bob",   "Bob@123456", "user"),
]


def seed() -> None:
    init_db(app.config["DATABASE"])
    with app.app_context():
        db = get_db()
        for username, password, role in DEMO_USERS:
            existing = db.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                print(f"  - {username:<8} already exists, skipping")
                continue
            pw_hash = app.bcrypt.generate_password_hash(password).decode("utf-8")
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, pw_hash, role),
            )
            print(f"  + created {username:<8} role={role:<6} password={password}")
        db.commit()


if __name__ == "__main__":
    seed()
    print("\nSeed complete. Demo accounts you can log in with:")
    for u, p, r in DEMO_USERS:
        print(f"   {u:<8} / {p}    ({r})")
