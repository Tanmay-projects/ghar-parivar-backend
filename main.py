import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# =========================================================
# GHAR PARIVAR — SECURE LOGIN BACKEND
# =========================================================

app = FastAPI(title="Ghar Parivar API")


# =========================================================
# FRONTEND ACCESS
# =========================================================

FRONTEND_URL = os.getenv(
    "FRONTEND_URL",
    "https://tanmay-projects.github.io"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        FRONTEND_URL,
        "https://tanmay-projects.github.io",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# DATABASE
# =========================================================

DATABASE = os.getenv(
    "DATABASE_PATH",
    "ghar_parivar.db"
)


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():

    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            family_id TEXT,
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS private_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            mobile TEXT,
            email TEXT,
            address TEXT,
            birthday TEXT,
            notes TEXT
        )
    """)

    db.commit()
    db.close()


init_database()


# =========================================================
# PASSWORD SECURITY
# =========================================================

def hash_password(password: str) -> str:

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )

    return (
        salt.hex()
        + ":"
        + password_hash.hex()
    )


def verify_password(password: str, stored_hash: str) -> bool:

    try:

        salt_hex, hash_hex = stored_hash.split(":")

        salt = bytes.fromhex(salt_hex)

        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            200_000
        )

        return secrets.compare_digest(
            calculated.hex(),
            hash_hex
        )

    except Exception:
        return False


# =========================================================
# ADMIN INITIALIZATION
# =========================================================

def create_initial_admin():

    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")

    if not username or not password:
        return

    db = get_db()

    existing = db.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not existing:

        db.execute("""
            INSERT INTO users
            (username, password_hash, role, family_id, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            username,
            hash_password(password),
            "admin",
            None,
            datetime.now(timezone.utc).isoformat()
        ))

        db.commit()

    db.close()


create_initial_admin()


# =========================================================
# MODELS
# =========================================================

class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    family_id: str


class PrivateProfileRequest(BaseModel):
    user_id: int
    mobile: str | None = None
    email: str | None = None
    address: str | None = None
    birthday: str | None = None
    notes: str | None = None


# =========================================================
# AUTHENTICATION
# =========================================================

def get_current_user(request: Request):

    token = request.cookies.get("gp_session")

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Not logged in"
        )

    db = get_db()

    session = db.execute("""
        SELECT users.*
        FROM sessions
        JOIN users
        ON users.id = sessions.user_id
        WHERE sessions.token = ?
        AND sessions.expires_at > ?
        AND users.active = 1
    """, (
        token,
        datetime.now(timezone.utc).isoformat()
    )).fetchone()

    db.close()

    if not session:
        raise HTTPException(
            status_code=401,
            detail="Session expired"
        )

    return session


def require_admin(user=Depends(get_current_user)):

    if user["role"] != "admin":

        raise HTTPException(
            status_code=403,
            detail="Administrator access required"
        )

    return user


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/")
def home():

    return {
        "name": "Ghar Parivar",
        "status": "online",
        "message": "Ghar Parivar backend is running"
    }


@app.get("/health")
def health():

    return {
        "status": "ok"
    }


# =========================================================
# LOGIN
# =========================================================

@app.post("/login")
def login(data: LoginRequest, response: Response):

    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (data.username,)
    ).fetchone()

    if not user or not verify_password(
        data.password,
        user["password_hash"]
    ):

        db.close()

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if not user["active"]:

        db.close()

        raise HTTPException(
            status_code=403,
            detail="This account is disabled"
        )

    token = secrets.token_urlsafe(48)

    expires = (
        datetime.now(timezone.utc)
        + timedelta(hours=24)
    ).isoformat()

    db.execute("""
        INSERT INTO sessions
        (token, user_id, expires_at)
        VALUES (?, ?, ?)
    """, (
        token,
        user["id"],
        expires
    ))

    db.commit()
    db.close()

    response.set_cookie(
        key="gp_session",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=86400
    )

    return {
        "message": "Login successful",
        "role": user["role"],
        "family_id": user["family_id"]
    }


# =========================================================
# CURRENT USER
# =========================================================

@app.get("/me")
def me(user=Depends(get_current_user)):

    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "family_id": user["family_id"]
    }


# =========================================================
# LOGOUT
# =========================================================

@app.post("/logout")
def logout(
    request: Request,
    response: Response
):

    token = request.cookies.get("gp_session")

    if token:

        db = get_db()

        db.execute(
            "DELETE FROM sessions WHERE token = ?",
            (token,)
        )

        db.commit()
        db.close()

    response.delete_cookie("gp_session")

    return {
        "message": "Logged out"
    }


# =========================================================
# ADMIN — CREATE FAMILY USER
# =========================================================

@app.post("/admin/users")
def create_user(
    data: CreateUserRequest,
    admin=Depends(require_admin)
):

    if len(data.password) < 8:

        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters"
        )

    db = get_db()

    try:

        cursor = db.execute("""
            INSERT INTO users
            (username, password_hash, role, family_id, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            data.username,
            hash_password(data.password),
            "family",
            data.family_id,
            datetime.now(timezone.utc).isoformat()
        ))

        db.commit()

        user_id = cursor.lastrowid

    except sqlite3.IntegrityError:

        db.close()

        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    db.close()

    return {
        "message": "Family account created",
        "user_id": user_id,
        "username": data.username,
        "family_id": data.family_id
    }


# =========================================================
# ADMIN — LIST USERS
# =========================================================

@app.get("/admin/users")
def list_users(
    admin=Depends(require_admin)
):

    db = get_db()

    users = db.execute("""
        SELECT
            id,
            username,
            role,
            family_id,
            active,
            created_at
        FROM users
        ORDER BY id
    """).fetchall()

    db.close()

    return [
        dict(user)
        for user in users
    ]


# =========================================================
# ADMIN — DISABLE USER
# =========================================================

@app.post("/admin/users/{user_id}/disable")
def disable_user(
    user_id: int,
    admin=Depends(require_admin)
):

    db = get_db()

    db.execute("""
        UPDATE users
        SET active = 0
        WHERE id = ?
        AND role != 'admin'
    """, (user_id,))

    db.commit()
    db.close()

    return {
        "message": "User disabled"
    }


# =========================================================
# PRIVATE PROFILE
# =========================================================

@app.get("/private-profile/{user_id}")
def private_profile(
    user_id: int,
    user=Depends(get_current_user)
):

    # Admin can access any private profile.
    # Family members can access only their own.

    if (
        user["role"] != "admin"
        and user["id"] != user_id
    ):

        raise HTTPException(
            status_code=403,
            detail="You cannot access this profile"
        )

    db = get_db()

    profile = db.execute("""
        SELECT
            mobile,
            email,
            address,
            birthday,
            notes
        FROM private_profiles
        WHERE user_id = ?
    """, (user_id,)).fetchone()

    db.close()

    if not profile:

        return {
            "message": "No private information available"
        }

    return dict(profile)


# =========================================================
# ADMIN — SAVE PRIVATE PROFILE
# =========================================================

@app.post("/admin/private-profile")
def save_private_profile(
    data: PrivateProfileRequest,
    admin=Depends(require_admin)
):

    db = get_db()

    existing = db.execute(
        "SELECT id FROM private_profiles WHERE user_id = ?",
        (data.user_id,)
    ).fetchone()

    if existing:

        db.execute("""
            UPDATE private_profiles

            SET
                mobile = ?,
                email = ?,
                address = ?,
                birthday = ?,
                notes = ?

            WHERE user_id = ?
        """, (
            data.mobile,
            data.email,
            data.address,
            data.birthday,
            data.notes,
            data.user_id
        ))

    else:

        db.execute("""
            INSERT INTO private_profiles
            (
                user_id,
                mobile,
                email,
                address,
                birthday,
                notes
            )

            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            data.user_id,
            data.mobile,
            data.email,
            data.address,
            data.birthday,
            data.notes
        ))

    db.commit()
    db.close()

    return {
        "message": "Private profile saved"
    }
