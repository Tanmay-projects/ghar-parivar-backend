import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

APP_NAME = "Ghar Parivar API"
DATABASE = os.getenv("DATABASE_PATH", "ghar_parivar.db")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://tanmay-projects.github.io")
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "24"))

app = FastAPI(title=APP_NAME, version="2.0.0")
allowed_origins = {
    FRONTEND_ORIGIN.rstrip("/"),
    "https://tanmay-projects.github.io",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
}
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(allowed_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)


def utc_now():
    return datetime.now(timezone.utc)


def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_database():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'family',
            family_id TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS private_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            mobile TEXT, email TEXT, address TEXT, birthday TEXT,
            education TEXT, profession TEXT, notes TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS family_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            family_id TEXT NOT NULL,
            name TEXT NOT NULL,
            designation TEXT, relation TEXT, phone TEXT, email TEXT,
            birthday TEXT, address TEXT, education TEXT, profession TEXT,
            biography TEXT, achievements TEXT, memories TEXT, avatar TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_family ON users(family_id);
        CREATE INDEX IF NOT EXISTS idx_members_family ON family_members(family_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
    """)
    db.commit()
    db.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 200_000)
        return secrets.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def create_initial_admin():
    username, password = os.getenv("ADMIN_USERNAME"), os.getenv("ADMIN_PASSWORD")
    if not username or not password or len(password) < 8:
        return
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not existing:
        db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                   (username, hash_password(password), "admin", utc_now().isoformat()))
        db.commit()
    db.close()


init_database()
create_initial_admin()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=200)
    family_id: str = Field(min_length=1, max_length=80)


class PrivateProfileRequest(BaseModel):
    user_id: int
    mobile: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None
    birthday: Optional[str] = None
    education: Optional[str] = None
    profession: Optional[str] = None
    notes: Optional[str] = None


class MemberRequest(BaseModel):
    family_id: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=150)
    designation: Optional[str] = None
    relation: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    birthday: Optional[str] = None
    address: Optional[str] = None
    education: Optional[str] = None
    profession: Optional[str] = None
    biography: Optional[str] = None
    achievements: Optional[str] = None
    memories: Optional[str] = None
    avatar: Optional[str] = None


def current_user(request: Request):
    token = request.cookies.get("gp_session")
    if not token:
        raise HTTPException(401, "Not logged in")
    db = get_db()
    row = db.execute("""
        SELECT u.* FROM sessions s
        JOIN users u ON u.id=s.user_id
        WHERE s.token=? AND s.expires_at>? AND u.active=1
    """, (token, utc_now().isoformat())).fetchone()
    db.close()
    if not row:
        raise HTTPException(401, "Session expired")
    return row


def admin_user(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    return user


@app.get("/")
def root():
    return {"name": "Ghar Parivar", "status": "online", "version": "2.0.0"}


@app.get("/health")
def health():
    return {"status": "ok", "database": "connected"}


@app.post("/login")
def login(data: LoginRequest, response: Response):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (data.username.strip(),)).fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        db.close()
        raise HTTPException(401, "Invalid username or password")
    if not user["active"]:
        db.close()
        raise HTTPException(403, "This account is disabled")
    token = secrets.token_urlsafe(48)
    expires = utc_now() + timedelta(hours=SESSION_HOURS)
    db.execute("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)",
               (token, user["id"], expires.isoformat()))
    db.execute("DELETE FROM sessions WHERE expires_at<=?", (utc_now().isoformat(),))
    db.commit()
    db.close()
    response.set_cookie(key="gp_session", value=token, max_age=SESSION_HOURS*3600,
                        httponly=True, secure=True, samesite="none", path="/")
    return {"message":"Login successful", "role":user["role"], "family_id":user["family_id"]}


@app.get("/me")
def me(user=Depends(current_user)):
    return {"id":user["id"], "username":user["username"], "role":user["role"], "family_id":user["family_id"]}


@app.post("/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get("gp_session")
    if token:
        db = get_db()
        db.execute("DELETE FROM sessions WHERE token=?", (token,))
        db.commit()
        db.close()
    response.delete_cookie("gp_session", path="/")
    return {"message":"Logged out"}


@app.get("/family/private")
def private_family(user=Depends(current_user)):
    if not user["family_id"]:
        raise HTTPException(404, "No family is assigned to this account")
    db = get_db()
    members = db.execute("SELECT * FROM family_members WHERE family_id=? AND active=1 ORDER BY id",
                         (user["family_id"],)).fetchall()
    db.close()
    return {"family_id":user["family_id"], "members":[dict(row) for row in members]}


@app.get("/private-profile/{user_id}")
def private_profile(user_id: int, user=Depends(current_user)):
    if user["role"] != "admin" and user["id"] != user_id:
        raise HTTPException(403, "You cannot access this profile")
    db = get_db()
    row = db.execute("SELECT * FROM private_profiles WHERE user_id=?", (user_id,)).fetchone()
    db.close()
    return dict(row) if row else {"message":"No private information available"}


@app.post("/admin/users")
def create_user(data: CreateUserRequest, admin=Depends(admin_user)):
    db = get_db()
    try:
        cur = db.execute("INSERT INTO users(username,password_hash,role,family_id,created_at) VALUES(?,?,?,?,?)",
                         (data.username.strip(), hash_password(data.password), "family", data.family_id.strip(), utc_now().isoformat()))
        db.commit()
        return {"message":"Family account created", "user_id":cur.lastrowid, "username":data.username, "family_id":data.family_id}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already exists")
    finally:
        db.close()


@app.get("/admin/users")
def list_users(admin=Depends(admin_user)):
    db = get_db()
    rows = db.execute("SELECT id,username,role,family_id,active,created_at FROM users ORDER BY id").fetchall()
    db.close()
    return [dict(row) for row in rows]


@app.post("/admin/users/{user_id}/disable")
def disable_user(user_id: int, admin=Depends(admin_user)):
    db = get_db()
    db.execute("UPDATE users SET active=0 WHERE id=? AND role!='admin'", (user_id,))
    db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    db.commit()
    db.close()
    return {"message":"User disabled"}


@app.post("/admin/private-profile")
def save_private_profile(data: PrivateProfileRequest, admin=Depends(admin_user)):
    db = get_db()
    exists = db.execute("SELECT id FROM private_profiles WHERE user_id=?", (data.user_id,)).fetchone()
    values = (data.mobile,data.email,data.address,data.birthday,data.education,data.profession,data.notes)
    if exists:
        db.execute("UPDATE private_profiles SET mobile=?,email=?,address=?,birthday=?,education=?,profession=?,notes=? WHERE user_id=?",
                   values + (data.user_id,))
    else:
        db.execute("INSERT INTO private_profiles(user_id,mobile,email,address,birthday,education,profession,notes) VALUES(?,?,?,?,?,?,?,?)",
                   (data.user_id,) + values)
    db.commit()
    db.close()
    return {"message":"Private profile saved"}


@app.get("/admin/members")
def admin_members(admin=Depends(admin_user)):
    db = get_db()
    rows = db.execute("SELECT * FROM family_members ORDER BY family_id,id").fetchall()
    db.close()
    return [dict(row) for row in rows]


@app.post("/admin/members")
def create_member(data: MemberRequest, admin=Depends(admin_user)):
    db = get_db()
    cur = db.execute("""INSERT INTO family_members
        (family_id,name,designation,relation,phone,email,birthday,address,education,profession,biography,achievements,memories,avatar,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (data.family_id,data.name,data.designation,data.relation,data.phone,data.email,data.birthday,data.address,
         data.education,data.profession,data.biography,data.achievements,data.memories,data.avatar,utc_now().isoformat()))
    db.commit()
    member_id = cur.lastrowid
    db.close()
    return {"message":"Family member created", "member_id":member_id}


@app.patch("/admin/members/{member_id}")
def update_member(member_id: int, data: MemberRequest, admin=Depends(admin_user)):
    db = get_db()
    result = db.execute("""UPDATE family_members SET family_id=?,name=?,designation=?,relation=?,phone=?,email=?,birthday=?,address=?,education=?,profession=?,biography=?,achievements=?,memories=?,avatar=? WHERE id=?""",
        (data.family_id,data.name,data.designation,data.relation,data.phone,data.email,data.birthday,data.address,
         data.education,data.profession,data.biography,data.achievements,data.memories,data.avatar,member_id))
    db.commit()
    db.close()
    if result.rowcount == 0:
        raise HTTPException(404, "Member not found")
    return {"message":"Family member updated"}


@app.delete("/admin/members/{member_id}")
def delete_member(member_id: int, admin=Depends(admin_user)):
    db = get_db()
    result = db.execute("DELETE FROM family_members WHERE id=?", (member_id,))
    db.commit()
    db.close()
    if result.rowcount == 0:
        raise HTTPException(404, "Member not found")
    return {"message":"Family member deleted"}
