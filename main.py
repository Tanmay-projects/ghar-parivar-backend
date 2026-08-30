import os, sqlite3, hashlib, secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

APP_NAME="Ghar Parivar API"; DATABASE=os.getenv("DATABASE_PATH","ghar_parivar.db")
FRONTEND_ORIGIN=os.getenv("FRONTEND_ORIGIN","https://tanmay-projects.github.io"); SESSION_HOURS=int(os.getenv("SESSION_HOURS","24"))
app=FastAPI(title=APP_NAME,version="3.0.0")
app.add_middleware(CORSMiddleware,allow_origins=[FRONTEND_ORIGIN.rstrip("/"),"https://tanmay-projects.github.io","http://localhost:5500","http://127.0.0.1:5500"],allow_credentials=True,allow_methods=["GET","POST","PATCH","DELETE","OPTIONS"],allow_headers=["Content-Type"])

def now(): return datetime.now(timezone.utc)
def db():
    x=sqlite3.connect(DATABASE); x.row_factory=sqlite3.Row; x.execute("PRAGMA foreign_keys=ON"); return x

def init_db():
    x=db(); x.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'family',family_id TEXT,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS private_profiles(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER UNIQUE NOT NULL,mobile TEXT,email TEXT,address TEXT,birthday TEXT,education TEXT,profession TEXT,notes TEXT,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS family_members(id INTEGER PRIMARY KEY AUTOINCREMENT,family_id TEXT NOT NULL,name TEXT NOT NULL,designation TEXT,relation TEXT,phone TEXT,email TEXT,birthday TEXT,address TEXT,education TEXT,profession TEXT,biography TEXT,achievements TEXT,memories TEXT,avatar TEXT,parent_id INTEGER,spouse_id INTEGER,generation TEXT DEFAULT 'child',is_public INTEGER NOT NULL DEFAULT 1,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,FOREIGN KEY(parent_id) REFERENCES family_members(id) ON DELETE SET NULL,FOREIGN KEY(spouse_id) REFERENCES family_members(id) ON DELETE SET NULL);
    CREATE INDEX IF NOT EXISTS idx_members_family ON family_members(family_id);
    CREATE INDEX IF NOT EXISTS idx_members_parent ON family_members(parent_id);
    ''')
    # Upgrade databases created by earlier versions.
    cols={r[1] for r in x.execute("PRAGMA table_info(family_members)")}
    for name,definition in [("parent_id","INTEGER"),("spouse_id","INTEGER"),("generation","TEXT DEFAULT 'child'"),("is_public","INTEGER NOT NULL DEFAULT 1")]:
        if name not in cols: x.execute(f"ALTER TABLE family_members ADD COLUMN {name} {definition}")
    x.commit(); x.close()

def hp(p):
    s=secrets.token_bytes(16); d=hashlib.pbkdf2_hmac("sha256",p.encode(),s,200000); return s.hex()+":"+d.hex()
def vp(p,s):
    try:
        a,b=s.split(":",1); d=hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(a),200000); return secrets.compare_digest(d.hex(),b)
    except: return False
init_db()

class Login(BaseModel): username:str=Field(min_length=1,max_length=80); password:str=Field(min_length=1,max_length=200)
class NewUser(BaseModel): username:str=Field(min_length=3,max_length=80); password:str=Field(min_length=8,max_length=200); family_id:str=Field(min_length=1,max_length=80)
class Private(BaseModel): user_id:int; mobile:Optional[str]=None; email:Optional[str]=None; address:Optional[str]=None; birthday:Optional[str]=None; education:Optional[str]=None; profession:Optional[str]=None; notes:Optional[str]=None
class Member(BaseModel):
    family_id:str=Field(min_length=1,max_length=80); name:str=Field(min_length=1,max_length=150); designation:Optional[str]=None; relation:Optional[str]=None
    phone:Optional[str]=None; email:Optional[str]=None; birthday:Optional[str]=None; address:Optional[str]=None; education:Optional[str]=None; profession:Optional[str]=None
    biography:Optional[str]=None; achievements:Optional[str]=None; memories:Optional[str]=None; avatar:Optional[str]=None
    parent_id:Optional[int]=None; spouse_id:Optional[int]=None; generation:Optional[str]="child"; is_public:bool=True

def current(request:Request):
    t=request.cookies.get("gp_session")
    if not t: raise HTTPException(401,"Not logged in")
    x=db(); r=x.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>? AND u.active=1",(t,now().isoformat())).fetchone(); x.close()
    if not r: raise HTTPException(401,"Session expired")
    return r
def admin(u=Depends(current)):
    if u["role"]!="admin": raise HTTPException(403,"Administrator access required")
    return u

@app.get("/")
def root(): return {"name":"Ghar Parivar","status":"online","version":"3.0.0"}
@app.get("/health")
def health(): return {"status":"ok","database":"connected"}

@app.post("/login")
def login(data:Login,response:Response):
    x=db(); u=x.execute("SELECT * FROM users WHERE username=?",(data.username.strip(),)).fetchone()
    if not u or not vp(data.password,u["password_hash"]): x.close(); raise HTTPException(401,"Invalid username or password")
    if not u["active"]: x.close(); raise HTTPException(403,"This account is disabled")
    t=secrets.token_urlsafe(48); exp=now()+timedelta(hours=SESSION_HOURS); x.execute("INSERT INTO sessions VALUES(?,?,?)",(t,u["id"],exp.isoformat())); x.execute("DELETE FROM sessions WHERE expires_at<=?",(now().isoformat(),)); x.commit(); x.close()
    response.set_cookie("gp_session",t,max_age=SESSION_HOURS*3600,httponly=True,secure=True,samesite="none",path="/")
    return {"message":"Login successful","role":u["role"],"family_id":u["family_id"]}
@app.get("/me")
def me(u=Depends(current)): return {"id":u["id"],"username":u["username"],"role":u["role"],"family_id":u["family_id"]}
@app.post("/logout")
def logout(request:Request,response:Response):
    t=request.cookies.get("gp_session"); x=db()
    if t: x.execute("DELETE FROM sessions WHERE token=?",(t,)); x.commit()
    x.close(); response.delete_cookie("gp_session",path="/"); return {"message":"Logged out"}

# Public tree data contains only fields deliberately marked public.
@app.get("/families/{family_id}")
def public_family(family_id:str):
    x=db(); rows=x.execute("SELECT id,family_id,name,designation,relation,avatar,parent_id,spouse_id,generation FROM family_members WHERE family_id=? AND active=1 AND is_public=1 ORDER BY id",(family_id,)).fetchall(); x.close()
    return {"family_id":family_id,"members":[dict(r) for r in rows]}

@app.get("/family/private")
def private_family(u=Depends(current)):
    if not u["family_id"]: raise HTTPException(404,"No family is assigned to this account")
    x=db(); rows=x.execute("SELECT * FROM family_members WHERE family_id=? AND active=1 ORDER BY id",(u["family_id"],)).fetchall(); x.close(); return {"family_id":u["family_id"],"members":[dict(r) for r in rows]}
@app.get("/private-profile/{user_id}")
def private_profile(user_id:int,u=Depends(current)):
    if u["role"]!="admin" and u["id"]!=user_id: raise HTTPException(403,"You cannot access this profile")
    x=db(); r=x.execute("SELECT * FROM private_profiles WHERE user_id=?",(user_id,)).fetchone(); x.close(); return dict(r) if r else {"message":"No private information available"}

@app.post("/admin/users")
def create_user(data:NewUser,a=Depends(admin)):
    x=db()
    try:
        c=x.execute("INSERT INTO users(username,password_hash,role,family_id,created_at) VALUES(?,?,?,?,?)",(data.username.strip(),hp(data.password),"family",data.family_id.strip(),now().isoformat())); x.commit(); return {"message":"Family account created","user_id":c.lastrowid}
    except sqlite3.IntegrityError: raise HTTPException(409,"Username already exists")
    finally: x.close()
@app.get("/admin/users")
def users(a=Depends(admin)):
    x=db(); r=x.execute("SELECT id,username,role,family_id,active,created_at FROM users ORDER BY id").fetchall(); x.close(); return [dict(v) for v in r]
@app.post("/admin/users/{user_id}/disable")
def disable(user_id:int,a=Depends(admin)):
    x=db(); x.execute("UPDATE users SET active=0 WHERE id=? AND role!='admin'",(user_id,)); x.execute("DELETE FROM sessions WHERE user_id=?",(user_id,)); x.commit(); x.close(); return {"message":"User disabled"}
@app.post("/admin/private-profile")
def save_private(data:Private,a=Depends(admin)):
    x=db(); vals=(data.mobile,data.email,data.address,data.birthday,data.education,data.profession,data.notes); exists=x.execute("SELECT id FROM private_profiles WHERE user_id=?",(data.user_id,)).fetchone()
    if exists: x.execute("UPDATE private_profiles SET mobile=?,email=?,address=?,birthday=?,education=?,profession=?,notes=? WHERE user_id=?",vals+(data.user_id,))
    else: x.execute("INSERT INTO private_profiles(user_id,mobile,email,address,birthday,education,profession,notes) VALUES(?,?,?,?,?,?,?,?)",(data.user_id,)+vals)
    x.commit(); x.close(); return {"message":"Private profile saved"}

@app.get("/admin/members")
def members(a=Depends(admin)):
    x=db(); r=x.execute("SELECT * FROM family_members ORDER BY family_id,id").fetchall(); x.close(); return [dict(v) for v in r]
def member_values(d): return (d.family_id,d.name,d.designation,d.relation,d.phone,d.email,d.birthday,d.address,d.education,d.profession,d.biography,d.achievements,d.memories,d.avatar,d.parent_id,d.spouse_id,d.generation,1 if d.is_public else 0)
@app.post("/admin/members")
def add_member(data:Member,a=Depends(admin)):
    x=db(); v=member_values(data); c=x.execute("""INSERT INTO family_members(family_id,name,designation,relation,phone,email,birthday,address,education,profession,biography,achievements,memories,avatar,parent_id,spouse_id,generation,is_public,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",v+(now().isoformat(),)); x.commit(); i=c.lastrowid; x.close(); return {"message":"Family member created","member_id":i}
@app.patch("/admin/members/{member_id}")
def edit_member(member_id:int,data:Member,a=Depends(admin)):
    x=db(); v=member_values(data); r=x.execute("""UPDATE family_members SET family_id=?,name=?,designation=?,relation=?,phone=?,email=?,birthday=?,address=?,education=?,profession=?,biography=?,achievements=?,memories=?,avatar=?,parent_id=?,spouse_id=?,generation=?,is_public=? WHERE id=?""",v+(member_id,)); x.commit(); x.close()
    if not r.rowcount: raise HTTPException(404,"Member not found")
    return {"message":"Family member updated"}
@app.delete("/admin/members/{member_id}")
def delete_member(member_id:int,a=Depends(admin)):
    x=db(); r=x.execute("DELETE FROM family_members WHERE id=?",(member_id,)); x.commit(); x.close()
    if not r.rowcount: raise HTTPException(404,"Member not found")
    return {"message":"Family member deleted"}
