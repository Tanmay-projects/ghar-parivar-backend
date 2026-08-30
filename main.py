import os, sqlite3, hashlib, secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

APP_NAME="Ghar Parivar API"; DATABASE=os.getenv("DATABASE_PATH","ghar_parivar.db"); FRONTEND_ORIGIN=os.getenv("FRONTEND_ORIGIN","https://tanmay-projects.github.io"); SESSION_HOURS=int(os.getenv("SESSION_HOURS","24"))
app=FastAPI(title=APP_NAME,version="2.1.0")
app.add_middleware(CORSMiddleware,allow_origins=list({FRONTEND_ORIGIN.rstrip("/"),"https://tanmay-projects.github.io","http://localhost:5500","http://127.0.0.1:5500"}),allow_credentials=True,allow_methods=["GET","POST","PATCH","DELETE","OPTIONS"],allow_headers=["Content-Type"])
def now(): return datetime.now(timezone.utc)
def db():
 x=sqlite3.connect(DATABASE);x.row_factory=sqlite3.Row;x.execute("PRAGMA foreign_keys=ON");return x
def init():
 x=db();x.executescript("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'family',family_id TEXT,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);CREATE TABLE IF NOT EXISTS private_profiles(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER UNIQUE NOT NULL,mobile TEXT,email TEXT,address TEXT,birthday TEXT,education TEXT,profession TEXT,notes TEXT,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);CREATE TABLE IF NOT EXISTS family_members(id INTEGER PRIMARY KEY AUTOINCREMENT,family_id TEXT NOT NULL,name TEXT NOT NULL,designation TEXT,relation TEXT,generation TEXT DEFAULT 'child',parent_id INTEGER,spouse_id INTEGER,phone TEXT,email TEXT,birthday TEXT,address TEXT,education TEXT,profession TEXT,biography TEXT,achievements TEXT,memories TEXT,avatar TEXT,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);CREATE INDEX IF NOT EXISTS idx_users_family ON users(family_id);CREATE INDEX IF NOT EXISTS idx_members_family ON family_members(family_id);CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);""")
 cols={r[1] for r in x.execute("PRAGMA table_info(family_members)")};
 for n,t in (("generation","TEXT DEFAULT 'child'"),("parent_id","INTEGER"),("spouse_id","INTEGER")):
  if n not in cols:x.execute(f"ALTER TABLE family_members ADD COLUMN {n} {t}")
 x.commit();x.close()
def hp(p):
 s=secrets.token_bytes(16);return s.hex()+":"+hashlib.pbkdf2_hmac("sha256",p.encode(),s,200000).hex()
def vp(p,v):
 try:
  s,d=v.split(":",1);return secrets.compare_digest(hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(s),200000).hex(),d)
 except:return False
def seed_admin():
 u,p=os.getenv("ADMIN_USERNAME"),os.getenv("ADMIN_PASSWORD")
 if not u or not p or len(p)<8:return
 x=db()
 if not x.execute("SELECT id FROM users WHERE username=?",(u,)).fetchone():x.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",(u,hp(p),"admin",now().isoformat()));x.commit()
 x.close()
init();seed_admin()
class Login(BaseModel): username:str=Field(min_length=1,max_length=80);password:str=Field(min_length=1,max_length=200)
class NewUser(BaseModel): username:str=Field(min_length=3,max_length=80);password:str=Field(min_length=8,max_length=200);family_id:str=Field(min_length=1,max_length=80)
class Private(BaseModel): user_id:int;mobile:Optional[str]=None;email:Optional[str]=None;address:Optional[str]=None;birthday:Optional[str]=None;education:Optional[str]=None;profession:Optional[str]=None;notes:Optional[str]=None
class Member(BaseModel):
 family_id:str=Field(min_length=1,max_length=80);name:str=Field(min_length=1,max_length=150);designation:Optional[str]=None;relation:Optional[str]=None;generation:Optional[str]="child";parent_id:Optional[int]=None;spouse_id:Optional[int]=None;phone:Optional[str]=None;email:Optional[str]=None;birthday:Optional[str]=None;address:Optional[str]=None;education:Optional[str]=None;profession:Optional[str]=None;biography:Optional[str]=None;achievements:Optional[str]=None;memories:Optional[str]=None;avatar:Optional[str]=None
def user(req:Request):
 t=req.cookies.get("gp_session");
 if not t:raise HTTPException(401,"Not logged in")
 x=db();r=x.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>? AND u.active=1",(t,now().isoformat())).fetchone();x.close()
 if not r:raise HTTPException(401,"Session expired")
 return r
def admin(u=Depends(user)):
 if u["role"]!="admin":raise HTTPException(403,"Administrator access required")
 return u
@app.get("/")
def root():return {"name":"Ghar Parivar","status":"online","version":"2.1.0"}
@app.get("/health")
def health():return {"status":"ok","database":"connected"}
@app.post("/login")
def login(d:Login,response:Response):
 x=db();u=x.execute("SELECT * FROM users WHERE username=?",(d.username.strip(),)).fetchone()
 if not u or not vp(d.password,u["password_hash"]):x.close();raise HTTPException(401,"Invalid username or password")
 if not u["active"]:x.close();raise HTTPException(403,"This account is disabled")
 t=secrets.token_urlsafe(48);x.execute("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)",(t,u["id"],(now()+timedelta(hours=SESSION_HOURS)).isoformat()));x.execute("DELETE FROM sessions WHERE expires_at<=?",(now().isoformat(),));x.commit();x.close();response.set_cookie("gp_session",t,max_age=SESSION_HOURS*3600,httponly=True,secure=True,samesite="none",path="/");return {"message":"Login successful","role":u["role"],"family_id":u["family_id"]}
@app.get("/me")
def me(u=Depends(user)):return {"id":u["id"],"username":u["username"],"role":u["role"],"family_id":u["family_id"]}
@app.post("/logout")
def logout(req:Request,res:Response):
 t=req.cookies.get("gp_session");x=db();
 if t:x.execute("DELETE FROM sessions WHERE token=?",(t,));x.commit()
 x.close();res.delete_cookie("gp_session",path="/");return {"message":"Logged out"}
@app.get("/families/{family_id}")
def public_family(family_id:str):
 x=db();r=x.execute("SELECT id,family_id,name,designation,relation,generation,parent_id,spouse_id,avatar,biography,achievements,memories FROM family_members WHERE family_id=? AND active=1 ORDER BY id",(family_id,)).fetchall();x.close();return {"family_id":family_id,"members":[dict(a) for a in r]}
@app.get("/family/private")
def private_family(u=Depends(user)):
 if not u["family_id"]:raise HTTPException(404,"No family is assigned to this account")
 x=db();r=x.execute("SELECT * FROM family_members WHERE family_id=? AND active=1 ORDER BY id",(u["family_id"],)).fetchall();x.close();return {"family_id":u["family_id"],"members":[dict(a) for a in r]}
@app.get("/private-profile/{uid}")
def private_profile(uid:int,u=Depends(user)):
 x=db();target=x.execute("SELECT id,family_id FROM users WHERE id=?",(uid,)).fetchone()
 if not target:x.close();raise HTTPException(404,"User not found")
 if u["role"]!="admin" and (u["id"]!=uid or u["family_id"]!=target["family_id"]):x.close();raise HTTPException(403,"You cannot access this profile")
 r=x.execute("SELECT * FROM private_profiles WHERE user_id=?",(uid,)).fetchone();x.close();return dict(r) if r else {"message":"No private information available"}
@app.post("/admin/users")
def create_user(d:NewUser,u=Depends(admin)):
 x=db()
 try:c=x.execute("INSERT INTO users(username,password_hash,role,family_id,created_at) VALUES(?,?,?,?,?)",(d.username.strip(),hp(d.password),"family",d.family_id.strip(),now().isoformat()));x.commit();return {"message":"Family account created","user_id":c.lastrowid,"username":d.username,"family_id":d.family_id}
 except sqlite3.IntegrityError:raise HTTPException(409,"Username already exists")
 finally:x.close()
@app.get("/admin/users")
def users(u=Depends(admin)):
 x=db();r=x.execute("SELECT id,username,role,family_id,active,created_at FROM users ORDER BY id").fetchall();x.close();return [dict(a) for a in r]
@app.post("/admin/users/{uid}/disable")
def disable(uid:int,u=Depends(admin)):
 x=db();x.execute("UPDATE users SET active=0 WHERE id=? AND role!='admin'",(uid,));x.execute("DELETE FROM sessions WHERE user_id=?",(uid,));x.commit();x.close();return {"message":"User disabled"}
@app.post("/admin/private-profile")
def save_private(d:Private,u=Depends(admin)):
 x=db();vals=(d.mobile,d.email,d.address,d.birthday,d.education,d.profession,d.notes);e=x.execute("SELECT id FROM private_profiles WHERE user_id=?",(d.user_id,)).fetchone()
 if e:x.execute("UPDATE private_profiles SET mobile=?,email=?,address=?,birthday=?,education=?,profession=?,notes=? WHERE user_id=?",vals+(d.user_id,))
 else:x.execute("INSERT INTO private_profiles(user_id,mobile,email,address,birthday,education,profession,notes) VALUES(?,?,?,?,?,?,?,?)",(d.user_id,)+vals)
 x.commit();x.close();return {"message":"Private profile saved"}
@app.get("/admin/members")
def members(u=Depends(admin)):
 x=db();r=x.execute("SELECT * FROM family_members ORDER BY family_id,id").fetchall();x.close();return [dict(a) for a in r]
@app.post("/admin/members")
def create_member(d:Member,u=Depends(admin)):
 x=db();c=x.execute("INSERT INTO family_members(family_id,name,designation,relation,generation,parent_id,spouse_id,phone,email,birthday,address,education,profession,biography,achievements,memories,avatar,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(d.family_id,d.name,d.designation,d.relation,d.generation,d.parent_id,d.spouse_id,d.phone,d.email,d.birthday,d.address,d.education,d.profession,d.biography,d.achievements,d.memories,d.avatar,now().isoformat()));x.commit();x.close();return {"message":"Family member created","member_id":c.lastrowid}
@app.patch("/admin/members/{mid}")
def update_member(mid:int,d:Member,u=Depends(admin)):
 x=db();r=x.execute("UPDATE family_members SET family_id=?,name=?,designation=?,relation=?,generation=?,parent_id=?,spouse_id=?,phone=?,email=?,birthday=?,address=?,education=?,profession=?,biography=?,achievements=?,memories=?,avatar=? WHERE id=?",(d.family_id,d.name,d.designation,d.relation,d.generation,d.parent_id,d.spouse_id,d.phone,d.email,d.birthday,d.address,d.education,d.profession,d.biography,d.achievements,d.memories,d.avatar,mid));x.commit();x.close()
 if not r.rowcount:raise HTTPException(404,"Member not found")
 return {"message":"Family member updated"}
@app.delete("/admin/members/{mid}")
def delete_member(mid:int,u=Depends(admin)):
 x=db();r=x.execute("DELETE FROM family_members WHERE id=?",(mid,));x.commit();x.close()
 if not r.rowcount:raise HTTPException(404,"Member not found")
 return {"message":"Family member deleted"}
