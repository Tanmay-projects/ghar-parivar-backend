import os, hashlib, secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from supabase import create_client

APP_NAME = "Ghar Parivar API"
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://tanmay-projects.github.io")
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "24"))
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured")

sb = create_client(SUPABASE_URL, SUPABASE_KEY)
app = FastAPI(title=APP_NAME, version="4.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=list({FRONTEND_ORIGIN.rstrip("/"), "https://tanmay-projects.github.io", "http://localhost:5500", "http://127.0.0.1:5500"}),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)

def now():
    return datetime.now(timezone.utc)

def hp(password):
    salt = secrets.token_bytes(16)
    return salt.hex() + ":" + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000).hex()

def vp(password, stored):
    try:
        salt, digest = stored.split(":", 1)
        return secrets.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200000).hex(), digest)
    except Exception:
        return False

def rows(table, **filters):
    q = sb.table(table).select("*")
    for key, value in filters.items():
        q = q.eq(key, value)
    return q.execute().data or []

def one(table, **filters):
    r = rows(table, **filters)
    return r[0] if r else None

def require_image(value):
    if not value or not str(value).startswith("data:image/"):
        raise HTTPException(400, "Photo must be an image data URL")

class Login(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)
class NewUser(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=200)
    family_id: str = Field(min_length=1, max_length=80)
class Private(BaseModel):
    user_id: int
    mobile: Optional[str] = None; email: Optional[str] = None; address: Optional[str] = None; birthday: Optional[str] = None
    education: Optional[str] = None; profession: Optional[str] = None; notes: Optional[str] = None
class Family(BaseModel):
    id: str = Field(min_length=1, max_length=80); name: str = Field(min_length=1, max_length=150)
    description: Optional[str] = None; icon: Optional[str] = "👨‍👩‍👧‍👦"; photo: Optional[str] = None; active: bool = True
class Member(BaseModel):
    family_id: str = Field(min_length=1, max_length=80); name: str = Field(min_length=1, max_length=150)
    designation: Optional[str] = None; relation: Optional[str] = None; generation: Optional[str] = "child"
    parent_id: Optional[int] = None; spouse_id: Optional[int] = None; phone: Optional[str] = None; email: Optional[str] = None
    birthday: Optional[str] = None; address: Optional[str] = None; education: Optional[str] = None; profession: Optional[str] = None
    biography: Optional[str] = None; achievements: Optional[str] = None; memories: Optional[str] = None; avatar: Optional[str] = None
class Event(BaseModel):
    title: str = Field(min_length=1, max_length=180); description: Optional[str] = None; date: Optional[str] = None
    location: Optional[str] = None; photo: Optional[str] = None; active: bool = True
class Media(BaseModel):
    slot: str = Field(min_length=1, max_length=40); image_data: str = Field(min_length=20)
    caption: Optional[str] = None; active: bool = True
class EventPhoto(BaseModel):
    image_data: str = Field(min_length=20); caption: Optional[str] = None

def user(req: Request):
    token = req.cookies.get("gp_session")
    if not token: raise HTTPException(401, "Not logged in")
    s = one("sessions", token=token)
    if not s: raise HTTPException(401, "Session expired")
    try:
        if datetime.fromisoformat(str(s["expires_at"]).replace("Z", "+00:00")) <= now():
            raise HTTPException(401, "Session expired")
    except ValueError:
        raise HTTPException(401, "Session expired")
    u = one("users", id=s["user_id"])
    if not u or not u.get("active"): raise HTTPException(401, "Session expired")
    return u

def admin(u=Depends(user)):
    if u["role"] != "admin": raise HTTPException(403, "Administrator access required")
    return u

@app.get("/")
def root(): return {"name": APP_NAME, "status": "online", "version": "4.0.0"}
@app.get("/health")
def health():
    try:
        sb.table("users").select("id").limit(1).execute()
        return {"status": "ok", "database": "supabase"}
    except Exception as e:
        raise HTTPException(503, "Database unavailable")

@app.post("/login")
def login(d: Login, response: Response):
    u = one("users", username=d.username.strip())
    if not u or not vp(d.password, u["password_hash"]): raise HTTPException(401, "Invalid username or password")
    if not u.get("active"): raise HTTPException(403, "This account is disabled")
    token = secrets.token_urlsafe(48)
    sb.table("sessions").insert({"token": token, "user_id": u["id"], "expires_at": (now() + timedelta(hours=SESSION_HOURS)).isoformat()}).execute()
    response.set_cookie("gp_session", token, max_age=SESSION_HOURS*3600, httponly=True, secure=True, samesite="none", path="/")
    return {"message": "Login successful", "role": u["role"], "family_id": u.get("family_id")}

@app.get("/me")
def me(u=Depends(user)): return {"id":u["id"],"username":u["username"],"role":u["role"],"family_id":u.get("family_id")}
@app.post("/logout")
def logout(req: Request, res: Response):
    token=req.cookies.get("gp_session")
    if token: sb.table("sessions").delete().eq("token", token).execute()
    res.delete_cookie("gp_session", path="/")
    return {"message":"Logged out"}

@app.get("/families")
def families():
    fs=rows("families", active=True)
    for f in fs: f["member_count"] = len(rows("family_members", family_id=f["id"], active=True))
    fs.sort(key=lambda x: x.get("created_at", ""))
    return fs

@app.get("/families/{family_id}")
def public_family(family_id: str):
    f=one("families", id=family_id, active=True)
    m=rows("family_members", family_id=family_id, active=True)
    public=[]
    for x in m:
        public.append({k:x.get(k) for k in ["id","family_id","name","designation","relation","generation","parent_id","spouse_id","avatar","biography","achievements","memories"]})
    public.sort(key=lambda x: x.get("id") or 0)
    return {"family": f or {"id":family_id,"name":family_id}, "members":public}

@app.get("/events")
def public_events():
    e=rows("events", active=True); e.sort(key=lambda x:(x.get("date") or "",x.get("id") or 0), reverse=True); return e
@app.get("/events/{eid}/photos")
def public_event_photos(eid:int): return [{k:p.get(k) for k in ["id","image_data","caption"]} for p in rows("event_photos", event_id=eid)]
@app.get("/media")
def public_media(): return rows("site_media", active=True)

@app.get("/family/private")
def private_family(u=Depends(user)):
    m=rows("family_members", active=True) if u["role"]=="admin" else rows("family_members", family_id=u.get("family_id"), active=True)
    return {"family_id":"all" if u["role"]=="admin" else u.get("family_id"), "members":m}
@app.get("/private-profile/{uid}")
def private_profile(uid:int,u=Depends(user)):
    target=one("users", id=uid)
    if not target: raise HTTPException(404,"User not found")
    if u["role"]!="admin" and (u["id"]!=uid or u.get("family_id")!=target.get("family_id")): raise HTTPException(403,"You cannot access this profile")
    return one("private_profiles", user_id=uid) or {"message":"No private information available"}

@app.post("/admin/families")
def create_family(d:Family,u=Depends(admin)):
    try:
        sb.table("families").insert({"id":d.id,"name":d.name,"description":d.description,"icon":d.icon,"photo":d.photo,"active":d.active,"created_at":now().isoformat()}).execute()
    except Exception: raise HTTPException(409,"Family ID already exists")
    return {"message":"Family created","family_id":d.id}
@app.get("/admin/families")
def admin_families(u=Depends(admin)): return rows("families")
@app.patch("/admin/families/{fid}")
def update_family(fid:str,d:Family,u=Depends(admin)):
    if not one("families", id=fid): raise HTTPException(404,"Family not found")
    sb.table("families").update({"id":d.id,"name":d.name,"description":d.description,"icon":d.icon,"photo":d.photo,"active":d.active}).eq("id",fid).execute()
    if d.id!=fid: sb.table("family_members").update({"family_id":d.id}).eq("family_id",fid).execute()
    return {"message":"Family updated"}
@app.delete("/admin/families/{fid}")
def delete_family(fid:str,u=Depends(admin)):
    if not one("families", id=fid): raise HTTPException(404,"Family not found")
    sb.table("family_members").update({"active":False}).eq("family_id",fid).execute()
    sb.table("families").delete().eq("id",fid).execute()
    return {"message":"Family deleted"}

@app.post("/admin/events")
def create_event(d:Event,u=Depends(admin)):
    r=sb.table("events").insert({"title":d.title,"description":d.description,"date":d.date,"location":d.location,"photo":d.photo,"active":d.active,"created_at":now().isoformat()}).execute()
    return {"message":"Event created","event_id":r.data[0]["id"]}
@app.get("/admin/events")
def admin_events(u=Depends(admin)): return rows("events")
@app.patch("/admin/events/{eid}")
def update_event(eid:int,d:Event,u=Depends(admin)):
    if not one("events", id=eid): raise HTTPException(404,"Event not found")
    sb.table("events").update({"title":d.title,"description":d.description,"date":d.date,"location":d.location,"photo":d.photo,"active":d.active}).eq("id",eid).execute()
    return {"message":"Event updated"}
@app.delete("/admin/events/{eid}")
def delete_event(eid:int,u=Depends(admin)):
    if not one("events", id=eid): raise HTTPException(404,"Event not found")
    sb.table("event_photos").delete().eq("event_id",eid).execute()
    sb.table("events").delete().eq("id",eid).execute()
    return {"message":"Event deleted"}
@app.post("/admin/events/{eid}/photos")
def add_event_photo(eid:int,d:EventPhoto,u=Depends(admin)):
    require_image(d.image_data)
    if not one("events", id=eid): raise HTTPException(404,"Event not found")
    r=sb.table("event_photos").insert({"event_id":eid,"image_data":d.image_data,"caption":d.caption,"created_at":now().isoformat()}).execute()
    return {"message":"Event photo uploaded","photo_id":r.data[0]["id"]}
@app.get("/admin/events/{eid}/photos")
def admin_event_photos(eid:int,u=Depends(admin)): return rows("event_photos", event_id=eid)
@app.delete("/admin/event-photos/{pid}")
def delete_event_photo(pid:int,u=Depends(admin)):
    if not one("event_photos", id=pid): raise HTTPException(404,"Event photo not found")
    sb.table("event_photos").delete().eq("id",pid).execute(); return {"message":"Event photo deleted"}

@app.post("/admin/users")
def create_user(d:NewUser,u=Depends(admin)):
    try:
        r=sb.table("users").insert({"username":d.username.strip(),"password_hash":hp(d.password),"role":"family","family_id":d.family_id.strip(),"active":True,"created_at":now().isoformat()}).execute()
    except Exception: raise HTTPException(409,"Username already exists")
    return {"message":"Family account created","user_id":r.data[0]["id"],"username":d.username,"family_id":d.family_id}
@app.get("/admin/users")
def users(u=Depends(admin)): return [{k:x.get(k) for k in ["id","username","role","family_id","active","created_at"]} for x in rows("users")]
@app.post("/admin/users/{uid}/disable")
def disable(uid:int,u=Depends(admin)):
    sb.table("users").update({"active":False}).eq("id",uid).neq("role","admin").execute()
    sb.table("sessions").delete().eq("user_id",uid).execute(); return {"message":"User disabled"}
@app.post("/admin/private-profile")
def save_private(d:Private,u=Depends(admin)):
    data={"user_id":d.user_id,"mobile":d.mobile,"email":d.email,"address":d.address,"birthday":d.birthday,"education":d.education,"profession":d.profession,"notes":d.notes}
    if one("private_profiles", user_id=d.user_id): sb.table("private_profiles").update({k:v for k,v in data.items() if k!="user_id"}).eq("user_id",d.user_id).execute()
    else: sb.table("private_profiles").insert(data).execute()
    return {"message":"Private profile saved"}

@app.get("/admin/members")
def members(u=Depends(admin)): return rows("family_members")
@app.post("/admin/members")
def create_member(d:Member,u=Depends(admin)):
    data=d.model_dump(); data["active"]=True; data["created_at"]=now().isoformat()
    r=sb.table("family_members").insert(data).execute(); return {"message":"Family member created","member_id":r.data[0]["id"]}
@app.patch("/admin/members/{mid}")
def update_member(mid:int,d:Member,u=Depends(admin)):
    if not one("family_members", id=mid): raise HTTPException(404,"Member not found")
    sb.table("family_members").update(d.model_dump()).eq("id",mid).execute(); return {"message":"Family member updated"}
@app.delete("/admin/members/{mid}")
def delete_member(mid:int,u=Depends(admin)):
    if not one("family_members", id=mid): raise HTTPException(404,"Member not found")
    sb.table("family_members").delete().eq("id",mid).execute(); return {"message":"Family member deleted"}

@app.get("/admin/media")
def admin_media(u=Depends(admin)): return rows("site_media")
@app.post("/admin/media")
def create_media(d:Media,u=Depends(admin)):
    require_image(d.image_data)
    sb.table("site_media").update({"active":False}).eq("slot",d.slot).execute()
    r=sb.table("site_media").insert({"slot":d.slot,"image_data":d.image_data,"caption":d.caption,"active":d.active,"created_at":now().isoformat()}).execute()
    return {"message":"Photo uploaded","media_id":r.data[0]["id"]}
@app.patch("/admin/media/{mid}")
def update_media(mid:int,d:Media,u=Depends(admin)):
    require_image(d.image_data)
    if not one("site_media", id=mid): raise HTTPException(404,"Photo not found")
    sb.table("site_media").update({"active":False}).eq("slot",d.slot).neq("id",mid).execute()
    sb.table("site_media").update({"slot":d.slot,"image_data":d.image_data,"caption":d.caption,"active":d.active}).eq("id",mid).execute()
    return {"message":"Photo updated"}
@app.delete("/admin/media/{mid}")
def delete_media(mid:int,u=Depends(admin)):
    if not one("site_media", id=mid): raise HTTPException(404,"Photo not found")
    sb.table("site_media").delete().eq("id",mid).execute(); return {"message":"Photo deleted"}
