import csv, io, json, logging, os, secrets
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .config import settings
from .database import Base, engine, get_db
from .models import Organization, User, Brand, Threat, AuditLog
from .schemas import RegisterIn, LoginIn, BrandIn, ThreatIn, StatusIn, CopilotIn
from .security import hash_password, verify_password, create_token, current_user, require_admin
from .risk import assess, fingerprint
from .seed import seed

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("brandshield")
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title=settings.app_name, version="1.0.0", description="BrandShield X digital risk protection API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
origins = [x.strip() for x in settings.cors_origins.split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["GET","POST","PATCH","OPTIONS"], allow_headers=["Authorization","Content-Type","X-Request-ID"])

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api") else "no-cache"
    response.headers["X-Request-ID"] = request.headers.get("X-Request-ID", secrets.token_hex(8))
    return response

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    if settings.demo_mode:
        from .database import SessionLocal
        db = SessionLocal()
        try: seed(db)
        finally: db.close()

@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    db.execute(func.count(Organization.id).select())
    return {"status":"ok","database":"connected","mode":"demo" if settings.demo_mode else "standard","timestamp":datetime.now(timezone.utc).isoformat()}

def audit(db, user, action, resource="", result="success"):
    db.add(AuditLog(organization_id=user.organization_id, user_id=user.id, action=action, resource=resource, result=result))
    db.commit()

@app.post("/api/auth/register")
@limiter.limit("5/minute")
def register(request: Request, payload: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(func.lower(User.email)==payload.email.lower()).first():
        raise HTTPException(409, "Email already registered")
    org = Organization(name=payload.organization_name.strip())
    db.add(org)
    try: db.flush()
    except Exception:
        db.rollback(); raise HTTPException(409, "Organization name may already be in use")
    user = User(email=payload.email.lower(), password_hash=hash_password(payload.password), role="SECURITY_ADMIN", organization_id=org.id)
    db.add(user); db.commit(); db.refresh(user)
    return {"access_token":create_token(user),"token_type":"bearer","user":{"email":user.email,"role":user.role,"organization":org.name}}

@app.post("/api/auth/login")
@limiter.limit("10/minute")
def login(request: Request, payload: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(func.lower(User.email)==payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Incorrect email or password")
    audit(db, user, "login", "session")
    return {"access_token":create_token(user),"token_type":"bearer","user":{"id":user.id,"email":user.email,"role":user.role,"organization_id":user.organization_id}}

@app.get("/api/auth/me")
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    org = db.get(Organization, user.organization_id)
    return {"id":user.id,"email":user.email,"role":user.role,"organization":org.name if org else "Unknown"}

@app.get("/api/brands")
def list_brands(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [{"id":b.id,"name":b.name,"website":b.website,"aliases":json.loads(b.aliases_json),"official_domains":json.loads(b.official_domains_json),"official_social_accounts":json.loads(b.official_social_json),"official_apps":json.loads(b.official_apps_json),"fingerprint":b.identity_fingerprint} for b in db.query(Brand).filter_by(organization_id=user.organization_id).all()]

@app.post("/api/brands")
def create_brand(payload: BrandIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    b = Brand(organization_id=user.organization_id,name=payload.name.strip(),website=payload.website,
        aliases_json=json.dumps(payload.aliases),official_domains_json=json.dumps(payload.official_domains),
        official_social_json=json.dumps(payload.official_social_accounts),official_apps_json=json.dumps(payload.official_apps),
        identity_fingerprint=fingerprint(payload.name+"|"+payload.website+"|"+"|".join(payload.official_domains)))
    db.add(b); db.commit(); db.refresh(b); audit(db,user,"brand_created",str(b.id))
    return {"id":b.id,"name":b.name,"fingerprint":b.identity_fingerprint,"message":"Digital Brand Twin created"}

def threat_dict(t):
    return {"id":t.id,"organization_id":t.organization_id,"brand_id":t.brand_id,"asset_type":t.asset_type,"platform":t.platform,"asset_name":t.asset_name,"asset_url":t.asset_url,"domain":t.domain,"description":t.description,"risk_score":t.risk_score,"confidence":t.confidence,"identity_risk":t.identity_risk,"domain_risk":t.domain_risk,"social_risk":t.social_risk,"application_risk":t.application_risk,"severity":t.severity,"status":t.status,"reasons":json.loads(t.reasons_json),"evidence":json.loads(t.evidence_json),"campaign_key":t.campaign_key,"is_demo":t.is_demo,"created_at":t.created_at.isoformat() if t.created_at else None}

@app.get("/api/threats")
def list_threats(q: str = "", severity: str = "", asset_type: str = "", status: str = "", limit: int = 100, offset: int = 0, user: User = Depends(current_user), db: Session = Depends(get_db)):
    query = db.query(Threat).filter(Threat.organization_id==user.organization_id)
    if q: query = query.filter(or_(Threat.asset_name.ilike(f"%{q}%"),Threat.domain.ilike(f"%{q}%"),Threat.asset_url.ilike(f"%{q}%")))
    if severity: query = query.filter(Threat.severity==severity.upper())
    if asset_type: query = query.filter(Threat.asset_type==asset_type.lower())
    if status: query = query.filter(Threat.status==status.upper())
    limit = min(max(limit,1),200)
    return {"items":[threat_dict(t) for t in query.order_by(Threat.created_at.desc()).offset(max(0,offset)).limit(limit).all()],"limit":limit,"offset":offset}

@app.get("/api/threats/{threat_id}")
def get_threat(threat_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = db.query(Threat).filter_by(id=threat_id,organization_id=user.organization_id).first()
    if not t: raise HTTPException(404,"Threat not found")
    return threat_dict(t)

@app.post("/api/assets/analyze")
def analyze_asset(payload: ThreatIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = None
    if payload.brand_id:
        b = db.query(Brand).filter_by(id=payload.brand_id,organization_id=user.organization_id).first()
        if not b: raise HTTPException(404,"Brand not found in your organization")
        brand = {"name":b.name,"aliases":json.loads(b.aliases_json),"official_domains":json.loads(b.official_domains_json)}
    elif db.query(Brand).filter_by(organization_id=user.organization_id).first():
        b = db.query(Brand).filter_by(organization_id=user.organization_id).first()
        brand = {"name":b.name,"aliases":json.loads(b.aliases_json),"official_domains":json.loads(b.official_domains_json)}
        payload.brand_id = b.id
    result = assess(payload.asset_name,payload.asset_type,payload.platform,payload.asset_url,payload.domain,payload.description,brand)
    t = Threat(organization_id=user.organization_id,brand_id=payload.brand_id,asset_type=payload.asset_type,platform=payload.platform,asset_name=payload.asset_name,asset_url=payload.asset_url,domain=payload.domain,description=payload.description,status="NEW",is_demo=False,**result)
    db.add(t); db.commit(); db.refresh(t); audit(db,user,"asset_analyzed",str(t.id))
    return threat_dict(t)

@app.patch("/api/threats/{threat_id}/status")
def update_status(threat_id: int, payload: StatusIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = db.query(Threat).filter_by(id=threat_id,organization_id=user.organization_id).first()
    if not t: raise HTTPException(404,"Threat not found")
    t.status = payload.status; db.commit(); audit(db,user,"threat_status_changed",f"{t.id}:{t.status}")
    return threat_dict(t)

@app.post("/api/threats/{threat_id}/investigate")
def investigate(threat_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = db.query(Threat).filter_by(id=threat_id,organization_id=user.organization_id).first()
    if not t: raise HTTPException(404,"Threat not found")
    report = {"threat_id":t.id,"assessment":"Heuristic investigation completed using stored record and evidence signals.","risk_score":t.risk_score,"confidence":t.confidence,"severity":t.severity,"evidence":json.loads(t.evidence_json),"recommended_actions":["Preserve source URL and evidence","Verify against the official Brand Twin","Escalate to the security owner for review","Use the platform's authorized reporting process if confirmed"],"human_review_required":True,"model":"BrandShield Risk Engine v1.0"}
    audit(db,user,"threat_investigated",str(t.id))
    return report

@app.get("/api/dashboard/summary")
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Threat).filter_by(organization_id=user.organization_id).all()
    return {"total":len(rows),"critical":sum(t.severity=="CRITICAL" for t in rows),"high":sum(t.severity=="HIGH" for t in rows),"medium":sum(t.severity=="MEDIUM" for t in rows),"low":sum(t.severity=="LOW" for t in rows),"open":sum(t.status not in ("RESOLVED","FALSE_POSITIVE") for t in rows),"resolved":sum(t.status=="RESOLVED" for t in rows),"campaigns":len(set(t.campaign_key for t in rows if t.campaign_key)),"demo_records":sum(t.is_demo for t in rows),"items":[threat_dict(t) for t in sorted(rows,key=lambda x:x.risk_score,reverse=True)[:6]]}

@app.get("/api/campaigns")
def campaigns(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Threat).filter(Threat.organization_id==user.organization_id,Threat.campaign_key!="").all()
    groups = {}
    for t in rows:
        g = groups.setdefault(t.campaign_key,{"id":t.campaign_key,"assets":[],"max_risk":0,"severity":"LOW"})
        g["assets"].append({"id":t.id,"name":t.asset_name,"type":t.asset_type})
        g["max_risk"] = max(g["max_risk"],t.risk_score)
        if t.severity in ("CRITICAL","HIGH") or g["severity"]=="LOW": g["severity"]=t.severity
    return list(groups.values())

@app.post("/api/copilot/query")
def copilot(payload: CopilotIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = payload.question.lower()
    rows = db.query(Threat).filter(Threat.organization_id==user.organization_id).all()
    if "critical" in q: rows = [t for t in rows if t.severity=="CRITICAL"]
    elif "resolved" in q: rows = [t for t in rows if t.status=="RESOLVED"]
    elif "domain" in q: rows = [t for t in rows if t.asset_type=="domain" or t.domain]
    else: rows = sorted(rows,key=lambda x:x.risk_score,reverse=True)[:5]
    return {"answer":f"Based on {len(rows)} matching records in your organization's database, here are the relevant findings. This is a database-grounded rules-based copilot, not an external LLM.","results":[{"id":t.id,"name":t.asset_name,"severity":t.severity,"risk":t.risk_score,"status":t.status} for t in rows],"evidence_ids":[f"THREAT-{t.id}" for t in rows]}

@app.post("/api/assets/import")
async def import_csv(file: UploadFile = File(...), user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(415,"Upload a CSV file. Only CSV ingestion is enabled in this MVP.")
    content = await file.read(2_000_001)
    if len(content)>2_000_000: raise HTTPException(413,"CSV file must be smaller than 2 MB")
    try: text = content.decode("utf-8-sig"); reader = csv.DictReader(io.StringIO(text))
    except Exception: raise HTTPException(400,"Could not read CSV")
    required = {"asset_name"}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)): raise HTTPException(400,"CSV must include asset_name; optional columns: asset_type, platform, asset_url, domain, description")
    brand = db.query(Brand).filter_by(organization_id=user.organization_id).first()
    brand_dict = {"name":brand.name,"aliases":json.loads(brand.aliases_json),"official_domains":json.loads(brand.official_domains_json)} if brand else None
    created=0
    for row in reader:
        name=(row.get("asset_name") or "").strip()
        if not name: continue
        typ=(row.get("asset_type") or "social").strip().lower()
        if typ not in {"social","app","domain","website","other"}: typ="other"
        platform=(row.get("platform") or "CSV Import")[:80]
        url=(row.get("asset_url") or "")[:1000]; domain=(row.get("domain") or "")[:255]; desc=(row.get("description") or "")[:5000]
        score=assess(name,typ,platform,url,domain,desc,brand_dict)
        db.add(Threat(organization_id=user.organization_id,brand_id=brand.id if brand else None,asset_type=typ,platform=platform,asset_name=name,asset_url=url,domain=domain,description=desc,status="NEW",is_demo=False,**score)); created+=1
        if created>=500: break
    db.commit(); audit(db,user,"csv_import",f"{created} records")
    return {"imported":created,"message":"Imported records are heuristic assessments; review before acting."}

@app.get("/api/audit-logs")
def audit_logs(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [{"id":a.id,"action":a.action,"resource":a.resource,"result":a.result,"created_at":a.created_at.isoformat() if a.created_at else None} for a in db.query(AuditLog).filter_by(organization_id=user.organization_id).order_by(AuditLog.created_at.desc()).limit(100).all()]

@app.get("/api/reports/threats.csv")
def export_threats(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Threat).filter_by(organization_id=user.organization_id).order_by(Threat.created_at.desc()).all()
    def stream():
        out=io.StringIO(); writer=csv.writer(out); writer.writerow(["id","asset_name","asset_type","platform","url","domain","risk_score","confidence","severity","status","created_at"]); yield out.getvalue(); out.seek(0); out.truncate(0)
        for t in rows:
            writer.writerow([t.id,t.asset_name,t.asset_type,t.platform,t.asset_url,t.domain,t.risk_score,t.confidence,t.severity,t.status,t.created_at.isoformat() if t.created_at else ""])
            yield out.getvalue(); out.seek(0); out.truncate(0)
    return StreamingResponse(stream(),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=brandshield-threats.csv"})

@app.get("/")
def root():
    return {"name":"BrandShield X","message":"API online. Open /docs for interactive API documentation.","docs":"/docs"}
