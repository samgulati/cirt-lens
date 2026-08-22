"""Authentication and tenant-scoped RBAC with local and OIDC-compatible JWTs."""
from dataclasses import dataclass
from datetime import datetime,timedelta,UTC
import base64,hashlib,hmac,os,uuid
import jwt
from fastapi import Depends,HTTPException,Request
from sqlalchemy.orm import Session
from .config import settings
from .database import get_db
from .models import Tenant,UserAccount

ROLE_LEVEL={"VIEWER":0,"ANALYST":1,"RESPONDER":2,"ADMINISTRATOR":3}
@dataclass(frozen=True)
class Principal:
    user_id:str;tenant_id:str;email:str;role:str

def hash_password(password,salt=None):
    salt=salt or os.urandom(16);digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,210_000);return f"pbkdf2_sha256$210000${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"
def verify_password(password,encoded):
    _,rounds,salt,digest=encoded.split("$");actual=hashlib.pbkdf2_hmac("sha256",password.encode(),base64.b64decode(salt),int(rounds));return hmac.compare_digest(actual,base64.b64decode(digest))
def issue_token(user):
    now=datetime.now(UTC);claims={"sub":user.id,"tenant_id":user.tenant_id,"email":user.email,"role":user.role,"aud":settings.oidc_audience,"iat":now,"exp":now+timedelta(hours=8),"iss":settings.oidc_issuer or "cirt-lens-local"};return jwt.encode(claims,settings.auth_secret,algorithm="HS256")
def seed_identity(db):
    now=datetime.now(UTC).replace(tzinfo=None)
    if not db.get(Tenant,settings.default_tenant_id):db.add(Tenant(id=settings.default_tenant_id,name="CIRT Lens Demo Organization",created_at=now))
    demos=[("viewer@demo.local","Viewer","VIEWER"),("analyst@demo.local","Analyst","ANALYST"),("responder@demo.local","Responder","RESPONDER"),("admin@demo.local","Administrator","ADMINISTRATOR")]
    for email,name,role in demos:
        if not db.query(UserAccount).filter_by(tenant_id=settings.default_tenant_id,email=email).first():db.add(UserAccount(id=f"USR-{uuid.uuid4().hex[:10].upper()}",tenant_id=settings.default_tenant_id,email=email,display_name=name,role=role,password_hash=hash_password("DemoPass!2026"),active=True,created_at=now))
    db.commit()
def current_principal(request:Request,db:Session=Depends(get_db)):
    header=request.headers.get("authorization","")
    if not header.startswith("Bearer "):
        if settings.auth_required:raise HTTPException(401,"Authentication required")
        return Principal("USR-DEMO",settings.default_tenant_id,"analyst@demo","ADMINISTRATOR")
    try:
        token=header[7:]
        if settings.auth_mode=="oidc":
            if not settings.oidc_issuer or not settings.oidc_jwks_url:raise ValueError("OIDC issuer and JWKS URL are required")
            signing_key=jwt.PyJWKClient(settings.oidc_jwks_url).get_signing_key_from_jwt(token).key
            claims=jwt.decode(token,signing_key,algorithms=["RS256","ES256"],audience=settings.oidc_audience,issuer=settings.oidc_issuer)
        else:
            claims=jwt.decode(token,settings.auth_secret,algorithms=["HS256"],audience=settings.oidc_audience,issuer=settings.oidc_issuer or "cirt-lens-local")
        return Principal(claims["sub"],claims["tenant_id"],claims["email"],claims["role"])
    except Exception as exc:raise HTTPException(401,"Invalid or expired access token") from exc
def require_role(minimum):
    def dependency(principal:Principal=Depends(current_principal)):
        if ROLE_LEVEL.get(principal.role,-1)<ROLE_LEVEL[minimum]:raise HTTPException(403,f"{minimum} role required")
        return principal
    return dependency
