import json
from sqlalchemy.orm import Session
from .models import Organization, User, Brand, Threat
from .security import hash_password
from .risk import assess, fingerprint

def seed(db: Session):
    if db.query(Organization).filter_by(name="Demo Security Lab").first():
        return
    org = Organization(name="Demo Security Lab")
    db.add(org); db.flush()
    user = User(email="demo@brandshield.local", password_hash=hash_password("DemoPass123!"), role="SECURITY_ADMIN", organization_id=org.id)
    db.add(user); db.flush()
    brand = Brand(organization_id=org.id, name="Northstar Pay", website="https://northstarpay.example",
        aliases_json=json.dumps(["Northstar", "Northstar Payments"]),
        official_domains_json=json.dumps(["northstarpay.example"]),
        official_social_json=json.dumps(["https://social.example/northstarpay"]),
        official_apps_json=json.dumps(["com.northstar.pay"]),
        identity_fingerprint=fingerprint("Northstar Pay|northstarpay.example"))
    db.add(brand); db.flush()
    records = [
        ("social","Social Network","Northstar Pay Support 24","https://social.example/northstarpay_help","northstar-pay-verify.example","Urgent support account. Verify your wallet now."),
        ("domain","Domain Intelligence","northstarpay-login","https://northstarpay-login.example","northstarpay-login.example","Login verification portal"),
        ("app","App Store","Northstar Wallet Support","https://apps.example/northstar-support","com.northstar.wallet.support","Unofficial app metadata submitted for review"),
        ("social","Social Network","Northstar Community Fans","https://social.example/northstar_fans","northstarpay.example","Fan community; not claiming official status"),
        ("domain","Domain Intelligence","northstarpay.example","https://northstarpay.example","northstarpay.example","Registered official domain demo record")
    ]
    for i, (typ, platform, name, url, domain, desc) in enumerate(records):
        values = assess(name, typ, platform, url, domain, desc, {"name":brand.name,"aliases":json.loads(brand.aliases_json),"official_domains":json.loads(brand.official_domains_json)})
        status = "NEW"
        if i == 3: values["risk_score"], values["severity"], values["confidence"] = 18, "LOW", 46
        if i == 4: values["risk_score"], values["severity"], values["confidence"] = 4, "LOW", 90
        db.add(Threat(organization_id=org.id, brand_id=brand.id, asset_type=typ, platform=platform, asset_name=name, asset_url=url, domain=domain, description=desc, status=status, campaign_key="NSP-CAMPAIGN-001" if i in (0,1,2) else "", is_demo=True, **values))
    db.commit()
