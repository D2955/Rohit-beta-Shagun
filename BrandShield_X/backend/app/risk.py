import json, re, hashlib
from difflib import SequenceMatcher
from urllib.parse import urlparse

SUSPICIOUS_TERMS = ("support", "verify", "login", "secure", "claim", "wallet", "urgent", "official", "free", "recovery")

def similarity(a: str, b: str) -> int:
    return round(SequenceMatcher(None, (a or "").lower(), (b or "").lower()).ratio() * 100)

def assess(asset_name: str, asset_type: str, platform: str, url: str, domain: str, description: str, brand: dict | None):
    reasons, evidence = [], []
    name = asset_name.lower()
    official_name = (brand or {}).get("name", "")
    aliases = (brand or {}).get("aliases", [])
    name_scores = [similarity(name, official_name)] + [similarity(name, x) for x in aliases if x]
    identity = max(name_scores or [0])
    if official_name and identity >= 65 and name != official_name.lower():
        reasons.append(f"Name resembles registered brand ({identity}% similarity)")
        evidence.append({"id":"SIG-IDENTITY-01","type":"identity","detail":f"Name similarity computed as {identity}%"})
    desc_lower = (description or "").lower()
    term_hits = [x for x in SUSPICIOUS_TERMS if x in desc_lower or x in name]
    social = min(100, len(term_hits) * 22 + (18 if "support" in name else 0))
    if term_hits:
        reasons.append("Potentially sensitive terms: " + ", ".join(term_hits[:5]))
        evidence.append({"id":"SIG-LANGUAGE-01","type":"language","detail":"Matched terms: " + ", ".join(term_hits[:5])})
    domain_score = 0
    host = (domain or "").lower().strip(".")
    if not host and url:
        host = (urlparse(url).hostname or "").lower()
    official_domains = [x.lower().replace("https://","").replace("http://","").split("/")[0] for x in (brand or {}).get("official_domains", [])]
    if host and official_domains and not any(host == d or host.endswith("." + d) for d in official_domains):
        domain_score = max(similarity(host.split(".")[0], d.split(".")[0]) for d in official_domains)
        domain_score = max(domain_score, 55 if any(t in host for t in ("login","verify","support","secure")) else 0)
        reasons.append(f"Domain differs from registered official domains ({host})")
        evidence.append({"id":"SIG-DOMAIN-01","type":"domain","detail":f"Submitted domain: {host}; this is a heuristic mismatch, not proof of abuse"})
    app = min(100, (35 if asset_type == "app" else 0) + (25 if asset_type == "app" and any(x in name for x in ("support","wallet","secure")) else 0))
    score = round(min(100, identity * .38 + domain_score * .27 + social * .20 + app * .15))
    confidence = min(97, max(25, round((len(evidence) * 18) + score * .55)))
    severity = "CRITICAL" if score >= 85 else "HIGH" if score >= 65 else "MEDIUM" if score >= 40 else "LOW"
    if not reasons:
        reasons.append("No strong heuristic signals found; analyst review may still be required")
    evidence.append({"id":"SIG-SCORE-01","type":"risk-engine","detail":f"BrandShield heuristic engine v1.0 calculated score {score}/100"})
    return {"risk_score":score,"confidence":confidence,"severity":severity,"identity_risk":identity,"domain_risk":domain_score,"social_risk":social,"application_risk":app,"reasons_json":json.dumps(reasons),"evidence_json":json.dumps(evidence)}

def fingerprint(value: str) -> str:
    return hashlib.sha256((value or "").strip().lower().encode()).hexdigest()
