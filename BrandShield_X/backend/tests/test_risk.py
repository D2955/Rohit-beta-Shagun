from app.risk import assess, fingerprint, similarity

def test_similarity_identical():
    assert similarity("northstar", "northstar") == 100

def test_fingerprint_is_stable():
    assert fingerprint("Northstar Pay") == fingerprint("northstar pay")

def test_assess_returns_explainable_fields():
    result = assess("Northstar Pay Support", "social", "social", "", "northstar-login.example",
        "urgent verify your wallet", {"name":"Northstar Pay","aliases":["Northstar"],"official_domains":["northstarpay.example"]})
    assert 0 <= result["risk_score"] <= 100
    assert result["severity"] in {"LOW","MEDIUM","HIGH","CRITICAL"}
    assert result["reasons_json"] and result["evidence_json"]
