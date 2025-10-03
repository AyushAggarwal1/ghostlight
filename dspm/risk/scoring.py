from __future__ import annotations

from typing import Dict, List, Tuple

from dspm.core.models import Detection


SENSITIVITY_WEIGHTS: Dict[str, int] = {
    # GDPR - PII
    "PII.Email": 5,
    "PII.Phone": 5,
    "PII.SSN": 15,
    "PII.Aadhaar": 10,
    "PII.PAN": 8,
    "PII.Passport": 12,
    "PII.DriverLicense": 8,
    "PII.IBAN": 10,
    "PII.IPv4": 2,
    "PII.IPv6": 2,
    "PII.Coordinates": 3,
    # HIPAA - PHI
    "PHI.MRN": 10,
    "PHI.NPI": 8,
    "PHI.MedicareID": 12,
    "PHI.MedicalRecord": 15,
    # PCI
    "PCI.CreditCard": 15,
    # SECRETS
    "Secrets.AWS.AccessKeyID": 15,
    "Secrets.AWS.SecretAccessKey": 20,
    "Secrets.AWS.MWSAuthToken": 12,
    "Secrets.Google.APIKey": 10,
    "Secrets.Slack.BotToken": 10,
    "Secrets.GitHub.Token": 12,
    "Secrets.RSA.PrivateKey": 20,
    "Secrets.OpenSSH.PrivateKey": 20,
    "Secrets.PGP.PrivateKey": 20,
    "Secrets.Database.ConnectionString": 15,
    "Secrets.Generic.BearerToken": 10,
}


def compute_sensitivity_score(detections: List[Detection]) -> Tuple[int, List[str]]:
    score = 0
    factors: List[str] = []
    for det in detections:
        weight = SENSITIVITY_WEIGHTS.get(det.pattern_name, 5)
        inc = weight * max(1, len(det.matches))
        score += inc
        factors.append(f"{det.pattern_name} x{len(det.matches)} (+{inc})")
    # Cap
    score = min(score, 100)
    return score, factors


def compute_exposure_factor(data_source: str | None, metadata: Dict[str, str]) -> Tuple[int, List[str]]:
    # Return exposure score 0-100 and factors
    if not data_source:
        return 10, ["unknown source"]
    factors: List[str] = []
    score = 10
    if data_source == "s3":
        is_public = metadata.get("bucket_public") == "true"
        sse = metadata.get("sse") or metadata.get("bucket_encryption")
        if is_public:
            score += 60
            factors.append("public bucket")
        if not sse:
            score += 20
            factors.append("no encryption")
    elif data_source == "git":
        score += 30
        factors.append("repository content")
    elif data_source == "filesystem":
        score += 10
        factors.append("local file")
    else:
        score += 20
        factors.append(f"{data_source} default exposure")
    return min(score, 100), factors


def compute_risk(sensitivity: int, exposure: int) -> Tuple[int, str]:
    # Weighted average favoring sensitivity
    risk = int(0.6 * sensitivity + 0.4 * exposure)
    if risk >= 75:
        level = "critical"
    elif risk >= 50:
        level = "high"
    elif risk >= 25:
        level = "medium"
    else:
        level = "low"
    return risk, level


