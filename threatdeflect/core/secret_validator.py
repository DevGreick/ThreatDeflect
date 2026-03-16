import base64
import json
import logging
import re
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE
)
SHA256_PATTERN = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)
SHA1_PATTERN = re.compile(r'^[0-9a-f]{40}$', re.IGNORECASE)
MD5_PATTERN = re.compile(r'^[0-9a-f]{32}$', re.IGNORECASE)
HEX_ONLY_PATTERN = re.compile(r'^[0-9a-f]+$', re.IGNORECASE)

KNOWN_FAKE_AWS_KEYS = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "AKIAEXAMPLEKEY123456",
}

BASE62_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def validate_finding(finding: Dict[str, Any]) -> float:
    rule_type = finding.get("type", "")
    match_content = finding.get("match_content", "")
    confidence = finding.get("confidence", 0.5)

    validator = VALIDATORS.get(rule_type)
    if validator is None:
        return confidence

    adjusted = validator(match_content, confidence)
    return max(0.0, min(1.0, adjusted))


def _validate_aws_key(value: str, confidence: float) -> float:
    key = value.strip()
    if key.startswith("AKIA"):
        key_body = key[4:]
    else:
        prefix_match = re.match(r'AKIA[A-Z0-9]+', key)
        if prefix_match:
            key = prefix_match.group()
            key_body = key[4:]
        else:
            return confidence * 0.5

    if len(key) != 20:
        return confidence * 0.3

    if key in KNOWN_FAKE_AWS_KEYS:
        return 0.05

    if not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in key_body):
        return confidence * 0.4

    return confidence


def _validate_github_token(value: str, confidence: float) -> float:
    prefixes = ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")
    token = value.strip()
    matched_prefix: Optional[str] = None

    for p in prefixes:
        if token.startswith(p):
            matched_prefix = p
            break

    if matched_prefix is None:
        return confidence * 0.3

    body = token[len(matched_prefix):]
    if len(body) != 36:
        return confidence * 0.4

    if not all(c in BASE62_CHARS or c == '_' for c in body):
        return confidence * 0.5

    return confidence


def _validate_jwt(value: str, confidence: float) -> float:
    token = value.strip()
    parts = token.split('.')
    if len(parts) != 3:
        return confidence * 0.2

    try:
        header_raw = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header_bytes = base64.urlsafe_b64decode(header_raw)
        header = json.loads(header_bytes)
        if "alg" not in header:
            return confidence * 0.4
    except Exception:
        return confidence * 0.3

    try:
        payload_raw = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_raw)
        json.loads(payload_bytes)
    except Exception:
        return confidence * 0.4

    return confidence * 1.2


def _validate_high_entropy(value: str, confidence: float) -> float:
    cleaned = value.strip().strip("'\"")

    if UUID_PATTERN.match(cleaned):
        return 0.05
    if SHA256_PATTERN.match(cleaned):
        return 0.05
    if SHA1_PATTERN.match(cleaned):
        return 0.05
    if MD5_PATTERN.match(cleaned):
        return 0.05

    if HEX_ONLY_PATTERN.match(cleaned) and len(cleaned) in (32, 40, 64, 128):
        return 0.1

    if cleaned.startswith("0x") and HEX_ONLY_PATTERN.match(cleaned[2:]):
        return 0.1

    return confidence


def _validate_generic_api_key(value: str, confidence: float) -> float:
    cleaned = value.strip().strip("'\"")

    if len(cleaned) < 16:
        return confidence * 0.3

    if UUID_PATTERN.match(cleaned):
        return 0.1

    unique_chars = len(set(cleaned))
    if unique_chars < 6:
        return confidence * 0.2

    return confidence


VALIDATORS = {
    "AWS Key": _validate_aws_key,
    "GitHub Token": _validate_github_token,
    "JSON Web Token (JWT)": _validate_jwt,
    "High Entropy String": _validate_high_entropy,
    "Generic API Key": _validate_generic_api_key,
}
