"""
Automatically detect which target type the user entered.
"""
import re

from .models import TargetType

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Dominio: algo.tld (sin @, sin espacios, con al menos un punto)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$"
)
# Phone: optional +, digits, spaces, dashes and parentheses
PHONE_RE = re.compile(r"^\+?[\d\s\-()]{7,}$")


def detect_type(target: str) -> TargetType:
    t = target.strip()

    if EMAIL_RE.match(t):
        return TargetType.EMAIL

    # A phone number: mostly digits and phone characters
    digits = sum(c.isdigit() for c in t)
    if PHONE_RE.match(t) and digits >= 7:
        return TargetType.PHONE

    if DOMAIN_RE.match(t):
        return TargetType.DOMAIN

    # Username: alphanumeric + . _ - without dots forming a domain
    if re.match(r"^[a-zA-Z0-9._-]{2,40}$", t):
        return TargetType.USERNAME

    return TargetType.UNKNOWN
