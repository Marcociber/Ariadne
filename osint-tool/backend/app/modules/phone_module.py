"""
Phone module (free, no API key required):
uses Google's `phonenumbers` library to extract country, carrier,
timezone and line type. Fully offline.

Also generates OSINT pivot links (WhatsApp, Telegram, Truecaller,
web search) constructed from the number — without making any external
requests. They are starting points for manual follow-up.
"""
import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType


def _flag(region_code: str) -> str:
    """Convierte un código ISO alfa-2 (ej. 'ES') en su emoji de bandera."""
    if not region_code or len(region_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in region_code.upper())


@register
class PhoneModule(OSINTModule):
    name = "phone"
    supported_types = [TargetType.PHONE]

    LINE_TYPES = {
        phonenumbers.PhoneNumberType.MOBILE: "Mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed or mobile",
        phonenumbers.PhoneNumberType.VOIP: "VoIP",
        phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-free (0800)",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium-rate",
        phonenumbers.PhoneNumberType.SHARED_COST: "Shared-cost",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal number",
        phonenumbers.PhoneNumberType.PAGER: "Pager",
        phonenumbers.PhoneNumberType.UAN: "UAN (universal access)",
        phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
    }

    async def _run(self, target: str) -> list[Finding]:
        # phonenumbers necesita el número con prefijo internacional.
        num = target if target.strip().startswith("+") else "+" + target.strip()
        parsed = phonenumbers.parse(num, None)

        findings: list[Finding] = []

        # ¿Tiene una estructura posible en algún plan de numeración?
        possible = phonenumbers.is_possible_number(parsed)
        valid = phonenumbers.is_valid_number(parsed)
        findings.append(
            Finding(label="Valid", value="Yes" if valid else "No", category="phone")
        )
        if not valid:
            findings.append(Finding(
                label="Possible structure",
                value="Yes (plausible length but not assigned)" if possible else "No",
                category="phone",
            ))
            return findings

        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        region_code = phonenumbers.region_code_for_number(parsed) or ""

        # --- Identidad del número ---
        findings.append(Finding(label="E.164 format", value=e164, category="phone"))
        findings.append(Finding(
            label="International format",
            value=phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            category="phone",
        ))
        findings.append(Finding(
            label="National format",
            value=phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            category="phone",
        ))

        # --- Country / geography ---
        cc = parsed.country_code
        flag = _flag(region_code)
        country_val = f"+{cc}" + (f" · {region_code} {flag}".rstrip() if region_code else "")
        findings.append(Finding(label="Country code", value=country_val, category="phone"))

        region = geocoder.description_for_number(parsed, "en")
        if region:
            findings.append(Finding(label="Region / location", value=region, category="phone"))

        ntype = phonenumbers.number_type(parsed)
        mobile_capable = ntype in (
            phonenumbers.PhoneNumberType.MOBILE,
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE,
        )

        # The carrier DB is only reliable for mobile numbers and reflects
        # the ORIGINAL numbering block (not ported numbers). For fixed
        # lines it's often empty or incorrect, so we show it only for
        # mobiles and with low confidence.
        car = carrier.name_for_number(parsed, "en") if mobile_capable else ""
        if car:
            findings.append(Finding(
                label="Carrier (original block, no portability)",
                value=car, category="carrier", confidence=0.6))

        tzs = list(timezone.time_zones_for_number(parsed))
        for tz in tzs:
            findings.append(Finding(label="Timezone", value=tz, category="phone"))

        # --- Technical characteristics ---
        line_type = self.LINE_TYPES.get(ntype, "Unknown")
        findings.append(Finding(label="Line type", value=line_type, category="phone"))

        national = phonenumbers.national_significant_number(parsed)
        findings.append(Finding(
            label="National number", value=national, category="phone"))
        findings.append(Finding(
            label="Length (national)", value=str(len(national)), category="phone"))

        # --- OSINT pivot links (only constructed, not queried) ---
        from urllib.parse import quote

        digits = e164.lstrip("+")
        national_fmt = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

        pivots: list[tuple[str, str]] = []
        # WhatsApp and Telegram require a MOBILE number: it's pointless
        # to offer them for fixed lines, toll-free, incoming-only VoIP, etc.
        if mobile_capable:
            pivots.append(("Check on WhatsApp", f"https://wa.me/{digits}"))
            pivots.append(("Check on Telegram", f"https://t.me/+{digits}"))
        # Truecaller and web search apply to any valid number.
        pivots.append(("Check on Truecaller", f"https://www.truecaller.com/search/{region_code.lower() or 'intl'}/{national}"))
        pivots.append(("Reverse lookup (Sync.me)", f"https://sync.me/search/?number={quote(e164)}"))
        pivots.append(("Search on Facebook", f"https://www.facebook.com/search/top?q={quote(e164)}"))
        pivots.append(("Web search (E.164)", f"https://www.google.com/search?q={quote(chr(34) + e164 + chr(34))}"))
        pivots.append(("Web search (local format)", f"https://www.google.com/search?q={quote(chr(34) + national_fmt + chr(34))}"))

        for label, url in pivots:
            findings.append(Finding(label=label, value=url, category="pivot", confidence=0.5))

        return findings
