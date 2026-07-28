"""
Phone module: 100% offline (Google's phonenumbers), so it needs no mocks.
"""

from app.modules.phone_module import PhoneModule


def values(findings, label):
    return [f.value for f in findings if f.label == label]


async def test_valid_spanish_mobile():
    findings = await PhoneModule()._run("+34612345678")
    assert values(findings, "Valid") == ["Yes"]
    assert values(findings, "E.164 format") == ["+34612345678"]
    assert values(findings, "Line type") == ["Mobile"]
    assert any("ES" in v for v in values(findings, "Country code"))


async def test_number_without_plus_is_accepted():
    findings = await PhoneModule()._run("34612345678")
    assert values(findings, "E.164 format") == ["+34612345678"]


async def test_invalid_number_stops_early():
    findings = await PhoneModule()._run("+34000")
    assert values(findings, "Valid") == ["No"]
    # Nothing beyond the validity verdict should be invented.
    assert not values(findings, "E.164 format")


async def test_mobile_offers_whatsapp_and_telegram_pivots():
    labels = [f.label for f in await PhoneModule()._run("+34612345678")]
    assert "Check on WhatsApp" in labels
    assert "Check on Telegram" in labels


async def test_landline_does_not_offer_mobile_pivots():
    """A fixed line cannot be on WhatsApp, so the pivot is not offered."""
    findings = await PhoneModule()._run("+34915550000")
    labels = [f.label for f in findings]
    assert values(findings, "Line type") == ["Fixed"]
    assert "Check on WhatsApp" not in labels


async def test_carrier_is_reported_with_low_confidence():
    """Portability makes the carrier database unreliable; it must say so."""
    carrier = [f for f in await PhoneModule()._run("+34612345678") if f.category == "carrier"]
    for finding in carrier:
        assert finding.confidence <= 0.6
        assert "portability" in finding.label.lower()


async def test_pivots_are_only_constructed_never_queried():
    pivots = [f for f in await PhoneModule()._run("+34612345678") if f.category == "pivot"]
    assert pivots
    assert all(f.value.startswith("https://") for f in pivots)
