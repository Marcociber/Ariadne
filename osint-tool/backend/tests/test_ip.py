"""
IP module: the offline MaxMind GeoLite2 source and the accuracy radius.

No real .mmdb ships with the tests, so the readers are faked. What matters is
the contract the module relies on:

  * a lookup maps the geoip2 City/ASN structure to the normalized record used
    by the consensus, and carries MaxMind's accuracy radius;
  * a stated radius surfaces as an explicit "Accuracy radius" finding, so a
    city-level fix is never presented as an exact address;
  * with no database configured the source is simply absent — the free,
    offline-by-default setup keeps working.
"""

from types import SimpleNamespace as NS

import geoip2.errors

import app.modules.ip_module as ipm
from app.modules.ip_module import IPModule


def _fake_city(**over):
    """Minimal stand-in for a geoip2.models.City record."""
    base = {
        "country": NS(name="Spain", iso_code="ES"),
        "subdivisions": NS(most_specific=NS(name="Community of Madrid")),
        "city": NS(name="Madrid"),
        "postal": NS(code="28013"),
        "location": NS(latitude=40.4168, longitude=-3.7038, time_zone="Europe/Madrid", accuracy_radius=20),
    }
    base.update(over)
    return NS(**base)


class _FakeCityReader:
    def __init__(self, record):
        self._record = record

    def city(self, ip):
        if self._record is None:
            raise geoip2.errors.AddressNotFoundError(f"{ip} not found")
        return self._record


class _FakeASNReader:
    def asn(self, ip):
        return NS(autonomous_system_number=3352, autonomous_system_organization="TELEFONICA DE ESPANA")


async def test_maxmind_lookup_maps_record_and_carries_radius(monkeypatch):
    monkeypatch.setattr(ipm, "_get_geoip_readers", lambda: (_FakeCityReader(_fake_city()), _FakeASNReader()))
    rec = await IPModule()._from_maxmind(None, "88.28.0.1")

    assert rec is not None
    assert rec["source"] == "MaxMind GeoLite2"
    assert rec["city"] == "Madrid"
    assert rec["country_code"] == "ES"
    assert rec["accuracy_radius"] == 20
    assert rec["asn"].startswith("AS3352")


async def test_maxmind_absent_when_no_database_configured(monkeypatch):
    monkeypatch.setattr(ipm, "_get_geoip_readers", lambda: (None, None))
    assert await IPModule()._from_maxmind(None, "88.28.0.1") is None


async def test_address_not_in_database_is_not_an_error(monkeypatch):
    # City miss + no ASN reader -> nothing to report, but no exception either.
    monkeypatch.setattr(ipm, "_get_geoip_readers", lambda: (_FakeCityReader(None), None))
    assert await IPModule()._from_maxmind(None, "203.0.113.7") is None


async def test_accuracy_radius_becomes_a_finding(monkeypatch):
    """With every HTTP provider silent, MaxMind alone must yield the radius."""

    async def _silent(self, client, ip):
        return None

    async def _maxmind(self, client, ip):
        return _fake_city_record()

    monkeypatch.setattr(IPModule, "_from_ipapi", _silent)
    monkeypatch.setattr(IPModule, "_from_ipwho", _silent)
    monkeypatch.setattr(IPModule, "_from_geojs", _silent)
    monkeypatch.setattr(IPModule, "_from_rfg", _silent)
    monkeypatch.setattr(IPModule, "_from_maxmind", _maxmind)

    findings = await IPModule()._geolocate("88.28.0.1")
    radius = next((f for f in findings if f.label == "Accuracy radius (MaxMind)"), None)
    assert radius is not None
    assert "20 km" in radius.value
    # And the fix itself is still reported.
    assert any(f.label == "Coordinates" for f in findings)


def _fake_city_record():
    return {
        "source": "MaxMind GeoLite2",
        "country": "Spain",
        "country_code": "ES",
        "region": "Community of Madrid",
        "city": "Madrid",
        "postal": "28013",
        "lat": 40.4168,
        "lon": -3.7038,
        "timezone": "Europe/Madrid",
        "accuracy_radius": 20,
    }
