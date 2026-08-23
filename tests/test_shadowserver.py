"""Shadowserver report parsing.

The reports themselves cannot be tested against the real thing here — they
arrive only to a subscriber who has proven they control the address space, and
this build has no subscription. So these fixtures are built from Shadowserver's
published report schemas, and that limit is stated in `docs/` rather than
implied by green tests.

What IS tested properly: that a malformed file cannot discard a good one, that
an unparseable timestamp never becomes today's date, and that no row is ever
promoted to a determination.
"""
from __future__ import annotations

import pytest

from collect import shadowserver as ss

MEMCACHED = """timestamp,ip,protocol,port,hostname,tag,version,asn,geo
2026-08-22 03:11:04,198.51.100.7,udp,11211,cache-1.example.com,memcached,1.4.13,64500,IN
2026-08-22 03:11:09,198.51.100.8,udp,11211,,memcached,1.5.6,64500,IN
"""

RDP = """timestamp,ip,port,hostname,asn
2026-08-22 04:02:00,198.51.100.9,3389,jump.example.com,64500
"""


# ── parsing ─────────────────────────────────────────────────────────────────
def test_a_report_parses_to_rows():
    rows = ss.parse("scan_memcached", MEMCACHED)
    assert len(rows) == 2
    assert rows[0].address == "198.51.100.7"
    assert rows[0].port == 11211
    assert rows[0].observed_on == "2026-08-22"
    assert rows[0].hostname == "cache-1.example.com"
    assert rows[0].version == "1.4.13"


def test_the_report_type_is_required_because_it_carries_the_reason():
    """'This host answers on 11211' is not useful. 'It is in the open-memcached
    report' is."""
    with pytest.raises(ss.ReportUnreadable):
        ss.parse("", MEMCACHED)


def test_the_report_type_is_carried_onto_every_row():
    assert all(r.report == "scan_memcached"
               for r in ss.parse("scan_memcached", MEMCACHED))


def test_unknown_columns_are_carried_rather_than_dropped():
    """76 report types exist and they differ wildly. A field this build has
    never seen is likelier to be useful than to be noise."""
    row = ss.parse("scan_memcached", MEMCACHED)[0]
    assert row.extra["asn"] == "64500"
    assert row.extra["geo"] == "IN"


def test_an_empty_report_is_empty_not_an_error():
    """A quiet day is a result. Shadowserver sends reports with no rows."""
    assert ss.parse("scan_memcached", "") == []


def test_a_header_only_report_yields_no_rows():
    assert ss.parse("scan_rdp", "timestamp,ip,port\n") == []


def test_the_wrong_file_is_refused_rather_than_parsed_to_zero_rows():
    """A CSV with no address column is not a sparse report, it is the wrong
    file — and "parsed fine, found nothing" is exactly how that reads as an
    estate with no exposure. Caught from the HEADER, before any row.

    An earlier version of this test asserted the opposite of its own docstring
    and passed anyway, which is how the gap it describes stayed open.
    """
    with pytest.raises(ss.ReportUnreadable, match="no address column"):
        ss.parse("scan_rdp", "invoice_no,amount,currency\n1,20,GBP\n")


def test_a_row_with_no_address_is_skipped_not_guessed():
    rows = ss.parse("scan_rdp", "timestamp,ip,port\n2026-08-22 04:02:00,,3389\n")
    assert rows == []


def test_a_non_numeric_port_becomes_none_rather_than_raising():
    rows = ss.parse("scan_rdp",
                    "timestamp,ip,port\n2026-08-22 04:02:00,198.51.100.9,n/a\n")
    assert rows[0].port is None


@pytest.mark.parametrize("column", ["ip", "src_ip", "address"])
def test_the_several_spellings_of_the_address_column_all_work(column):
    """Report types spell the same idea differently; assuming one is how this
    silently returns zero rows for half the subscription."""
    rows = ss.parse("x", f"timestamp,{column},port\n"
                         f"2026-08-22 04:02:00,198.51.100.9,3389\n")
    assert rows and rows[0].address == "198.51.100.9"


# ── dates ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("stamp,expected", [
    ("2026-08-22 03:11:04", "2026-08-22"),
    ("2026-08-22T03:11:04", "2026-08-22"),
    ("2026-08-22", "2026-08-22"),
])
def test_timestamp_formats(stamp, expected):
    assert ss._as_date(stamp) == expected


def test_an_unparseable_timestamp_is_empty_not_today():
    """Substituting today would claim a stale observation was made this
    morning, which is the one error that makes an old report look current."""
    assert ss._as_date("last tuesday") == ""
    assert ss._as_date("") == ""


def test_undated_rows_are_counted_in_the_summary():
    rows = ss.parse("scan_rdp",
                    "timestamp,ip,port\nnot-a-date,198.51.100.9,3389\n")
    assert ss.summarise(rows)["undated_rows"] == 1


# ── the refusal ─────────────────────────────────────────────────────────────
def test_a_row_is_an_observation_never_a_determination():
    """Better than a banner guess — a third party's direct, dated measurement —
    and still not a comparison against a published affected range."""
    observation = ss.parse("scan_memcached", MEMCACHED)[0].to_observation()
    assert "not a version comparison" in observation["basis"]
    assert "does not treat it as a determination" in observation["basis"]


def test_a_version_in_a_report_does_not_become_a_finding_field():
    """The report carries `1.4.13`. It is recorded as an observed version, with
    the same refusal `core/identity.py` makes about every observed version."""
    observation = ss.parse("scan_memcached", MEMCACHED)[0].to_observation()
    assert observation["version"] == "1.4.13"
    assert "basis" in observation


# ── several reports at once ─────────────────────────────────────────────────
def test_one_bad_report_does_not_discard_the_good_ones():
    """The same rule `core/inventory.py` follows: rejects are RETURNED."""
    result = ss.parse_many({"scan_memcached": MEMCACHED, "": RDP})
    assert len(result["rows"]) == 2
    assert result["summary"]["failed_reports"]


def test_a_failure_is_returned_rather_than_raised():
    result = ss.parse_many({"": "whatever"})
    assert result["rows"] == []
    assert "" in result["summary"]["failed_reports"]


def test_the_summary_counts_by_report_type():
    result = ss.parse_many({"scan_memcached": MEMCACHED, "scan_rdp": RDP})
    assert result["summary"]["reports"] == {"scan_memcached": 2, "scan_rdp": 1}
    assert result["summary"]["addresses"] == 3


def test_the_summary_dates_the_window():
    summary = ss.summarise(ss.parse("scan_memcached", MEMCACHED))
    assert summary["observed_from"] == "2026-08-22"
    assert summary["observed_to"] == "2026-08-22"


def test_the_summary_says_what_it_does_not_cover():
    """An empty report is not an estate with no exposure. It is an estate
    Shadowserver was not asked about."""
    text = ss.summarise([])["covers"]
    assert "proven to Shadowserver" in text
    assert "not an estate with no exposure" in text
    assert "supplier" in text


# ── it performs no I/O, deliberately ────────────────────────────────────────
def test_this_module_declares_no_network_boundary():
    """It is a PARSER. Shadowserver delivers by download link or e-mail to a
    subscriber; there is no API to poll and no credential SKOPOS could hold, so
    a marker here would claim an egress path that does not exist."""
    import pathlib
    source = pathlib.Path(ss.__file__).read_text(encoding="utf-8")
    assert "# NETWORK-BOUNDARY:" not in source
    for forbidden in ("urllib.request", "egress.http_get", "socket."):
        assert forbidden not in source, forbidden


def test_subscription_is_documented_as_a_human_act():
    assert ss.SUBSCRIPTION["to"].endswith("@shadowserver.org")
    assert "control" in ss.SUBSCRIPTION["include"]
    assert "no public API" in ss.SUBSCRIPTION["why_not_automated"]
