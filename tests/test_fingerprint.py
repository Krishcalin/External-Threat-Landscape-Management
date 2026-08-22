"""The step that connects discovery to scoring, and the ceilings on it.

The acceptance criterion for the whole of P1: a fingerprint written by this
product, round-tripped through an inventory CSV, must actually produce exposures
from `core/match.py`. Measured before any of this existed, CT discovery writes
`product="unknown"` and a 400-host estate yields ZERO findings.

Nothing here touches the network.
"""
from __future__ import annotations

import csv
import io
from datetime import date

import pytest

from collect import fingerprint as fp
from core import intel, inventory, match, signatures
from core.identity import Attestation, Fingerprint, FingerprintRun, IdentitySignal
from core.signatures import Signature, SignatureRejected

TODAY = date(2026, 8, 22)


@pytest.fixture(scope="module")
def catalogue():
    try:
        return intel.load().entries()
    except intel.IntelUnavailable as exc:      # pragma: no cover
        pytest.skip(str(exc))


def signal(source, value, attestation=Attestation.SELF_REPORTED, port=443):
    return IdentitySignal(source, value, attestation, port)


# -- the acceptance criterion ------------------------------------------------
def test_a_fingerprint_round_trips_into_exposures(catalogue, tmp_path):
    """Banner -> canonical product -> CSV -> Asset -> join. The whole chain."""
    run = FingerprintRun(fingerprints=[
        Fingerprint(
            host="vpn.example.com", product="Connect Secure", vendor="Ivanti",
            observed_version="9.1", attestation=Attestation.INFERRED,
            signals=[signal("tls.subject", "CN=vpn, O=Ivanti Connect Secure",
                            Attestation.INFERRED)],
            open_ports=(443,), probed_ports=(443, 80)),
    ])
    rows = fp.to_inventory_rows(run)

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    path = tmp_path / "fingerprinted.csv"
    path.write_text(buffer.getvalue(), encoding="utf-8")

    assets, rejected = inventory.load(path)
    assert not rejected, rejected
    exposures = match.match(assets, catalogue)
    assert exposures, "the whole point of P1: the join must fire"
    assert any(e.confidence.value == "strong" for e in exposures)


def test_the_unfingerprinted_baseline_really_is_zero(catalogue, tmp_path):
    """The measurement the design rests on, asserted so it cannot rot."""
    path = tmp_path / "ct.csv"
    path.write_text("identifier,product,version\n"
                    "a.example.com,unknown,\nb.example.com,unknown,\n",
                    encoding="utf-8")
    assets, _ = inventory.load(path)
    assert len(assets) == 2
    assert match.match(assets, catalogue) == []


# -- what gets written -------------------------------------------------------
def test_the_canonical_name_is_written_not_the_banner():
    """`Apache/2.4.54 (Ubuntu)` tokenises to {apache, ubuntu} — the distro
    token vetoes every match, so writing the banner yields nothing."""
    chosen, _ = signatures.identify([signal("http.server", "Apache/2.4.54 (Ubuntu)")])
    assert chosen is not None
    assert chosen.product == "Apache HTTP Server"
    assert chosen.vendor == "Apache"


def test_the_observed_version_never_reaches_the_version_field():
    """The structural refusal.

    engine.score_exposure marks NOT_AFFECTED as a VERSION_RANGE determination,
    which RETIRES a finding — so a spoofed high version would delete entries
    from the customer's worklist. `obs_version` is not in
    inventory.ALIASES['version'], so it cannot get there.
    """
    row = Fingerprint(host="h.example.com", product="Tomcat", vendor="Apache",
                      observed_version="99.0").inventory_row()
    assert row["obs_version"] == "99.0"
    assert "version" not in row
    assert "obsversion" not in inventory.ALIASES["version"]


def test_a_spoofed_version_does_not_become_a_determination(tmp_path):
    row = Fingerprint(host="h.example.com", product="Tomcat", vendor="Apache",
                      observed_version="99.0").inventory_row()
    path = tmp_path / "x.csv"
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    assets, _ = inventory.load(path)
    assert assets[0].version is None, \
        "a banner version must not populate the field a published range is " \
        "evaluated against"


def test_target_controlled_text_is_redacted_before_it_is_written():
    """A Server header is written by whoever owns the box."""
    row = Fingerprint(
        host="h.example.com", product="Tomcat", vendor="Apache",
        signals=[signal("http.server", "EvilWAF blocks cve-2021-44228")],
    ).inventory_row()
    assert "cve-2021-44228" not in row["obs_signals"].lower()
    from core.provenance import check_row
    check_row(row)          # must not raise


# -- unidentified vs unknown -------------------------------------------------
def test_probed_but_unmatched_is_not_the_same_as_never_probed():
    """`unknown` means never fingerprinted — run the fingerprinter.
    `unidentified` means probed and nothing fired — a different action."""
    probed = Fingerprint(host="h.example.com")
    assert probed.product == "unidentified"
    assert not probed.identified
    assert match.tokens("unidentified") == set(), "must not be able to join"
    assert match.tokens("unknown") == set()


def test_the_run_note_separates_identified_from_probed_unidentified():
    run = FingerprintRun(fingerprints=[
        Fingerprint(host="a.example.com", product="Tomcat", vendor="Apache"),
        Fingerprint(host="b.example.com"),
    ])
    note = run.note()
    assert "1 identified" in note
    assert "1 answered but matched no signature" in note


def test_an_exhausted_budget_names_what_was_not_attempted():
    """A run cut short and an estate with nothing exposed must not look alike."""
    run = FingerprintRun(fingerprints=[Fingerprint(host="a.example.com")],
                         unattempted=["b.example.com", "c.example.com"])
    note = run.note()
    assert "NOT ATTEMPTED" in note
    assert "not 'nothing found'" in note


def test_refusals_are_reported_not_dropped():
    run = FingerprintRun(refused=[("vpn.example.com", "no ownership verification")])
    assert "refused by the gate" in run.note()


# -- the signature guards ----------------------------------------------------
@pytest.mark.parametrize("product", ["IOS XE", "Windows Server", "Cisco Router"])
def test_os_family_signatures_are_refused(product):
    """Measured: 'IOS XE' tokenises to {ios} and pulls 33 Apple entries onto a
    Cisco router — 79 hits across two vendors."""
    with pytest.raises(SignatureRejected):
        Signature("http.server", "x", product, "SomeVendor")


def test_a_versioned_product_is_refused():
    with pytest.raises(SignatureRejected) as exc:
        Signature("http.server", "x", "Apache HTTP Server 2.4", "Apache")
    assert "carries a version" in str(exc.value)


def test_a_product_that_tokenises_to_nothing_is_refused():
    with pytest.raises(SignatureRejected) as exc:
        Signature("http.server", "x", "the server", "X")
    assert "tokenises to nothing" in str(exc.value)


def test_every_shipped_signature_passes_its_own_audit(catalogue):
    """The guard that caught two of these before they shipped.

    'HTTP Server' — the catalogue's own spelling — tokenises to {http} because
    'server' is a stopword, and pulls in Rejetto's HTTP File Server, IETF HTTP/2
    and Microsoft HTTP.sys: 9 hits across 4 vendors.
    """
    failures = []
    for sig in signatures.SIGNATURES:
        ok, why = signatures.audit(sig, catalogue)
        if not ok:
            failures.append(f"{sig.product}: {why}")
    assert not failures, "\n".join(failures)


def test_vendor_span_is_the_cap_not_hit_count(catalogue):
    """Hit count inverts the populations: Cisco is 96 hits across ONE vendor
    (precise) while 'Security Gateway' is 28 across EIGHT (imprecise)."""
    precise_hits, precise_vendors = signatures.catalogue_profile(
        "Cisco", "Cisco", catalogue)
    vague_hits, vague_vendors = signatures.catalogue_profile(
        "Security Gateway", "Check Point", catalogue)
    assert precise_hits > vague_hits
    assert len(precise_vendors) == 1
    assert len(vague_vendors) > 1


def test_a_declared_vendor_span_is_allowed(catalogue):
    """Connect Secure legitimately spans Ivanti and Pulse Secure — a rename."""
    sig = [s for s in signatures.SIGNATURES if s.product == "Connect Secure"][0]
    ok, why = signatures.audit(sig, catalogue)
    assert ok, why
    assert "Pulse Secure" in sig.expect_vendors


# -- attestation -------------------------------------------------------------
def test_only_the_operator_may_determine_a_version():
    assert Attestation.OPERATOR.can_determine_version
    assert not Attestation.SELF_REPORTED.can_determine_version
    assert not Attestation.INFERRED.can_determine_version


def test_an_inferred_signal_beats_a_self_reported_one():
    """A certificate is a side effect of serving; a header is a string anyone
    with access rewrites. When they disagree, the harder one to forge wins."""
    chosen, _ = signatures.identify([
        signal("http.server", "Apache"),
        signal("tls.subject", "CN=vpn, O=Ivanti Connect Secure",
               Attestation.INFERRED),
    ])
    assert chosen.product == "Connect Secure"
    assert chosen.attestation is Attestation.INFERRED


def test_nothing_matching_returns_no_signature():
    chosen, supporting = signatures.identify([signal("http.server", "nginx/1.18.0")])
    assert chosen is None and supporting == []


# -- the inventory merge -----------------------------------------------------
def test_operator_columns_survive_the_merge():
    """A closed column list would blank `owner`, which core/models.py calls the
    whole objective — an exposure with no owner is a fact nobody acts on."""
    base = [{"identifier": "a.example.com", "product": "unknown",
             "owner": "platform-team", "environment": "prod"}]
    run = FingerprintRun(fingerprints=[
        Fingerprint(host="a.example.com", product="Tomcat", vendor="Apache")])
    rows = fp.to_inventory_rows(run, base)
    assert rows[0]["owner"] == "platform-team"
    assert rows[0]["environment"] == "prod"
    assert rows[0]["product"] == "Tomcat"


def test_a_host_only_the_fingerprinter_saw_is_still_written():
    base = [{"identifier": "a.example.com", "product": "unknown"}]
    run = FingerprintRun(fingerprints=[
        Fingerprint(host="b.example.com", product="Tomcat", vendor="Apache")])
    rows = fp.to_inventory_rows(run, base)
    assert {r["identifier"] for r in rows} == {"a.example.com", "b.example.com"}
