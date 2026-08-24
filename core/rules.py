"""The rule catalogue: every check this product performs, named and listable.

WHY THIS EXISTS
---------------
SKOPOS could not answer the first question any evaluator asks: *what does it
check?* The checks were real and scattered — a signal enum here, a verdict there,
a threshold inside a scoring function — and the only way to enumerate them was to
read the source.

Recorded Future publishes 40+ named risk rules. Their scoring is weaker than this
product's (forty rules collapsed into one number between 0 and 99, after which
nobody can say which rule produced it), but their *legibility* is better, and
legibility is not a small thing to lose on. This file is the honest version of
the same idea: the rules enumerated, each carrying its own evidence, and none of
them summed into a scalar.

WHAT MAKES AN ENTRY LEGITIMATE HERE
-------------------------------------
Every rule in this catalogue corresponds to a check that ALREADY RUNS. Nothing
was invented to lengthen the list. `tests/test_rules.py` asserts that every rule
id emitted anywhere in the codebase appears here, and — the direction that
actually matters — that every id here is emitted by something.

A catalogue that drifts from the code is worse than no catalogue, because it is
read as a specification.

THE REQUIRED FIELD NOBODY ELSE HAS
------------------------------------
`limits` is mandatory and may not be empty. Every rule states what firing does
NOT establish, because that is the sentence a scanner normally omits and the
omission is where the category earns its reputation. A rule that cannot say what
it fails to prove has not been thought through.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple


class Severity(str, enum.Enum):
    """How much a firing rule should move somebody.

    Deliberately NOT a number. A number invites summation, and a sum of forty
    rules is the scalar this catalogue exists to avoid.
    """

    ACT = "act"                # something is wrong and somebody should act
    CHECK = "check"            # a human has to look; the tool cannot decide
    CONTEXT = "context"        # true and useful, not actionable on its own
    COVERAGE = "coverage"      # a gap in what could be seen, not in the estate


class Category(str, enum.Enum):
    EXPOSURE = "exposure"
    VULNERABILITY = "vulnerability"
    TAKEOVER = "takeover"
    BRAND = "brand"
    SUPPLIER = "supplier"
    ABUSE = "abuse"
    HYGIENE = "hygiene"
    RECONCILIATION = "reconciliation"
    COVERAGE = "coverage"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: Category
    severity: Severity
    #: What firing means, in one sentence a non-specialist can act on.
    detects: str
    #: What firing does NOT establish. Required; may not be empty.
    limits: str
    #: The module that emits this rule, so a reader can go and check.
    emitted_by: str
    #: Fields carried as evidence when this fires.
    evidence: Tuple[str, ...] = ()
    #: Set where a rule depends on something the operator may not have supplied.
    needs: str = ""

    def __post_init__(self) -> None:
        if not self.limits.strip():
            raise ValueError(f"rule {self.id} has no stated limits")
        if not self.detects.strip():
            raise ValueError(f"rule {self.id} does not say what it detects")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title,
            "category": self.category.value, "severity": self.severity.value,
            "detects": self.detects, "limits": self.limits,
            "emitted_by": self.emitted_by, "evidence": list(self.evidence),
            "needs": self.needs or None,
        }


CATALOGUE: Sequence[Rule] = (
    # ── the join: what makes a finding a finding ────────────────────────────
    Rule("vuln.product_match", "Product corresponds to an exploited CVE",
         Category.VULNERABILITY, Severity.CHECK,
         "This asset runs a product named in the CISA KEV catalogue.",
         "NOT that the asset is vulnerable. KEV carries no structured "
         "affected-version data, so nobody has compared the version. This is a "
         "worklist entry and the run says so.",
         "core/match.py", ("asset", "cve", "product", "evidence")),
    Rule("vuln.version_range", "Version falls inside a published affected range",
         Category.VULNERABILITY, Severity.ACT,
         "An observed version was compared against a CNA-published range and "
         "falls inside it.",
         "Still depends on the observed version being correct, and a banner is "
         "a claim by the party whose patch state is the question. Backported "
         "fixes make a version string wrong without making it a lie.",
         "core/affected.py", ("asset", "cve", "version", "range")),
    Rule("vuln.retired", "Version falls OUTSIDE every published range",
         Category.VULNERABILITY, Severity.CONTEXT,
         "A worklist entry was retired: the version was compared and is not "
         "affected.",
         "Only as good as the version. A retirement is a claim this product "
         "made and it is shown, not silently dropped.",
         "core/affected.py", ("asset", "cve", "version")),
    Rule("vuln.identity_unresolved", "Product identity could not be resolved",
         Category.COVERAGE, Severity.COVERAGE,
         "An asset carries a banner that did not map to a catalogue spelling, "
         "so it could not be joined at all.",
         "NOT that the asset is clean. It is an asset nobody could ask about, "
         "which is a different and worse state.",
         "core/signatures.py", ("asset", "banner")),

    # ── the crosshair: seven independent reasons to look ────────────────────
    Rule("crosshair.exploited", "Exploitation observed in the wild",
         Category.VULNERABILITY, Severity.CONTEXT,
         "CISA has observed this CVE being exploited.",
         "True of every entry in this corpus, so it is the floor rather than a "
         "discriminator. It separates nothing.",
         "core/crosshair.py", ("cve",)),
    Rule("crosshair.sprayed", "Exploitation is automatable",
         Category.VULNERABILITY, Severity.ACT,
         "CISA-ADP judged this automatable: sprayed at everything rather than "
         "aimed at anyone, so being found is a matter of time.",
         "NOT that you are being targeted. Nobody chose you.",
         "core/crosshair.py", ("cve", "ssvc_automatable")),
    Rule("crosshair.ransomware", "Known ransomware campaign use",
         Category.VULNERABILITY, Severity.ACT,
         "CISA records ransomware campaign use, which changes what a breach "
         "costs rather than how likely it is.",
         "NOT a prediction that you will be hit, and not an actor attribution.",
         "core/crosshair.py", ("cve",)),
    Rule("crosshair.confirmed", "Version comparison confirms the finding",
         Category.VULNERABILITY, Severity.ACT,
         "The version was compared against a published range and falls inside.",
         "Inherits every limit of vuln.version_range.",
         "core/crosshair.py", ("asset", "cve", "version")),
    Rule("crosshair.reachable", "A port answered from outside",
         Category.EXPOSURE, Severity.ACT,
         "SKOPOS connected. There is no ambiguity about reachability.",
         "Reachable is not exploitable, and a WAF or an auth prompt in front "
         "of the service is invisible from here.",
         "core/reach.py", ("asset", "port", "observed_at")),
    Rule("crosshair.accelerating", "EPSS moved sharply",
         Category.VULNERABILITY, Severity.CHECK,
         "The world's estimate of exploitation probability changed recently.",
         "A model changing its mind, not an event. EPSS moves for reasons "
         "including new evidence and model retraining.",
         "core/velocity.py", ("cve", "epss_delta", "window")),
    Rule("crosshair.overdue", "A CISA remediation deadline has passed",
         Category.VULNERABILITY, Severity.CHECK,
         "The KEV due date is in the past.",
         "That deadline binds US federal agencies. It is not yours unless you "
         "have adopted it, and the finding says so.",
         "core/crosshair.py", ("cve", "due_date")),

    # ── takeover ────────────────────────────────────────────────────────────
    Rule("takeover.registrable_domain_unregistered",
         "A record points at an unregistered registrable domain",
         Category.TAKEOVER, Severity.ACT,
         "A DNS record delegates to a domain that RDAP reports as "
         "unregistered — the strongest dangling signal available passively.",
         "NOT proof anybody can claim it. The only experiment that would "
         "establish that is registering the resource, which this product "
         "refuses to perform. The ceiling is permanent.",
         "core/takeover.py", ("asset", "target", "rdap_status")),
    Rule("takeover.claimable_looking", "A provider fingerprint suggests claimable",
         Category.TAKEOVER, Severity.CHECK,
         "The response matches a known provider's unclaimed-resource "
         "fingerprint.",
         "A fingerprint is a pattern, not a proof. Providers change their "
         "error pages and the catalogue carries review dates for that reason.",
         "core/takeover_rules.py", ("asset", "provider", "fingerprint")),
    Rule("takeover.provider_guarded", "Provider prevents reclaiming",
         Category.TAKEOVER, Severity.CONTEXT,
         "The provider is known to guard against re-registration of a released "
         "resource.",
         "A statement about the provider's published behaviour, not a "
         "guarantee about your specific resource.",
         "core/takeover_rules.py", ("asset", "provider", "reviewed_on")),
    Rule("takeover.internal_dangling", "A record points at private space",
         Category.TAKEOVER, Severity.CHECK,
         "A public record resolves into RFC1918 or otherwise internal space.",
         "Not externally claimable. It is an information leak about internal "
         "addressing, which is a different problem.",
         "core/takeover.py", ("asset", "target")),
    Rule("takeover.inconclusive", "Dangling assessment could not conclude",
         Category.COVERAGE, Severity.COVERAGE,
         "The evidence required to reach any verdict was unavailable.",
         "NOT a clean result. It is an absence of evidence and it is reported "
         "rather than resolved to 'no'.",
         "core/takeover.py", ("asset", "reason")),

    # ── brand ───────────────────────────────────────────────────────────────
    Rule("brand.homoglyph", "Visually confusable characters",
         Category.BRAND, Severity.ACT,
         "The name substitutes characters that read as the brand.",
         "NOT that the domain is being used maliciously; registration is not "
         "an attack. It may also be a legitimate defensive registration.",
         "core/lookalike.py", ("candidate", "brand", "substitutions")),
    Rule("brand.edit_distance", "One or two edits from the brand",
         Category.BRAND, Severity.ACT,
         "Within a small edit distance of a protected term.",
         "Short brands generate false positives at this distance; this rule "
         "only counts toward a finding alongside another strong signal.",
         "core/lookalike.py", ("candidate", "brand", "distance")),
    Rule("brand.brand_as_subdomain", "The brand appears as a subdomain",
         Category.BRAND, Severity.ACT,
         "`yourbrand.something-else.com` — the pattern used to make a URL read "
         "as yours at a glance.",
         "The registrable domain belongs to somebody else, which is the point. "
         "Intent is not observable from here.",
         "core/lookalike.py", ("candidate", "brand", "registrable")),
    Rule("brand.punycode", "Internationalised name decoding to the brand",
         Category.BRAND, Severity.ACT,
         "An xn-- name that renders as the protected term.",
         "Punycode is legitimate infrastructure for non-Latin scripts. The "
         "signal is the rendering, not the encoding.",
         "core/lookalike.py", ("candidate", "brand", "decoded")),
    Rule("brand.cheap_tld", "Registered in a TLD with high abuse rates",
         Category.BRAND, Severity.CONTEXT,
         "The name sits in a TLD disproportionately represented in abuse data.",
         "Cheap is not criminal. This never produces a finding alone.",
         "core/lookalike.py", ("candidate", "tld")),
    Rule("brand.harvest_word", "Credential-harvest vocabulary in the name",
         Category.BRAND, Severity.CONTEXT,
         "Words like login, verify, secure, account beside the brand.",
         "Common in legitimate infrastructure too. Weak alone by design.",
         "core/lookalike.py", ("candidate", "words")),
    Rule("brand.recent", "Registered recently",
         Category.BRAND, Severity.CONTEXT,
         "The registration is new enough to precede a campaign.",
         "Most new domains are not attacks. Recency is an amplifier, never a "
         "finding.",
         "core/lookalike.py", ("candidate", "registered_on")),

    # ── supplier posture, passively observable only ─────────────────────────
    Rule("supplier.spf_missing", "No SPF record",
         Category.SUPPLIER, Severity.CONTEXT,
         "The supplier's domain publishes no SPF policy.",
         "Measured across real domains at 8/8 present, so presence separates "
         "nobody. Absence is the signal and it is rare.",
         "core/suppliers.py", ("supplier", "domain")),
    Rule("supplier.dmarc_unenforced", "DMARC present but not enforcing",
         Category.SUPPLIER, Severity.CHECK,
         "A DMARC record exists at p=none, which reports without acting.",
         "p=none is a legitimate rollout stage. It is a question about how long "
         "they have been there, not a failure.",
         "core/suppliers.py", ("supplier", "domain", "policy")),
    Rule("supplier.mta_sts_absent", "No MTA-STS policy",
         Category.SUPPLIER, Severity.CONTEXT,
         "No published policy requiring TLS for inbound mail.",
         "Adoption is low across the board; this differentiates leaders rather "
         "than identifying laggards.",
         "core/suppliers.py", ("supplier", "domain")),
    Rule("supplier.caa_absent", "No CAA record",
         Category.SUPPLIER, Severity.CONTEXT,
         "No published restriction on which CAs may issue for the domain.",
         "Absence is the norm. Presence indicates deliberate certificate "
         "governance.",
         "core/suppliers.py", ("supplier", "domain")),
    Rule("supplier.registry_lock_absent", "Registry lock not observed",
         Category.SUPPLIER, Severity.CHECK,
         "The registrable domain does not show a transfer lock.",
         "Only scored when the field was actually READ. An unread lock is "
         "unknown, never 'absent' — a bug this product has already made once.",
         "core/suppliers.py", ("supplier", "domain", "observed")),
    Rule("supplier.cert_expiring", "Supplier certificate nearing expiry",
         Category.SUPPLIER, Severity.CHECK,
         "A certificate on the supplier's public estate expires soon.",
         "Renewal is routine and usually automated. This is a question, not a "
         "finding about them.",
         "core/suppliers.py", ("supplier", "host", "not_after")),

    # ── abuse-feed membership ───────────────────────────────────────────────
    Rule("abuse.listed", "Asset appears on a published abuse feed",
         Category.ABUSE, Severity.CHECK,
         "This exact address or host appears on a named list, in a snapshot "
         "with a stated date.",
         "NOT that the asset is compromised, and not that it is compromised "
         "NOW. Shared hosting and CDN ranges put innocent tenants on the same "
         "address as an abusive one. Absence proves nothing at all.",
         "core/blocklists.py", ("asset", "feed", "publisher", "data_age_days")),
    Rule("abuse.tor_exit", "Address is a Tor exit relay",
         Category.ABUSE, Severity.CONTEXT,
         "The address operates a Tor exit relay.",
         "NOT abuse. Running a relay is legal and often admirable; this is "
         "context about where traffic originated and is never counted as a "
         "threat.",
         "core/blocklists.py", ("asset", "feed")),

    # ── ingested CTI (P9) ───────────────────────────────────────────────────
    Rule("cti.asset_in_intelligence",
         "An asset appears in ingested threat intelligence",
         Category.ABUSE, Severity.ACT,
         "This exact name or address appears in a named source's published "
         "intelligence, dated, and recent enough that the age has not "
         "discounted it below the reporting floor.",
         "NOT that the asset is compromised, and NOT a judgement by SKOPOS — "
         "it is the named source's own claim, repeated with their date on it. "
         "Shared hosting and cloud egress put unrelated tenants behind one "
         "address. Absence proves nothing: no source observes everything.",
         "core/cti.py",
         ("asset", "source", "publisher", "seen_on", "weight", "context")),
    Rule("cti.asset_named_by_actor_report",
         "An asset appears in reporting the source ties to a named actor",
         Category.ABUSE, Severity.ACT,
         "The source related this indicator to a named threat actor, malware "
         "family or campaign in a relationship it published.",
         "THE SOURCE'S ATTRIBUTION, NEVER SKOPOS'S. docs/REFUSALS.md §1 "
         "refuses to infer attribution — P3 measured a median of 57 groups "
         "per CVE. This carries a claim somebody else signed; it does not "
         "compute one, and the actor named is theirs to defend.",
         "core/cti.py",
         ("asset", "source", "actor", "seen_on", "weight")),
    Rule("cti.stale_corpus",
         "The ingested CTI corpus is old enough that absence means less",
         Category.COVERAGE, Severity.CONTEXT,
         "The vendored CTI corpus has not been refreshed recently, so a "
         "result of no sightings reflects the corpus age as much as the "
         "estate.",
         "NOT a finding about any asset. A coverage statement about SKOPOS "
         "itself, so a reader does not mistake a stale corpus for a quiet "
         "estate.",
         "core/cti.py", ("built_on", "age_days")),

    # ── ransomware leak sites (P8 W2) ───────────────────────────────────────
    Rule("leak.domain_listed", "A domain in scope appears on a leak site",
         Category.ABUSE, Severity.ACT,
         "A ransomware group published this domain on its own public victim "
         "index. The strongest match available here — a domain compared to a "
         "domain rather than a company name to a company name.",
         "A CLAIM BY THAT GROUP, not a confirmed breach. Groups exaggerate, "
         "recycle old data and occasionally list victims they never reached. "
         "SKOPOS reads the index and never downloads what was published.",
         "collect/leaksites.py",
         ("asset", "group", "published", "confidence", "days_old")),
    Rule("leak.name_listed", "A supplier NAME matches a leak-site listing",
         Category.SUPPLIER, Severity.CHECK,
         "A victim name on a public leak site matches a name in the supplier "
         "register after normalisation.",
         "Names are ambiguous and company names are not unique across "
         "jurisdictions. Confirm before telling anybody their supplier was "
         "breached — a partial match frequently is a coincidence, which is why "
         "the confidence and the reason for it are carried on every match.",
         "collect/leaksites.py",
         ("supplier", "group", "matched_against", "confidence")),
    Rule("leak.not_listed", "Nothing matched the leak-site index",
         Category.COVERAGE, Severity.COVERAGE,
         "No name or domain matched the vendored victim index.",
         "NOT reassurance. This covers only groups that run a public leak site "
         "and only victims they chose to publish — organisations that paid "
         "before publication, groups that do not publish, and every intrusion "
         "that was not ransomware are all invisible here. Not being listed is "
         "the normal state of a breached organisation.",
         "collect/leaksites.py", ("listings_searched",)),

    # ── reconciliation against cloud ground truth ───────────────────────────
    Rule("recon.unexplained_exposure", "Reachable, but the cloud model says not",
         Category.RECONCILIATION, Severity.ACT,
         "Something answers from outside that OverWatch's four-gate cloud model "
         "does not account for.",
         "The disagreement is the finding. Neither method is preferred, and "
         "'no verdict' is inconclusive rather than agreement.",
         "core/overwatch.py", ("asset", "skopos", "overwatch")),
    Rule("recon.discovery_blind_spot", "Cloud model says exposed, discovery missed it",
         Category.RECONCILIATION, Severity.ACT,
         "OverWatch models the asset as reachable and SKOPOS's discovery never "
         "found it.",
         "A gap in this product's discovery, stated as such rather than "
         "attributed to the estate.",
         "core/overwatch.py", ("asset", "skopos", "overwatch")),

    # ── certificate posture (P8 W3) ─────────────────────────────────────────
    Rule("cert.expired", "The newest certificate for a host has expired",
         Category.HYGIENE, Severity.CHECK,
         "No certificate seen for this host is still valid.",
         "A QUESTION, not a finding. A Certificate Transparency entry records "
         "issuance, not deployment — the host may be decommissioned, may "
         "terminate TLS somewhere else entirely, or may be genuinely broken, "
         "and a log cannot tell those apart.",
         "core/certificates.py", ("host", "issuer", "not_after", "days_ago")),
    Rule("cert.expiring", "A certificate expires within 30 days",
         Category.HYGIENE, Severity.CHECK,
         "The newest certificate for this host expires inside one working "
         "window.",
         "Renewal is routine and usually automated. This is a working window "
         "rather than an alarm, and an automated renewal will very often have "
         "happened before anybody reads it.",
         "core/certificates.py", ("host", "issuer", "not_after", "days_left")),
    Rule("cert.weak_signature", "Certificate signed with a broken algorithm",
         Category.HYGIENE, Severity.ACT,
         "The certificate carries an MD5 or SHA-1 signature.",
         "Only fires on algorithms that are broken rather than merely dated. "
         "It says nothing about the key size, the chain above it, or whether "
         "the certificate is deployed anywhere.",
         "core/certificates.py", ("host", "signature_algorithm")),
    Rule("cert.broad_san", "One certificate covers a great many names",
         Category.HYGIENE, Severity.CONTEXT,
         "A certificate carries more than 100 subject alternative names.",
         "NOT wrong — a CDN or shared platform legitimately issues these. It "
         "is a blast-radius observation: one private key is a single point of "
         "failure for every name on it.",
         "core/certificates.py", ("host", "san_count", "issuer")),

    # ── hygiene ─────────────────────────────────────────────────────────────
    Rule("hygiene.dns_changed", "A DNS record changed between runs",
         Category.HYGIENE, Severity.CONTEXT,
         "The (rcode, digest) comparand for this name differs from the last "
         "sweep.",
         "Change is not incident. Most changes are ordinary operations.",
         "core/dns_state.py", ("asset", "rrtype", "previous", "current")),
    Rule("hygiene.resolver_disagreement", "Resolvers disagreed about a name",
         Category.COVERAGE, Severity.COVERAGE,
         "Independent resolvers returned different answers for the same query.",
         "Often legitimate geo-routing. It is reported because a single "
         "resolver's answer would have hidden it.",
         "core/dns_state.py", ("asset", "rrtype", "answers")),
    Rule("hygiene.dns_truncated", "A DNS answer was truncated",
         Category.COVERAGE, Severity.COVERAGE,
         "The TC bit was set and the answer is incomplete until retried over "
         "TCP.",
         "NOT NODATA. Reading a truncated response as empty is a bug this "
         "product shipped for one phase and now refuses.",
         "collect/dns_wire.py", ("asset", "rrtype")),

    # ── coverage: the rules that describe what could not be seen ────────────
    Rule("coverage.source_unavailable", "A discovery source did not answer",
         Category.COVERAGE, Severity.COVERAGE,
         "A named source failed, was rate limited, or was excluded by its own "
         "terms.",
         "Findings from this run are a subset of what was findable. '0 "
         "findings' and '0 findings with three sources down' are different "
         "sentences.",
         "collect/report.py", ("source", "outcome", "reason")),
    Rule("coverage.unverified_asset", "Active assessment refused: ownership unproven",
         Category.COVERAGE, Severity.COVERAGE,
         "The gate refused an active operation because no live ownership "
         "verification exists for this asset.",
         "NOT a failure. It is the control working, and the asset is simply "
         "less well characterised than a verified one.",
         "core/gate.py", ("asset", "operation")),
    Rule("coverage.no_version_observed", "No version available to compare",
         Category.COVERAGE, Severity.COVERAGE,
         "The asset produced no version, so a determination was impossible "
         "regardless of what the catalogue holds.",
         "The dominant reason a finding stays a worklist entry. 47.5% of the "
         "corpus is version-determinable at best; this is the other constraint.",
         "core/identity.py", ("asset",)),
)

BY_ID: Dict[str, Rule] = {r.id: r for r in CATALOGUE}


def get(rule_id: str) -> Optional[Rule]:
    return BY_ID.get(str(rule_id or "").strip())


def by_category() -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for rule in CATALOGUE:
        grouped.setdefault(rule.category.value, []).append(rule.to_dict())
    return dict(sorted(grouped.items()))


def catalogue() -> Dict[str, Any]:
    """The whole catalogue, for `GET /api/v1/rules`.

    Deliberately public. Somebody evaluating this product should be able to read
    what it checks before installing it, and a catalogue behind a login is a
    catalogue nobody reads.
    """
    return {
        "rules": [r.to_dict() for r in CATALOGUE],
        "count": len(CATALOGUE),
        "by_category": by_category(),
        "severities": {s.value: _SEVERITY_MEANING[s] for s in Severity},
        "note": (
            "Every rule states what it does NOT establish, and that field is "
            "required rather than optional. These are not summed into a score: "
            "a single number is what survives into a summary, and by then "
            "nobody can say which rule produced it. TEPS stays decomposed into "
            "four factors and the rules stay individually visible."),
    }


_SEVERITY_MEANING = {
    Severity.ACT: "something is wrong and somebody should act",
    Severity.CHECK: "a person has to look; this tool cannot decide it",
    Severity.CONTEXT: "true and useful, not actionable on its own",
    Severity.COVERAGE: "a limit on what could be seen, not a fact about the estate",
}


def summarise(fired: Sequence[str]) -> Dict[str, Any]:
    """Counts for a set of fired rule ids.

    Unknown ids are RETURNED rather than dropped. A rule id that no longer
    exists in the catalogue means the code and this file have drifted, which is
    the failure mode a catalogue has.
    """
    known = [r for r in fired if r in BY_ID]
    unknown = sorted({r for r in fired if r not in BY_ID})
    counts: Dict[str, int] = {}
    for rule_id in known:
        counts[rule_id] = counts.get(rule_id, 0) + 1
    by_sev: Dict[str, int] = {}
    for rule_id in known:
        sev = BY_ID[rule_id].severity.value
        by_sev[sev] = by_sev.get(sev, 0) + 1
    return {
        "fired": dict(sorted(counts.items())),
        "by_severity": dict(sorted(by_sev.items())),
        "distinct_rules": len(counts),
        "catalogue_size": len(CATALOGUE),
        "unknown_ids": unknown,
        "silent_rules": sorted(set(BY_ID) - set(counts)),
    }


__all__ = ["Rule", "Severity", "Category", "CATALOGUE", "BY_ID", "get",
           "catalogue", "by_category", "summarise"]
