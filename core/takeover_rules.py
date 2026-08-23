"""Which providers a dangling CNAME might point at, and what that means.

A rule says two things a verdict depends on: that a hostname belongs to a known
provider, and whether that provider RESERVES released names against
re-registration. The second is a statement about somebody else's policy at a
point in time, so every rule carries `last_reviewed` and the meaning string
interpolates it — "guarded" alone is not defensible, "guarded per catalogue v1,
policy last reviewed 2026-08-23" is.

DELIBERATELY SMALL, AND HONEST ABOUT IT
---------------------------------------
This is not a comprehensive takeover-fingerprint database, and pretending
otherwise is the failure mode: a provider absent from this table produces
`NO_CLAIM_SIGNAL_FOUND`, which is why that verdict says in as many words that it
is NOT the same as safe.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

CATALOGUE_VERSION = "v1"
LAST_REVIEWED = "2026-08-23"


@dataclass(frozen=True)
class ProviderRule:
    provider: str
    #: Suffix of the CNAME target that identifies this provider.
    suffix: str
    #: Does the provider hold released hostnames against re-registration?
    #: True means a dangling record is NOT trivially claimable.
    guarded: bool
    note: str = ""
    last_reviewed: str = LAST_REVIEWED


RULES: Tuple[ProviderRule, ...] = (
    ProviderRule("Amazon S3", ".s3.amazonaws.com", guarded=False,
                 note="bucket names are globally unique and re-registrable "
                      "once released"),
    ProviderRule("Amazon CloudFront", ".cloudfront.net", guarded=True,
                 note="distributions are account-bound; a released domain is "
                      "not re-attachable by a third party"),
    ProviderRule("Azure", ".azurewebsites.net", guarded=False,
                 note="app service names are globally unique and reusable"),
    ProviderRule("Azure Traffic Manager", ".trafficmanager.net", guarded=False),
    ProviderRule("GitHub Pages", ".github.io", guarded=False,
                 note="a released user or org name can be re-registered"),
    ProviderRule("Heroku", ".herokuapp.com", guarded=False),
    ProviderRule("Shopify", ".myshopify.com", guarded=False),
    ProviderRule("Fastly", ".fastly.net", guarded=True),
    ProviderRule("Cloudflare", ".cdn.cloudflare.net", guarded=True,
                 note="zone-bound; a dangling record here is usually a "
                      "configuration remnant rather than a claimable resource"),
)


def match(target: str) -> Optional[ProviderRule]:
    """The rule for a CNAME target, or None — which is NOT 'safe'."""
    lowered = str(target or "").strip().lower().rstrip(".")
    for rule in RULES:
        if lowered.endswith(rule.suffix):
            return rule
    return None


def registrable_domain(hostname: str) -> Optional[str]:
    """A best-effort registrable domain, stated as best-effort.

    This uses the last two labels and is WRONG for multi-label suffixes like
    `co.uk` — a real implementation needs the Public Suffix List, which is a
    vendored data file this phase does not ship. The consequence is bounded: a
    wrong answer here produces an RDAP lookup that returns "registered" or
    fails, and the verdict falls back to INCONCLUSIVE rather than to a false
    claim of takeability.
    """
    parts = str(hostname or "").strip().lower().rstrip(".").split(".")
    if len(parts) < 2:
        return None
    return ".".join(parts[-2:])


#: Suffixes where the two-label heuristic above is known to be wrong. Findings
#: on these are suppressed rather than reported at a confidence the method
#: cannot support.
KNOWN_MULTI_LABEL: Tuple[str, ...] = (
    ".co.uk", ".org.uk", ".ac.uk", ".gov.uk", ".co.jp", ".com.au", ".co.nz",
    ".com.br", ".co.in", ".co.za", ".com.cn", ".co.kr",
)


def registrable_domain_is_reliable(hostname: str) -> bool:
    lowered = str(hostname or "").strip().lower().rstrip(".")
    return not any(lowered.endswith(suffix) for suffix in KNOWN_MULTI_LABEL)


__all__ = ["CATALOGUE_VERSION", "LAST_REVIEWED", "ProviderRule", "RULES",
           "match", "registrable_domain", "registrable_domain_is_reliable",
           "KNOWN_MULTI_LABEL"]
