"""TOTP, asserted against RFC 6238's own published vectors.

This is the difference between proving interoperability and proving that a file
agrees with itself. RFC 6238 Appendix B publishes (time, algorithm, expected
code) for a known seed; if this implementation reproduces that table it will
agree with Microsoft Authenticator, Google Authenticator, Authy and 1Password,
because they reproduce it too. A round-trip test of `code_now` against `verify`
would pass just as happily on a hand-rolled scheme no app can read.
"""
from __future__ import annotations

import base64

import pytest

from core import totp

# RFC 6238 Appendix B. The seeds are ASCII "12345678901234567890" repeated to
# the digest's key length, given there as hex; base32 is what this module takes.
SEED_SHA1 = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
SEED_SHA256 = base64.b32encode(
    (b"12345678901234567890" * 2)[:32]).decode().rstrip("=")
SEED_SHA512 = base64.b32encode(
    (b"12345678901234567890" * 4)[:64]).decode().rstrip("=")

# (unix time, algorithm, seed, expected 8-digit code) — the published table.
RFC_VECTORS = [
    (59, "SHA1", SEED_SHA1, "94287082"),
    (59, "SHA256", SEED_SHA256, "46119246"),
    (59, "SHA512", SEED_SHA512, "90693936"),
    (1111111109, "SHA1", SEED_SHA1, "07081804"),
    (1111111111, "SHA1", SEED_SHA1, "14050471"),
    (1234567890, "SHA1", SEED_SHA1, "89005924"),
    (2000000000, "SHA1", SEED_SHA1, "69279037"),
    (20000000000, "SHA1", SEED_SHA1, "65353130"),
    (1111111109, "SHA256", SEED_SHA256, "68084774"),
    (1234567890, "SHA512", SEED_SHA512, "93441116"),
]


@pytest.mark.parametrize("when,algorithm,seed,expected", RFC_VECTORS)
def test_rfc6238_appendix_b_vectors(when, algorithm, seed, expected):
    """If this passes, every conforming authenticator app agrees with us."""
    counter = totp.counter_at(when)
    assert totp.code_at(seed, counter, digits=8, algorithm=algorithm) == expected


def test_the_shipped_defaults_are_the_ones_apps_assume():
    """Advertising SHA-256 produces codes Microsoft and Google Authenticator
    never match, and the user experiences it as a broken app."""
    assert totp.ALGORITHM == "SHA1"
    assert totp.DIGITS == 6
    assert totp.PERIOD == 30


# ── secrets ─────────────────────────────────────────────────────────────────
def test_a_secret_is_160_bits_and_needs_no_padding():
    """32 base32 characters, so the manual-entry string has no '=' for somebody
    to mistype."""
    secret = totp.new_secret()
    assert len(secret) == 32 and "=" not in secret
    assert len(totp.normalise_secret(secret)) == totp.SECRET_BYTES


def test_secrets_are_not_predictable():
    assert len({totp.new_secret() for _ in range(200)}) == 200


@pytest.mark.parametrize("typed", ["abcd efgh", "ABCD-EFGH", "abcdefgh",
                                   "  ABCDEFGH  "])
def test_a_human_typed_secret_is_tolerated(typed):
    """Spaces, hyphens and lower case are what people actually type."""
    assert totp.normalise_secret(typed) == totp.normalise_secret("ABCDEFGH")


# ── verification ────────────────────────────────────────────────────────────
def test_a_current_code_verifies():
    secret = totp.new_secret()
    assert totp.verify(secret, totp.code_now(secret, when=1000), when=1000) is not None


def test_drift_of_one_step_either_side_is_accepted():
    """An unsynchronised phone clock and a slow typist."""
    secret = totp.new_secret()
    now = 1000.0
    for offset in (-totp.PERIOD, 0, totp.PERIOD):
        code = totp.code_now(secret, when=now + offset)
        assert totp.verify(secret, code, when=now) is not None, offset


def test_two_steps_away_is_refused():
    """Two would be 2.5 minutes of replay surface for a code read over a
    shoulder."""
    secret = totp.new_secret()
    code = totp.code_now(secret, when=1000 + 2 * totp.PERIOD)
    assert totp.verify(secret, code, when=1000) is None


def test_verify_returns_the_counter_so_a_replay_can_be_refused():
    """A code stays valid for its whole step, so 'verify returned True' is not
    the whole job — the caller must persist this and refuse it next time."""
    secret = totp.new_secret()
    code = totp.code_now(secret, when=1000)
    counter = totp.verify(secret, code, when=1000)
    assert counter == totp.counter_at(1000)
    assert totp.verify(secret, code, when=1000, after_counter=counter) is None


@pytest.mark.parametrize("bad", ["", "   ", "12345", "1234567", "abcdef",
                                 "12 34 56 78", None])
def test_a_malformed_code_is_refused_without_computing_anything(bad):
    assert totp.verify(totp.new_secret(), bad, when=1000) is None


def test_a_code_for_a_different_secret_does_not_verify():
    code = totp.code_now(totp.new_secret(), when=1000)
    assert totp.verify(totp.new_secret(), code, when=1000) is None


# ── enrolment ───────────────────────────────────────────────────────────────
def test_the_provisioning_uri_is_what_an_authenticator_consumes():
    secret = totp.new_secret()
    uri = totp.provisioning_uri(secret, "k.de@example.com")
    assert uri.startswith("otpauth://totp/")
    assert f"secret={secret}" in uri
    assert "issuer=SKOPOS" in uri
    assert "algorithm=SHA1" in uri and "digits=6" in uri and "period=30" in uri


def test_the_label_is_escaped_so_an_account_cannot_break_the_uri():
    uri = totp.provisioning_uri(totp.new_secret(), "a b/c?d=e&f")
    assert " " not in uri and uri.count("?") == 1


def test_the_secret_is_grouped_for_somebody_reading_it_off_a_screen():
    assert totp.format_secret("ABCDEFGH") == "ABCD EFGH"


# ── recovery codes ──────────────────────────────────────────────────────────
def test_recovery_codes_avoid_characters_that_get_misread():
    """These are read aloud and typed by somebody who has just lost a phone."""
    for code in totp.new_recovery_codes():
        assert not set(code) & set("l1o0"), code


def test_recovery_codes_are_unique_and_plural():
    codes = totp.new_recovery_codes()
    assert len(codes) == totp.RECOVERY_CODE_COUNT == len(set(codes))


def test_a_recovery_code_is_stored_only_as_a_hash():
    code = totp.new_recovery_codes(1)[0]
    fingerprint = totp.recovery_fingerprint(code)
    assert len(fingerprint) == 64 and code.replace("-", "") not in fingerprint


@pytest.mark.parametrize("typed", ["ABCDE-FGHIJ", "abcde fghij", "abcdefghij",
                                   " abcde-fghij "])
def test_a_recovery_code_is_matched_however_it_was_typed(typed):
    assert totp.recovery_fingerprint(typed) == totp.recovery_fingerprint(
        "abcde-fghij")


def test_the_module_does_not_pretend_to_track_replays():
    """The omission is deliberate and documented; a function here would imply
    state this module does not hold."""
    for banned in ("mark_used", "consume", "seen", "used_counters"):
        assert not hasattr(totp, banned), banned
