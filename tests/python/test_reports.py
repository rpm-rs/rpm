"""Tests for check_digests() / check_signatures() verification report API."""

import pytest

from rpm_rs import Package, Signer, Verifier

from conftest import (
    RPM_BASIC,
    RPM_SIGNED,
    RPM_MULTI_SIGNED,
    RPM_V4_BASIC,
    PUBLIC_KEY,
    PRIVATE_KEY,
    OTHER_PUBLIC_KEY,
)


class TestDigestStatus:
    def test_verified_status(self):
        pkg = Package.open(RPM_BASIC)
        report = pkg.check_digests()
        status = report.header_sha256
        assert status.is_verified()
        assert not status.is_not_present()
        assert not status.is_mismatch()
        assert status.expected is None
        assert status.actual is None

    def test_not_present_status(self):
        # v6 packages don't have SHA-1
        pkg = Package.open(RPM_BASIC)
        report = pkg.check_digests()
        status = report.header_sha1
        assert not status.is_verified()
        assert status.is_not_present()
        assert not status.is_mismatch()

    def test_repr(self):
        pkg = Package.open(RPM_BASIC)
        report = pkg.check_digests()
        assert "Verified" in repr(report.header_sha256)
        assert "NotPresent" in repr(report.header_sha1)


class TestDigestReport:
    def test_v6_package(self):
        pkg = Package.open(RPM_BASIC)
        report = pkg.check_digests()
        assert report.is_ok()

        # v6 has SHA-256 and SHA3-256 header digests
        assert report.header_sha256.is_verified()
        assert report.header_sha3_256.is_verified()

        # v6 does not have SHA-1 header digest
        assert report.header_sha1.is_not_present()

        # v6 has payload digests
        assert report.payload_sha256.is_verified()
        assert report.payload_sha512.is_verified()
        assert report.payload_sha3_256.is_verified()

    def test_v4_package(self):
        pkg = Package.open(RPM_V4_BASIC)
        report = pkg.check_digests()
        assert report.is_ok()

        # v4 has SHA-1 and SHA-256 header digests
        assert report.header_sha1.is_verified()
        assert report.header_sha256.is_verified()

        # v4 does not have SHA3-256
        assert report.header_sha3_256.is_not_present()

        # v4 has SHA-256 payload digest but not SHA-512 or SHA3-256
        assert report.payload_sha256.is_verified()
        assert report.payload_sha512.is_not_present()
        assert report.payload_sha3_256.is_not_present()

    def test_verify_passes(self):
        pkg = Package.open(RPM_BASIC)
        report = pkg.check_digests()
        report.verify()  # should not raise

    def test_repr(self):
        pkg = Package.open(RPM_BASIC)
        report = pkg.check_digests()
        assert "DigestReport" in repr(report)


class TestSignatureReport:
    def test_signed_package(self):
        pkg = Package.open(RPM_SIGNED)
        verifier = Verifier.from_file(PUBLIC_KEY)
        report = pkg.check_signatures(verifier)

        assert report.is_ok()
        assert report.digests.is_ok()

        sigs = report.signatures
        assert len(sigs) > 0
        assert any(s.is_verified() for s in sigs)

    def test_signature_check_result_fields(self):
        pkg = Package.open(RPM_SIGNED)
        verifier = Verifier.from_file(PUBLIC_KEY)
        report = pkg.check_signatures(verifier)
        sig = report.signatures[0]

        assert sig.is_verified()
        assert sig.error is None
        assert sig.info is not None
        assert sig.info.fingerprint is not None
        assert sig.info.algorithm is not None

    def test_wrong_key_fails_signature(self):
        pkg = Package.open(RPM_SIGNED)
        verifier = Verifier.from_file(OTHER_PUBLIC_KEY)
        report = pkg.check_signatures(verifier)

        # digests should still be ok
        assert report.digests.is_ok()

        # but no signature should verify
        assert not report.is_ok()
        for sig in report.signatures:
            assert not sig.is_verified()
            assert sig.error is not None

    def test_unsigned_package(self):
        pkg = Package.open(RPM_BASIC)
        verifier = Verifier.from_file(PUBLIC_KEY)
        report = pkg.check_signatures(verifier)

        assert report.digests.is_ok()
        assert len(report.signatures) == 0
        assert not report.is_ok()

    def test_verify_raises_on_failure(self):
        pkg = Package.open(RPM_BASIC)
        verifier = Verifier.from_file(PUBLIC_KEY)
        report = pkg.check_signatures(verifier)

        with pytest.raises(RuntimeError):
            report.verify()

    def test_verify_passes_on_success(self):
        pkg = Package.open(RPM_SIGNED)
        verifier = Verifier.from_file(PUBLIC_KEY)
        report = pkg.check_signatures(verifier)
        report.verify()  # should not raise

    def test_multi_signed_fingerprints(self):
        pkg = Package.open(RPM_MULTI_SIGNED)
        verifier = Verifier.from_file(PUBLIC_KEY)
        report = pkg.check_signatures(verifier)

        sigs = report.signatures
        assert len(sigs) > 1

        fingerprints = [s.info.fingerprint for s in sigs]
        assert all(fp is not None for fp in fingerprints)

    def test_repr(self):
        pkg = Package.open(RPM_SIGNED)
        verifier = Verifier.from_file(PUBLIC_KEY)
        report = pkg.check_signatures(verifier)
        assert "SignatureReport" in repr(report)

        sig = report.signatures[0]
        assert "SignatureCheckResult" in repr(sig)
