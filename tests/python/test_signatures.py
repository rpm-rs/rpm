"""Tests for Signer, Verifier, and Package signature operations."""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from rpm_rs import Package, Signer, SignatureInfo, SignatureVersion, Verifier

from conftest import (
    RPM_BASIC,
    RPM_SIGNED,
    RPM_MULTI_SIGNED,
    PUBLIC_KEY,
    PRIVATE_KEY,
    OTHER_PUBLIC_KEY,
    PROTECTED_PRIVATE_KEY,
    PROTECTED_PUBLIC_KEY,
    KEY_PASSPHRASE,
    KEYRING_PRIVATE,
)


class TestSignerConstruction:
    def test_from_bytes(self):
        signer = Signer(open(PRIVATE_KEY, "rb").read())
        assert signer is not None

    def test_from_file(self):
        signer = Signer.from_file(PRIVATE_KEY)
        assert signer is not None

    def test_from_file_pathlike(self):
        signer = Signer.from_file(Path(PRIVATE_KEY))
        assert signer is not None

    def test_invalid_key_raises(self):
        with pytest.raises(RuntimeError):
            Signer(b"not a key")

    def test_with_key_passphrase(self):
        signer = Signer.from_file(PROTECTED_PRIVATE_KEY)
        signer = signer.with_key_passphrase(KEY_PASSPHRASE)
        pkg = Package.open(RPM_BASIC)
        pkg.sign(signer)

    def test_with_signing_key(self):
        signer = Signer(open(KEYRING_PRIVATE, "rb").read())
        pkg = Package.open(RPM_SIGNED)
        sigs = pkg.signatures()
        if sigs and sigs[0].fingerprint:
            try:
                signer.with_signing_key(sigs[0].fingerprint)
            except RuntimeError:
                pass  # Key might not be in this keyring

    def test_with_signing_key_invalid_hex(self):
        signer = Signer(open(PRIVATE_KEY, "rb").read())
        with pytest.raises(ValueError, match="invalid hex"):
            signer.with_signing_key("not-hex!")


class TestVerifierConstruction:
    def test_from_bytes(self):
        verifier = Verifier(open(PUBLIC_KEY, "rb").read())
        assert verifier is not None

    def test_from_file(self):
        verifier = Verifier.from_file(PUBLIC_KEY)
        assert verifier is not None

    def test_from_file_pathlike(self):
        verifier = Verifier.from_file(Path(PUBLIC_KEY))
        assert verifier is not None

    def test_invalid_key_raises(self):
        with pytest.raises(RuntimeError):
            Verifier(b"not a key")

    def test_load_from_asc_bytes(self):
        verifier = Verifier(open(PUBLIC_KEY, "rb").read())
        verifier.load_from_asc_bytes(open(OTHER_PUBLIC_KEY, "rb").read())

    def test_load_from_asc_file(self):
        verifier = Verifier(open(PUBLIC_KEY, "rb").read())
        verifier.load_from_asc_file(OTHER_PUBLIC_KEY)

    def test_empty_verifier(self):
        verifier = Verifier()
        assert verifier is not None

    def test_with_key_invalid_hex(self):
        verifier = Verifier(open(PUBLIC_KEY, "rb").read())
        with pytest.raises(ValueError, match="invalid hex"):
            verifier.with_key("not-hex!")


class TestSignAndVerify:
    def test_sign_and_verify(self):
        pkg = Package.open(RPM_BASIC)
        signer = Signer.from_file(PRIVATE_KEY)
        pkg.sign(signer)
        verifier = Verifier.from_file(PUBLIC_KEY)
        pkg.verify_signature(verifier)

    def test_sign_with_timestamp(self):
        pkg = Package.open(RPM_BASIC)
        signer = Signer.from_file(PRIVATE_KEY)
        pkg.sign(signer, timestamp=1_600_000_000)
        verifier = Verifier.from_file(PUBLIC_KEY)
        pkg.verify_signature(verifier)

    def test_sign_with_passphrase(self):
        pkg = Package.open(RPM_BASIC)
        signer = Signer.from_file(PROTECTED_PRIVATE_KEY)
        signer = signer.with_key_passphrase(KEY_PASSPHRASE)
        pkg.sign(signer)
        verifier = Verifier.from_file(PROTECTED_PUBLIC_KEY)
        pkg.verify_signature(verifier)

    def test_verify_wrong_key_fails(self):
        pkg = Package.open(RPM_BASIC)
        signer = Signer.from_file(PRIVATE_KEY)
        pkg.sign(signer)
        verifier = Verifier.from_file(OTHER_PUBLIC_KEY)
        with pytest.raises(RuntimeError):
            pkg.verify_signature(verifier)

    def test_verify_pre_signed(self):
        pkg = Package.open(RPM_SIGNED)
        verifier = Verifier.from_file(PUBLIC_KEY)
        pkg.verify_signature(verifier)


class TestClearSignatures:
    def test_clear_signatures(self):
        pkg = Package.open(RPM_BASIC)
        signer = Signer.from_file(PRIVATE_KEY)
        verifier = Verifier.from_file(PUBLIC_KEY)

        pkg.sign(signer)
        pkg.verify_signature(verifier)

        pkg.clear_signatures()
        with pytest.raises(RuntimeError):
            pkg.verify_signature(verifier)


class TestSignatureInfo:
    def test_signatures_after_sign(self):
        pkg = Package.open(RPM_BASIC)
        signer = Signer.from_file(PRIVATE_KEY)
        pkg.sign(signer)

        for target in [pkg, pkg.metadata]:
            sigs = target.signatures()
            assert isinstance(sigs, list)
            assert len(sigs) > 0

            sig = sigs[0]
            assert isinstance(sig, SignatureInfo)
            assert sig.fingerprint is not None
            assert isinstance(sig.fingerprint, str)
            assert len(sig.fingerprint) > 16
            assert sig.algorithm is not None
            assert sig.hash_algorithm is not None
            assert sig.version == SignatureVersion.V6

    def test_signature_created_timestamp(self):
        pkg = Package.open(RPM_BASIC)
        signer = Signer.from_file(PRIVATE_KEY)
        pkg.sign(signer, timestamp=1_600_000_000)

        for target in [pkg, pkg.metadata]:
            sigs = target.signatures()
            assert len(sigs) > 0
            assert sigs[0].created == 1_600_000_000

    def test_signature_repr(self):
        pkg = Package.open(RPM_BASIC)
        signer = Signer.from_file(PRIVATE_KEY)
        pkg.sign(signer)
        sigs = pkg.signatures()
        assert "SignatureInfo" in repr(sigs[0])

    def test_unsigned_package_empty(self):
        pkg = Package.open(RPM_BASIC)
        for target in [pkg, pkg.metadata]:
            assert target.signatures() == []
            assert target.raw_signatures() == []

    def test_multi_signed_package(self):
        pkg = Package.open(RPM_MULTI_SIGNED)
        for target in [pkg, pkg.metadata]:
            sigs = target.signatures()
            assert len(sigs) > 1
            for sig in sigs:
                assert sig.version == SignatureVersion.V6

    def test_raw_signatures(self):
        pkg = Package.open(RPM_SIGNED)
        for target in [pkg, pkg.metadata]:
            sigs = target.raw_signatures()
            assert isinstance(sigs, list)
            assert len(sigs) > 0
            assert all(isinstance(s, bytes) for s in sigs)


class TestRemoteSigning:
    def test_header_bytes_returns_bytes(self):
        pkg = Package.open(RPM_BASIC)
        header = pkg.header_bytes()
        assert isinstance(header, bytes)
        assert len(header) > 0

    def test_signer_sign_returns_bytes(self):
        signer = Signer.from_file(PRIVATE_KEY)
        pkg = Package.open(RPM_BASIC)
        header = pkg.header_bytes()
        sig = signer.sign(header)
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_sign_and_apply_signature(self):
        signer = Signer.from_file(PRIVATE_KEY)
        verifier = Verifier.from_file(PUBLIC_KEY)
        pkg = Package.open(RPM_BASIC)

        header = pkg.header_bytes()
        sig = signer.sign(header)
        pkg.apply_signature(sig)

        pkg.verify_signature(verifier)

    def test_apply_signature_wrong_key_fails(self):
        signer = Signer.from_file(PRIVATE_KEY)
        pkg = Package.open(RPM_BASIC)

        header = pkg.header_bytes()
        sig = signer.sign(header)
        pkg.apply_signature(sig)

        verifier = Verifier.from_file(OTHER_PUBLIC_KEY)
        with pytest.raises(RuntimeError):
            pkg.verify_signature(verifier)


class TestCheckSignatures:
    def test_check_signatures_valid(self):
        pkg = Package.open(RPM_SIGNED)
        verifier = Verifier.from_file(PUBLIC_KEY)
        for target in [pkg, pkg.metadata]:
            report = target.check_signatures(verifier)
            assert report.is_ok()
            assert report.digests.is_ok()
            assert len(report.signatures) > 0
            assert all(s.is_verified for s in report.signatures)

    def test_check_signatures_wrong_key(self):
        pkg = Package.open(RPM_SIGNED)
        verifier = Verifier.from_file(OTHER_PUBLIC_KEY)
        for target in [pkg, pkg.metadata]:
            report = target.check_signatures(verifier)
            assert report.digests.is_ok()
            assert not report.is_ok()

    def test_check_signatures_unsigned(self):
        pkg = Package.open(RPM_BASIC)
        verifier = Verifier.from_file(PUBLIC_KEY)
        report = pkg.check_signatures(verifier)
        assert report.digests.is_ok()
        assert len(report.signatures) == 0

    def test_check_signatures_empty_verifier(self):
        pkg = Package.open(RPM_BASIC)
        verifier = Verifier()
        report = pkg.check_signatures(verifier)
        assert report.digests.is_ok()

    def test_verify_signature(self):
        pkg = Package.open(RPM_SIGNED)
        verifier = Verifier.from_file(PUBLIC_KEY)
        for target in [pkg, pkg.metadata]:
            target.verify_signature(verifier)

    def test_verify_signature_wrong_key_fails(self):
        pkg = Package.open(RPM_SIGNED)
        verifier = Verifier.from_file(OTHER_PUBLIC_KEY)
        for target in [pkg, pkg.metadata]:
            with pytest.raises(RuntimeError):
                target.verify_signature(verifier)

    def test_verify_unsigned_fails(self):
        pkg = Package.open(RPM_BASIC)
        verifier = Verifier.from_file(PUBLIC_KEY)
        for target in [pkg, pkg.metadata]:
            with pytest.raises(RuntimeError):
                target.verify_signature(verifier)

    def test_verify_with_loaded_key(self):
        verifier = Verifier()
        verifier.load_from_asc_bytes(open(PUBLIC_KEY, "rb").read())
        pkg = Package.open(RPM_SIGNED)
        for target in [pkg, pkg.metadata]:
            target.verify_signature(verifier)


class TestInPlace:
    def test_clear_signatures_in_place(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.rpm")
            shutil.copy2(RPM_SIGNED, path)
            original_size = os.path.getsize(path)

            Package.clear_signatures_in_place(path)

            assert os.path.getsize(path) == original_size
            pkg = Package.open(path)
            assert len(pkg.raw_signatures()) == 0

    def test_apply_signature_in_place(self):
        signed_pkg = Package.open(RPM_SIGNED)
        sigs = signed_pkg.raw_signatures()
        assert len(sigs) > 0

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.rpm")
            shutil.copy2(RPM_SIGNED, path)
            original_size = os.path.getsize(path)

            Package.clear_signatures_in_place(path)
            Package.apply_signature_in_place(path, sigs[0])

            assert os.path.getsize(path) == original_size
            pkg = Package.open(path)
            assert len(pkg.raw_signatures()) > 0

    def test_resign_in_place(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.rpm")
            shutil.copy2(RPM_SIGNED, path)
            original_size = os.path.getsize(path)

            signer = Signer.from_file(PRIVATE_KEY)
            Package.resign_in_place(path, signer)

            assert os.path.getsize(path) == original_size
            pkg = Package.open(path)
            assert len(pkg.raw_signatures()) > 0
