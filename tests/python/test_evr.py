"""Tests for Evr, Nevra, and evr_compare."""

from rpm_rs import Evr, Nevra, evr_compare


class TestEvr:
    def test_construct(self):
        e = Evr("1", "2.3.4", "5.el9")
        assert e.epoch == "1"
        assert e.version == "2.3.4"
        assert e.release == "5.el9"

    def test_parse(self):
        e = Evr.parse("1:2.3.4-5")
        assert e.epoch == "1"
        assert e.version == "2.3.4"
        assert e.release == "5"

    def test_parse_no_epoch(self):
        e = Evr.parse("2.3.4-5")
        assert e.epoch == ""
        assert e.version == "2.3.4"
        assert e.release == "5"

    def test_str(self):
        e = Evr("1", "2.3", "4")
        assert str(e) == "1:2.3-4"

    def test_repr(self):
        e = Evr("1", "2.3", "4")
        assert "Evr" in repr(e)

    def test_normalized_form(self):
        e = Evr("", "1.0", "1")
        assert e.as_normalized_form() == "0:1.0-1"

    def test_normalized_form_with_epoch(self):
        e = Evr("2", "1.0", "1")
        assert e.as_normalized_form() == "2:1.0-1"

    def test_ordering(self):
        a = Evr.parse("1.0-1")
        b = Evr.parse("2.0-1")
        assert a < b
        assert b > a
        assert a <= b
        assert b >= a

    def test_equality(self):
        a = Evr.parse("1.0-1")
        b = Evr.parse("1.0-1")
        assert a == b
        assert not (a != b)

    def test_epoch_comparison(self):
        a = Evr.parse("1:1.0-1")
        b = Evr.parse("2:1.0-1")
        assert a < b


class TestEvrCompare:
    def test_less(self):
        assert evr_compare("1.0-1", "2.0-1") == -1

    def test_greater(self):
        assert evr_compare("2:1.0-1", "1:9.9-1") == 1

    def test_equal(self):
        assert evr_compare("1.0-1", "1.0-1") == 0

    def test_release_comparison(self):
        assert evr_compare("1.0-1", "1.0-2") == -1


class TestNevra:
    def test_construct(self):
        n = Nevra("foo", "1", "2.3", "4", "x86_64")
        assert n.name == "foo"
        assert n.epoch == "1"
        assert n.version == "2.3"
        assert n.release == "4"
        assert n.arch == "x86_64"

    def test_parse(self):
        n = Nevra.parse("foo-1:2.3-4.x86_64")
        assert n.name == "foo"
        assert n.epoch == "1"
        assert n.version == "2.3"
        assert n.release == "4"
        assert n.arch == "x86_64"

    def test_str(self):
        n = Nevra.parse("foo-1:2.3-4.x86_64")
        assert str(n) == "foo-1:2.3-4.x86_64"

    def test_repr(self):
        n = Nevra.parse("foo-1:2.3-4.x86_64")
        assert "Nevra" in repr(n)

    def test_nvra(self):
        n = Nevra.parse("foo-1:2.3-4.x86_64")
        assert n.nvra() == "foo-2.3-4.x86_64"

    def test_evr(self):
        n = Nevra.parse("foo-1:2.3-4.x86_64")
        evr = n.evr()
        assert isinstance(evr, Evr)
        assert evr.epoch == "1"
        assert evr.version == "2.3"

    def test_ordering(self):
        a = Nevra.parse("foo-1.0-1.x86_64")
        b = Nevra.parse("foo-2.0-1.x86_64")
        assert a < b

    def test_equality(self):
        a = Nevra.parse("foo-1.0-1.x86_64")
        b = Nevra.parse("foo-1.0-1.x86_64")
        assert a == b
