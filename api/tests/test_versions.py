import pytest

from nimstead.versions import (
    apk_cmp,
    comparator_for,
    dpkg_cmp,
    gem_cmp,
    maven_cmp,
    nuget_cmp,
    pep440_cmp,
    rpm_cmp,
    semver_cmp,
    windows_cmp,
)

# (a, b, expected sign) — cases taken from dpkg, rpm, apk-tools and semver.org test suites
DPKG = [
    ("1.0", "1.0", 0),
    ("1.0-1", "1.0-2", -1),
    ("1:1.0", "2.0", 1),
    ("1.0~rc1", "1.0", -1),
    ("1.0~~", "1.0~", -1),
    ("1.0~", "1.0", -1),
    ("1.0", "1.0+b1", -1),
    ("1.0a", "1.0", 1),
    ("1.0.0", "1.0", 1),
    ("2.36-9+deb12u3", "2.36-9+deb12u4", -1),
    ("1.1.1n-0+deb11u5", "1.1.1n-0+deb11u4", 1),
    ("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.15", -1),
    ("0001.0", "1.0", 0),
    ("1.2.3-1ubuntu0.1", "1.2.3-1", 1),
    ("7.88.1-10+deb12u5", "7.88.1-10+deb12u12", -1),
]

RPM = [
    ("1.0", "1.0", 0),
    ("1.0", "2.0", -1),
    ("2.0.1", "2.0", 1),
    ("2.0", "2.0a", -1),
    ("1.0a", "1.0b", -1),
    ("1.0~rc1", "1.0", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0^", "1.0", 1),
    ("1.0^git1", "1.0.1", -1),
    ("1.0^git1", "1.0^git2", -1),
    ("5.5p1", "5.5p10", -1),
    ("10", "9", 1),
    ("1.0-1.el9", "1.0-1.el9_2", -1),
    ("1:1.0-1", "2.0-1", 1),
    ("3.0.7-27.el9", "3.0.7-25.el9_3", 1),
    ("1.0", "1.0-5", 0),  # missing release compares version only
    ("a", "1", -1),
    ("1.0010", "1.9", 1),
]

APK = [
    ("1.0", "1.0", 0),
    ("1.0-r1", "1.0-r0", 1),
    ("1.0_rc1", "1.0", -1),
    ("1.0_alpha", "1.0_beta", -1),
    ("1.0_p1", "1.0", 1),
    ("1.0a", "1.0", 1),
    ("1.2.1", "1.2", 1),
    ("3.1.4-r5", "3.1.4-r6", -1),
    ("1.36.1-r20", "1.36.1-r21", -1),
    ("2.0_git20230101", "2.0", 1),
]

SEMVER = [
    ("1.0.0", "1.0.0", 0),
    ("1.0.0-alpha", "1.0.0", -1),
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    ("1.0.0-beta.2", "1.0.0-beta.11", -1),
    ("1.0.0-rc.1", "1.0.0", -1),
    ("v1.2.3", "1.2.3", 0),
    ("1.2.3+build", "1.2.3", 0),
    ("4.17.20", "4.17.21", -1),
    ("0.10.0", "0.9.9", 1),
]

PEP440 = [
    ("2.31.0", "2.32.0", -1),
    ("1.0rc1", "1.0", -1),
    ("1.0.post1", "1.0", 1),
    ("1.0", "1.0.0", 0),
    ("1!0.1", "2.0", 1),
]

WINDOWS = [
    ("10.0.26200.6899", "10.0.26200.7019", -1),
    ("10.0.26200.9711", "10.0.26200.9711", 0),
    ("10.0.26200.10000", "10.0.26200.9999", 1),  # numeric, not lexical
    ("10.0.26100.1", "10.0.26200.1", -1),
    ("10.0.19045.5000", "10.0.26200.1", -1),
    ("10.0.26200", "10.0.26200.0", 0),  # missing UBR == 0
    ("6.2.9200.26434", "10.0.26200.1", -1),
]


@pytest.mark.parametrize(
    "cmp,a,b,want",
    [(dpkg_cmp, *c) for c in DPKG]
    + [(rpm_cmp, *c) for c in RPM]
    + [(apk_cmp, *c) for c in APK]
    + [(semver_cmp, *c) for c in SEMVER]
    + [(pep440_cmp, *c) for c in PEP440]
    + [(windows_cmp, *c) for c in WINDOWS],
)
def test_compare(cmp, a, b, want):
    assert cmp(a, b) == want
    assert cmp(b, a) == -want  # antisymmetry


def test_comparator_for():
    assert comparator_for("Debian:12") is dpkg_cmp
    assert comparator_for("Ubuntu:22.04:LTS") is dpkg_cmp
    assert comparator_for("Rocky Linux:9") is rpm_cmp
    assert comparator_for("Windows") is windows_cmp
    assert comparator_for("Hex") is None  # unsupported -> refuse to guess


def test_invalid_versions_raise():
    with pytest.raises(ValueError):
        apk_cmp("not a version", "1.0")
    with pytest.raises(ValueError):
        semver_cmp("abc", "1.0.0")
    with pytest.raises(ValueError):
        windows_cmp("10.0.26200.x", "10.0.26200.1")


# --- Maven: Apache Maven's ComparableVersionTest (ascending lists, equality pairs) ---
MAVEN_QUALIFIER_ORDER = ["1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2", "1-m11", "1-rc", "1-cr2",
                         "1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1", "1-1-snapshot",
                         "1-1", "1-2", "1-123"]
MAVEN_NUMBER_ORDER = ["2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1", "2.1.0.1", "2.2",
                      "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m"]
MAVEN_EQUAL = [("1", "1.0"), ("1", "1.0.0"), ("1.0", "1.0.0"), ("1", "1-0"), ("1", "1.0-0"), ("1.0", "1.0-0"), ("1a", "1-a"),
               ("1a", "1.0-a"), ("1.0a", "1-a"), ("1x", "1-x"), ("1.0.0x", "1-x"), ("1cr", "1rc"), ("1ga", "1"),
               ("1release", "1"), ("1final", "1"), ("1cR", "1Rc"), ("1-ga", "1"), ("1.0.0.0", "1"), ("1-0.ga", "1")]
MAVEN_PAIRS = [("1-1", "1.1", -1), ("1.0-alpha", "1.0", -1), ("1.0-SNAPSHOT", "1.0", -1), ("1.0-sp", "1.0", 1),
               ("2.14.1", "2.17.0", -1), ("2.13.4.2", "2.13.4.1", 1), ("2.9.10", "2.9.10.1", -1), ("1.0.0.X1", "1.0.0-X2", -1),
               ("1.0-ga", "1.0-alpha", 1), ("3.0", "2.99", 1)]


@pytest.mark.parametrize("order", [MAVEN_QUALIFIER_ORDER, MAVEN_NUMBER_ORDER], ids=["qualifier", "number"])
def test_maven_ascending(order):
    for i, a in enumerate(order):
        for b in order[i + 1:]:
            assert maven_cmp(a, b) == -1 and maven_cmp(b, a) == 1, (a, b)


@pytest.mark.parametrize("a,b", MAVEN_EQUAL)
def test_maven_equal(a, b):
    assert maven_cmp(a, b) == 0 == maven_cmp(b, a)


@pytest.mark.parametrize("a,b,want", MAVEN_PAIRS)
def test_maven_pairs(a, b, want):
    assert maven_cmp(a, b) == want and maven_cmp(b, a) == -want


NUGET = [
    ("1.0", "1.0.0.0", 0), ("1.0.0", "1.0.0.1", -1), ("1.0.0-beta", "1.0.0", -1), ("1.0.0-BETA", "1.0.0-beta", 0),
    ("1.0.0-beta.2", "1.0.0-beta.11", -1), ("1.0.0-beta.11", "1.0.0-rc.1", -1), ("1.0.0-1", "1.0.0-alpha", -1),
    ("1.0.0+meta", "1.0.0", 0), ("1.0.0-alpha", "1.0.0-alpha.1", -1), ("12.0.3", "13.0.1", -1), ("4.7.1", "5.0.1", -1),
    ("1.2.3.4", "1.2.3.10", -1), ("2", "1.9.9.9", 1),
]
RUBYGEMS = [
    ("1.0", "1", 0), ("1.0.0", "1", 0), ("2.2.3", "2.2.8", -1), ("3.0.0.beta1", "3.0.0", -1), ("3.0.0.beta1", "2.2.8", 1),
    ("1.0.a", "1.0", -1), ("1.0.a", "1.0.b", -1), ("1.0.a10", "1.0.a9", 1), ("1.0-1", "1.0.pre.1", 0), ("1.0.1.a", "1.0.1", -1),
    ("1.13.9", "1.16.5", -1), ("1.10", "1.9", 1), ("1.0.0.rc1", "1.0.0.beta2", 1), ("1.0.a.0", "1.0.a", 0),
]


@pytest.mark.parametrize("a,b,want", NUGET)
def test_nuget(a, b, want):
    assert nuget_cmp(a, b) == want and nuget_cmp(b, a) == -want


@pytest.mark.parametrize("a,b,want", RUBYGEMS)
def test_rubygems(a, b, want):
    assert gem_cmp(a, b) == want and gem_cmp(b, a) == -want


@pytest.mark.parametrize("fn,bad", [(maven_cmp, ""), (maven_cmp, " 1"), (nuget_cmp, "v1.0"), (nuget_cmp, "1.2.3.4.5"),
                                    (nuget_cmp, "1.0-"), (nuget_cmp, ""), (gem_cmp, ""), (gem_cmp, "a.1"), (gem_cmp, "1..2")])
def test_new_comparators_refuse_garbage(fn, bad):
    with pytest.raises(ValueError):
        fn(bad, "1.0")


def test_registered():
    assert comparator_for("Maven") is maven_cmp and comparator_for("NuGet") is nuget_cmp and comparator_for("RubyGems") is gem_cmp
