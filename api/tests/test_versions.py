import pytest

from nimstead.versions import apk_cmp, comparator_for, dpkg_cmp, pep440_cmp, rpm_cmp, semver_cmp, windows_cmp

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
    assert comparator_for("Maven") is None  # unsupported -> refuse to guess


def test_invalid_versions_raise():
    with pytest.raises(ValueError):
        apk_cmp("not a version", "1.0")
    with pytest.raises(ValueError):
        semver_cmp("abc", "1.0.0")
    with pytest.raises(ValueError):
        windows_cmp("10.0.26200.x", "10.0.26200.1")
