import ast
import hashlib
import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class GeneratorBuildInputsTests(unittest.TestCase):
    def setUp(self):
        self.dockerfile = (ROOT / "Dockerfile").read_text()
        with (ROOT / "poetry.lock").open("rb") as source:
            self.lock = tomllib.load(source)

    def test_export_matches_locked_versions_and_hashes(self):
        exported = {}
        text = (ROOT / "requirements.lock").read_text().replace("\\\n", "")
        for entry in text.splitlines():
            if not entry.strip() or entry.startswith("#"):
                continue
            requirement, *hashes = entry.split("--hash=sha256:")
            pin, separator, marker = requirement.strip().partition(" ; ")
            self.assertTrue(separator)
            self.assertEqual(marker, 'python_version >= "3.11" and python_version < "4.0"')
            name, separator, version = pin.partition("==")
            self.assertTrue(separator)
            self.assertNotIn(name, exported)
            hashes = {value.strip() for value in hashes}
            self.assertTrue(hashes)
            for value in hashes:
                self.assertRegex(value, r"^[0-9a-f]{64}$")
            exported[name] = (version, hashes)

        expected = {}
        for package in self.lock["package"]:
            self.assertFalse(package["optional"])
            self.assertNotIn("source", package)
            self.assertNotIn("marker", package)
            expected[package["name"]] = (
                package["version"],
                {item["hash"].removeprefix("sha256:") for item in package["files"]},
            )
        self.assertEqual(exported, expected)

    def test_source_checksums_are_complete_and_current(self):
        names = set()
        for line in (ROOT / "requirements.sources.sha256").read_text().splitlines():
            expected, name = line.split()
            self.assertNotIn(name, names)
            names.add(name)
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected)
        self.assertEqual(names, {"pyproject.toml", "poetry.lock", "requirements.lock"})
        self.assertIn("sha256sum -c requirements.sources.sha256", self.dockerfile)
        self.assertLess(
            self.dockerfile.index("sha256sum -c"),
            self.dockerfile.index("/opt/guest-attestation/bin/pip install"),
        )

    def test_both_stages_use_the_same_pinned_python(self):
        images = re.findall(r"^FROM (\S+)", self.dockerfile, re.MULTILINE)
        self.assertEqual(len(images), 2)
        self.assertEqual(images[0], images[1])
        self.assertRegex(images[0], r"^python:3\.11\.\d+-slim-bookworm@sha256:[0-9a-f]{64}$")

    def test_poetry_is_not_resolved_during_the_build(self):
        self.assertNotIn("pip install poetry", self.dockerfile)
        self.assertNotIn("poetry self add", self.dockerfile)
        self.assertNotIn("poetry export", self.dockerfile)

    def test_python_install_is_hash_checked_and_wheel_only(self):
        for option in ("--require-hashes", "--only-binary=:all:", "--no-deps", "--no-compile"):
            self.assertIn(option, self.dockerfile)
        self.assertEqual(self.dockerfile.count("pip check"), 2)

    def test_apt_sources_and_tpm_tools_are_frozen(self):
        self.assertRegex(self.dockerfile, r"ARG DEBIAN_SNAPSHOT=\d{8}T\d{6}Z")
        self.assertIn("rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*", self.dockerfile)
        self.assertIn("https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/", self.dockerfile)
        self.assertIn("https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/", self.dockerfile)
        self.assertIn("--no-install-recommends tpm2-tools=5.4-1", self.dockerfile)
        self.assertNotIn("trusted=yes", self.dockerfile)
        self.assertNotIn("--allow-unauthenticated", self.dockerfile)

    def test_build_logs_and_inode_dependent_cache_are_removed(self):
        for path in (
            "/var/cache/ldconfig/aux-cache",
            "/var/log/apt/history.log",
            "/var/log/apt/term.log",
            "/var/log/dpkg.log",
        ):
            self.assertIn(path, self.dockerfile)

    def test_packaging_defaults_select_the_same_published_image(self):
        repository = ROOT.parents[1]
        images = re.findall(
            r'^\s*ARG GUEST_ATTESTATION_IMAGE="([^"]+)"',
            (repository / "Earthfile").read_text(), re.MULTILINE,
        )
        self.assertEqual(len(images), 3)
        cli = ast.parse((repository / "cli/veritee/cli.py").read_text())
        default = next(
            node.value.value for node in cli.body if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "DEFAULT_GUEST_ATTESTATION_IMAGE"
                    for t in node.targets)
        )
        self.assertEqual(set(images), {default})
        self.assertRegex(default, r"@sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
