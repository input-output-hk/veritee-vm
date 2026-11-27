import copy
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("docker_apt_verify", HERE / "verify.py")
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


class DockerPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.lock = json.loads((HERE / "lock.json").read_text())

    def copy_inputs(self):
        directory = self.root / "inputs"
        shutil.copytree(HERE / "packages", directory)
        return directory

    def test_versions_match_guest_package_pins(self):
        template = (HERE.parent / "mkosi/rootfs/mkosi.conf.j2").read_text()
        self.assertEqual(len(self.lock["packages"]), 4)
        for package in self.lock["packages"]:
            self.assertIn(f"{package['name']}={package['version']}", template)
            self.assertEqual(package["architecture"], "amd64")
            self.assertEqual(Path(package["upstream_path"]).name, package["filename"])

    def test_real_vendored_signature_index_packages_and_control_fields(self):
        verify.verify(HERE / "packages", self.lock)

    def test_wrong_signing_key_is_rejected(self):
        self.lock["upstream"]["signing_key_fingerprint"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "unexpected key"):
            verify.verify(HERE / "packages", self.lock)

    def test_tampered_release_is_rejected_even_with_a_changed_lock_hash(self):
        directory = self.copy_inputs()
        release = directory / "InRelease"
        original = release.read_bytes()
        changed = original.replace(b"Suite: jammy", b"Suite: changed", 1)
        self.assertNotEqual(original, changed)
        release.write_bytes(changed)
        self.lock["metadata_sha256"]["InRelease"] = verify.sha256(release)
        destination = self.root / "staged"
        with self.assertRaises(subprocess.CalledProcessError):
            verify.stage(directory, destination, self.lock)
        self.assertFalse(destination.exists())

    def test_index_must_match_the_signed_release_even_with_a_changed_lock_hash(self):
        directory = self.copy_inputs()
        index = directory / "Packages.gz"
        index.write_bytes(index.read_bytes() + b"changed")
        self.lock["metadata_sha256"]["Packages.gz"] = verify.sha256(index)
        with self.assertRaisesRegex(ValueError, "Size mismatch|SHA-256 mismatch"):
            verify.verify(directory, self.lock)

    def test_package_lock_must_match_the_signed_index(self):
        self.lock["packages"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "Signed index identity mismatch"):
            verify.verify(HERE / "packages", self.lock)

    def test_corrupted_deb_does_not_produce_a_staged_directory(self):
        directory = self.copy_inputs()
        package = directory / self.lock["packages"][0]["filename"]
        with package.open("r+b") as stream:
            first = stream.read(1)
            stream.seek(0)
            stream.write(bytes([first[0] ^ 1]))
        destination = self.root / "staged"
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            verify.stage(directory, destination, self.lock)
        self.assertFalse(destination.exists())

    def test_size_and_symlink_checks(self):
        path = self.root / "package"
        path.write_bytes(b"original")
        with self.assertRaisesRegex(ValueError, "Size mismatch"):
            verify.check_file(path, verify.sha256(path), 1)
        link = self.root / "linked"
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "regular input file"):
            verify.check_file(link, verify.sha256(path))

    def test_unlisted_files_fail_before_signature_verification(self):
        (self.root / "unexpected.deb").touch()
        with patch.object(verify.subprocess, "run") as command:
            with self.assertRaisesRegex(ValueError, "membership"):
                verify.verify(self.root, self.lock)
            command.assert_not_called()

    def test_local_filenames_and_duplicates_are_rejected(self):
        for name in ("", "../outside", "..", "InRelease", "/package.deb"):
            lock = copy.deepcopy(self.lock)
            lock["packages"][0]["filename"] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify.filenames(lock)

    def test_stage_contains_only_normalized_verified_debs(self):
        destination = self.root / "staged"
        verify.stage(HERE / "packages", destination, self.lock)
        self.assertEqual({p.name for p in destination.iterdir()},
                         {p["filename"] for p in self.lock["packages"]})
        for package in self.lock["packages"]:
            path = destination / package["filename"]
            verify.check_file(path, package["sha256"], package["size"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(path.stat().st_mtime, 946684800)
        with self.assertRaisesRegex(ValueError, "already exist"):
            verify.stage(HERE / "packages", destination, self.lock)


if __name__ == "__main__":
    unittest.main()
