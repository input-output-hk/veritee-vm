import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from unittest import mock

from typer.testing import CliRunner

from veritee import cli, packaging_validation as validation


ROOT = Path(__file__).resolve().parents[2]
TEST_PROJECT = ROOT / "projects/proof_server_preprod"


@contextmanager
def working_directory(path):
    previous = Path.cwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(previous)


class ExternalAppSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "application"
        shutil.copytree(TEST_PROJECT, self.source)
        (self.source / "run.d/certs").mkdir()
        self.metadata = {
            "name": "External app", "description": "External folder fixture",
            "app_container_image": "registry.example/app@sha256:" + "a" * 64,
            "base_os_image": "registry.example/os@sha256:" + "b" * 64,
        }
        (self.source / "metadata.json").write_text(json.dumps(self.metadata) + "\n")

    def test_external_folder_uses_checkout_platform_files_and_preserves_source_bytes(self):
        # An app parent's partition definitions must never become platform input.
        (self.directory / "10-app.conf").write_text("unrelated external partition definition")
        compose = self.source / cli.DAPP_DOCKER_COMPOSE
        compose.chmod(0o600)
        os.utime(compose, (1234567890, 1234567890))
        source_stat = compose.stat()
        before = validation.source_tree(self.source)
        cli.validate_dapp_packaging(
            self.source, self.metadata, tls_mode="internal", tls_keyvault_name=None,
            guest_image=cli.DEFAULT_GUEST_ATTESTATION_IMAGE,
        )
        with cli.prepared_app_build_source(
            self.source, tls_mode="internal", tls_keyvault_name=None,
        ) as (relative, _):
            staged = ROOT / relative
            self.assertTrue(staged.is_relative_to(ROOT / ".temenos/app-build"))
            self.assertFalse((staged.parent / "10-app.conf").exists())
            staged_compose = staged / cli.DAPP_DOCKER_COMPOSE
            self.assertEqual(staged_compose.read_bytes(), compose.read_bytes())
            self.assertEqual(staged_compose.stat().st_mode, source_stat.st_mode)
            self.assertEqual(staged_compose.stat().st_mtime_ns, source_stat.st_mtime_ns)
            self.assertEqual((staged / "metadata.json").stat().st_mtime_ns, 0)
            cli.preflight_check_earthly_copy_sources(
                cli.EARTHLY_APP_DISK_TARGET, {"APP_DIR": relative},
            )
        self.assertFalse(staged.exists())
        self.assertEqual(validation.source_tree(self.source), before)

    def test_git_directory_and_worktree_pointer_are_excluded_from_every_input_view(self):
        before = validation.source_tree(self.source)
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        for git_is_directory in (True, False):
            with self.subTest(git_is_directory=git_is_directory):
                self.assertEqual(validation.source_tree(self.source), before)
                with cli.prepared_app_build_source(
                    self.source, tls_mode="internal", tls_keyvault_name=None,
                ) as (relative, _):
                    self.assertFalse((ROOT / relative / ".git").exists())
                if git_is_directory:
                    shutil.rmtree(self.source / ".git")
                    (self.source / ".git").write_text("gitdir: /external/worktree/metadata\n")

    def test_git_and_certificate_updates_do_not_hide_measured_file_drift(self):
        output = self.directory / "packaged"
        output.mkdir()
        metadata_file = output / "metadata.json"
        metadata_file.write_bytes((self.source / "metadata.json").read_bytes())
        selected = {"os_key": "e" * 64, "network": "preprod", "registry_address": "f" * 64,
                    "entry": {"release_version": "fixture"}}
        snapshot = validation.make_snapshot(
            self.source, metadata_file.read_bytes(), "internal", cli.DEFAULT_GUEST_ATTESTATION_IMAGE,
            "c" * 64, "d" * 64, selected, cli.local_registration_profile(),
        )
        (output / validation.SNAPSHOT_FILE).write_text(json.dumps(snapshot))
        (output / "pcrs.json").write_text(json.dumps({
            "application_root_hash": "c" * 64, "measurements": {"4": "d" * 64},
        }))
        (self.source / ".git").mkdir()
        (self.source / ".git/config").write_text("changed Git metadata\n")
        (self.source / "run.d/certs/generated.pem").write_text("certificate fixture\n")
        validation.verify_snapshot(metadata_file, self.source, "internal")
        with (self.source / cli.DAPP_DOCKER_COMPOSE).open("a") as stream:
            stream.write("# changed measured input\n")
        with self.assertRaisesRegex(ValueError, "App source changed"):
            validation.verify_snapshot(metadata_file, self.source, "internal")

    def test_relative_source_and_default_example_resolve_from_checkout_subdirectory(self):
        with working_directory(ROOT / "cli"):
            relative = Path(os.path.relpath(self.source, Path.cwd()))
            self.assertEqual(cli.resolve_app_source_dir(relative), self.source)
            self.assertEqual(cli.resolve_app_source_dir(), ROOT / "examples/dapp")
            self.assertEqual(cli.resolve_register_app_source_dir(Path("unused"), relative), self.source)

    def test_default_packaged_metadata_uses_checkout_root_but_explicit_paths_use_caller(self):
        checkout = self.directory / "checkout"
        (checkout / "cli/veritee").mkdir(parents=True)
        (checkout / "cli/veritee/cli.py").write_text("# checkout marker\n")
        packaged = checkout / cli.DAPP_OUTPUT_DIR / cli.APP_METADATA_FILE
        packaged.parent.mkdir()
        packaged.write_text(json.dumps(self.metadata))
        with working_directory(checkout / "cli"):
            self.assertEqual(cli.resolve_app_metadata_path(None), packaged)
            explicit = Path("../other-package/metadata.json")
            self.assertEqual(cli.resolve_app_metadata_path(explicit), explicit)

    def test_recursive_checkout_and_build_sources_fail_before_staging(self):
        for source in (ROOT, ROOT.parent, ROOT / ".temenos"):
            source.mkdir(exist_ok=True)
            with self.subTest(source=source), mock.patch.object(cli.tempfile, "TemporaryDirectory") as stage:
                with self.assertRaisesRegex(cli.DeployerException, "must not contain"):
                    cli.resolve_app_source_dir(source)
                stage.assert_not_called()

    def test_registration_requires_explicit_source_before_key_or_network_work(self):
        with mock.patch.object(cli, "resolve_app_key") as key, \
                mock.patch.object(cli, "post_warden_json_response") as post:
            result = CliRunner().invoke(cli.app, ["register-app"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Pass --app-dir", str(result.exception))
        key.assert_not_called()
        post.assert_not_called()

    def test_app_disk_command_helpers_require_and_forward_the_selected_source(self):
        values = {
            "app_container_image": self.metadata["app_container_image"],
            "guest_attestation_image": cli.DEFAULT_GUEST_ATTESTATION_IMAGE,
            "registry": "fixture.azurecr.io", "acr_token": "fixture-token",
            "tls_mode": "internal",
        }
        staged_source = ".temenos/app-build/fixture/app"
        for helper, extra in (
            (cli.build_earthly_app_disk_command, {}),
            (cli.build_earthly_extend_os_command, {"persist_size": "2G"}),
        ):
            with self.subTest(helper=helper.__name__):
                command = helper(app_dir=staged_source, **values, **extra)
                self.assertEqual(
                    [value for value in command if value.startswith("--APP_DIR=")],
                    ["--APP_DIR=" + staged_source],
                )
            for missing in ("", " \t"):
                with self.subTest(helper=helper.__name__, app_dir=missing):
                    with self.assertRaisesRegex(cli.DeployerException, "APP_DIR must be provided explicitly"):
                        helper(app_dir=missing, **values, **extra)

    @unittest.skipUnless(os.environ.get("VERITEE_TEST_EARTHLY"), "Set VERITEE_TEST_EARTHLY to test actual Earthly argument admission")
    def test_earthly_app_targets_reject_missing_or_empty_source_before_building(self):
        empty_inputs = self.directory / "empty.inputs"
        empty_inputs.write_text("")
        for target in (
            "veritee-os-azure-snp-combined",
            cli.EARTHLY_EXTEND_OS_TARGET,
            cli.EARTHLY_APP_DISK_TARGET,
        ):
            for supplied in ([], ["--APP_DIR="]):
                with self.subTest(target=target, supplied=supplied):
                    result = subprocess.run([
                        os.environ["VERITEE_TEST_EARTHLY"], "--no-output",
                        "--arg-file-path", str(empty_inputs),
                        "--env-file-path", str(empty_inputs),
                        "--secret-file-path", str(empty_inputs),
                        "-P", "+" + target, *supplied,
                    ], cwd=ROOT, capture_output=True, text=True, timeout=60)
                    output = result.stdout + result.stderr
                    self.assertNotEqual(result.returncode, 0, output)
                    self.assertIn("value not supplied for required ARG: APP_DIR", output)
                    self.assertNotIn("examples/dapp", output)
                    self.assertNotIn("debian-systemd", output)

    def test_build_command_stages_external_relative_source_in_the_checkout(self):
        def build(command, **kwargs):
            self.assertEqual(kwargs["cwd"], ROOT)
            staged = ROOT / next(value.split("=", 1)[1] for value in command if value.startswith("--APP_DIR="))
            self.assertTrue(staged.is_dir())
            self.assertEqual(json.loads((staged / "metadata.json").read_bytes())["app_container_image"], self.metadata["app_container_image"])
            return "fixture build"

        with working_directory(ROOT / "cli"):
            relative = os.path.relpath(self.source, Path.cwd())
            with mock.patch.object(cli, "require_acr_name", return_value="fixture"), \
                    mock.patch.object(cli, "get_acr_access_token", return_value="fixture-token"), \
                    mock.patch.object(cli, "run_streamable_command", side_effect=build) as run:
                result = CliRunner().invoke(cli.app, [
                    "build-app-disk", "--image", self.metadata["app_container_image"],
                    "--app-dir", relative, "--tls-mode", "internal",
                ])
            self.assertEqual(result.exit_code, 0, result.exception)
            self.assertEqual(Path.cwd(), ROOT / "cli")
            run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
