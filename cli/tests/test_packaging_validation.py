import copy
import json
import os
from pathlib import Path
from contextlib import ExitStack
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from typer.testing import CliRunner

from veritee import cli
from veritee import packaging_validation as validation


ROOT = Path(__file__).resolve().parents[2]


class PackagingValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.app = self.directory / "app"
        shutil.copytree(ROOT / "projects/dapp", self.app)
        self.metadata = {
            "name": "Test DApp", "description": "Test",
            "app_container_image": "registry.example/app@sha256:" + "a" * 64,
            "base_os_image": "registry.example/os@sha256:" + "b" * 64,
        }
        self.write_metadata()
        self.profile = validation.local_profile(ROOT, cli.DEFAULT_GUEST_ATTESTATION_IMAGE)

    def write_metadata(self):
        (self.app / "metadata.json").write_text(json.dumps(self.metadata) + "\n")

    def check(self, **kwargs):
        return cli.validate_dapp_packaging(
            self.app, self.metadata, tls_mode="internal", tls_keyvault_name=None,
            guest_image=kwargs.pop("guest_image", cli.DEFAULT_GUEST_ATTESTATION_IMAGE),
            profile=kwargs.pop("profile", self.profile), **kwargs,
        )

    def test_valid_source_is_unchanged_and_no_registry_image_or_azure_work_occurs(self):
        before = {p.relative_to(self.app).as_posix(): p.read_bytes() for p in self.app.rglob("*") if p.is_file()}
        with mock.patch.object(cli, "run_checked") as commands, mock.patch.object(cli.requests, "get") as network:
            self.check()
        commands.assert_not_called()
        network.assert_not_called()
        self.assertEqual(before, {p.relative_to(self.app).as_posix(): p.read_bytes() for p in self.app.rglob("*") if p.is_file()})

    def test_exact_json_utf8_limits_include_quotes_escaping_and_multibyte_text(self):
        for name in ("x" * 32, "é" * 16, "😀" * 8):
            with self.subTest(name=name):
                self.metadata["name"] = name
                self.check()
        for name in ("x" * 33, "é" * 17, "😀" * 9, "x" * 31 + '"', "x" * 31 + "\\"):
            with self.subTest(name=name):
                self.metadata["name"] = name
                with self.assertRaisesRegex(cli.DeployerException, "name.*JSON-encoded UTF-8"):
                    self.check()
        self.metadata["name"] = "Test"
        self.metadata["description"] = "x" * 128
        self.check()
        self.metadata["description"] += "x"
        with self.assertRaisesRegex(cli.DeployerException, "description"):
            self.check()

    def test_bundled_rules_enforce_the_field_and_total_budgets(self):
        profile = copy.deepcopy(self.profile)
        profile["app_details"]["field_encoded_bytes"]["name"] = 40
        self.metadata["name"] = "x" * 33
        self.check(profile=profile)
        profile["app_details"]["max_bytes"] = 100
        with self.assertRaisesRegex(cli.DeployerException, "app_details exceeds 100"):
            self.check(profile=profile)

    def test_image_tags_fail_instead_of_being_re_resolved_or_rewritten(self):
        self.metadata["app_container_image"] = "registry.example/app:latest"
        with self.assertRaisesRegex(cli.DeployerException, "app_container_image must be pinned"):
            self.check()
        self.metadata["app_container_image"] += "@sha256:" + "a" * 64
        self.check()
        with self.assertRaisesRegex(cli.DeployerException, "Guest attestation image differs"):
            self.check(guest_image="registry.example/generator@sha256:" + "c" * 64)
        with self.assertRaisesRegex(cli.DeployerException, "guest_attestation_image must be pinned"):
            self.check(guest_image="registry.example/generator:latest")

    def test_equivalent_helper_tag_spelling_keeps_the_pinned_identity(self):
        image = cli.DEFAULT_GUEST_ATTESTATION_IMAGE.replace("@sha256:", ":release@sha256:")
        self.check(guest_image=image)
        self.assertEqual(
            validation.image_identity("localhost:5000/a:tag@sha256:" + "c" * 64),
            "localhost:5000/a@sha256:" + "c" * 64,
        )

    def test_extra_files_or_changed_default_scripts_cannot_be_rebuilt(self):
        (self.app / "README.md").write_text("not sent to Warden")
        with self.assertRaisesRegex(cli.DeployerException, "cannot reproduce app file README.md"):
            self.check()
        (self.app / "README.md").unlink()
        (self.app / "run.d/main").write_bytes((ROOT / "projects/templates/run.d/main").read_bytes())
        self.check()
        (self.app / "run.d/main").write_text("custom startup")
        with self.assertRaisesRegex(cli.DeployerException, "cannot reproduce app file run.d/main"):
            self.check()

    def test_empty_directories_and_symlinks_are_not_silently_ignored(self):
        (self.app / "extra").mkdir()
        with self.assertRaisesRegex(cli.DeployerException, "extra app directories"):
            self.check()
        (self.app / "extra").rmdir()
        (self.app / "linked").symlink_to(self.directory)
        with self.assertRaisesRegex(cli.DeployerException, "symlink"):
            self.check()

    def test_warden_profile_repart_and_default_script_mismatches_fail_early(self):
        for field in ("repart_files", "fallback_scripts"):
            profile = copy.deepcopy(self.profile)
            key = next(iter(profile["rebuild"][field]))
            profile["rebuild"][field][key] = "0" * 64
            with self.subTest(field=field), self.assertRaisesRegex(cli.DeployerException, "repart|default script"):
                self.check(profile=profile)
        self.check(allow_warden=True)  # An unused opt-in does not change the disk.
        self.metadata["egress_profile"] = "warden"
        self.write_metadata()
        with self.assertRaisesRegex(cli.DeployerException, "does not accept --allow-warden-egress-profile"):
            self.check(allow_warden=True)

    def test_generated_certs_are_excluded_from_the_stage_and_snapshot(self):
        certificates = self.app / "run.d/certs"
        (certificates / "private-key.pem").write_text("fixture key, never package")
        with cli.prepared_app_build_source(self.app, tls_mode="internal", tls_keyvault_name=None) as (staged, _):
            self.assertFalse((Path(staged) / "run.d/certs").exists())
        self.assertTrue((certificates / "private-key.pem").exists())
        self.check()
        self.assertFalse(any(validation.excluded_path(p) for p in validation.source_tree(self.app)["files"]))

    def test_single_site_crlf_and_cli_guest_disagreements_fail_before_packaging(self):
        for caddy in (
            "one.example {\n}\n",
            "one.example {\r\n}\r\ntwo.example {\r\n}\r\n",
            "one.example, alias.example {\n}\ntwo.example {\n}\n",
            "one.example { # inline comment\n}\ntwo.example {\n}\n",
        ):
            with self.subTest(caddy=caddy):
                (self.app / cli.DAPP_CADDYFILE_TEMPLATE).write_bytes(caddy.encode())
                with self.assertRaises((cli.DeployerException, cli.typer.BadParameter)):
                    self.check()

    def test_domain_and_api_address_limits_are_checked_after_url_expansion(self):
        host = "x" * 63 + "." + "y" * 14  # 78 chars, valid DNS, too long for API URL.
        (self.app / cli.DAPP_CADDYFILE_TEMPLATE).write_text(f"att.example {{\n}}\n{host} {{\n}}\n")
        with self.assertRaisesRegex(cli.DeployerException, "app field address"):
            cli.validate_dapp_packaging(self.app, self.metadata, tls_mode="azure_vault", tls_keyvault_name="fixture-vault",
                                        guest_image=cli.DEFAULT_GUEST_ATTESTATION_IMAGE, profile=self.profile)

    def test_os_version_comes_from_selected_release_and_must_match_optional_hint(self):
        selected = {"os_key": "a" * 64, "entry": {"release_version": "0.5.3"}}
        self.check(selected_os=selected)
        self.metadata["base_os_version"] = "wrong"
        with self.assertRaisesRegex(cli.DeployerException, "base_os_version disagrees"):
            self.check(selected_os=selected)

    def test_azure_tag_lengths_are_checked_even_for_operator_images(self):
        self.metadata["app_container_image"] = "registry.example/" + "a" * 230 + "@sha256:" + "b" * 64
        with self.assertRaisesRegex(cli.DeployerException, "Azure deployment tag.*256"):
            self.check(registration_preflight=False)

    def test_standalone_validation_is_local_even_when_a_warden_is_configured(self):
        with mock.patch.dict(os.environ, {cli.WARDEN_URL_ENV_VAR: "https://not-contacted.invalid"}), \
                mock.patch.object(cli.requests, "get", side_effect=AssertionError("no validation HTTP requests")) as network, \
                mock.patch.object(cli.os_release, "query_registry") as chain:
            result = CliRunner().invoke(cli.app, ["validate-dapp", "--app-dir", str(self.app)])
        self.assertEqual(result.exit_code, 0, result.exception)
        self.assertIn('"scope": "local_inputs"', result.stdout)
        self.assertIn('"azure_vault_availability_checked": false', result.stdout)
        network.assert_not_called()
        chain.assert_not_called()

    def test_invalid_package_inputs_fail_before_any_pull_build_or_key_creation(self):
        self.metadata["name"] = "x" * 33
        self.write_metadata()
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(cli.os_release, "resolve_selection") as resolve, \
                mock.patch.object(cli.os_release, "pull_selected") as pull, \
                mock.patch.object(cli, "run_streamable_command") as build:
            result = CliRunner().invoke(cli.app, ["package-dapp-deployable-vm-image", "--app-dir", str(self.app),
                                                  "--tls-mode", "internal", "--no-push"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("name", str(result.exception))
        resolve.assert_not_called()
        pull.assert_not_called()
        build.assert_not_called()
        self.assertFalse((self.app / "temenos_app_key").exists())

    def test_registration_transport_preserves_crlf_exact_bytes(self):
        for path in (cli.DAPP_CADDYFILE_TEMPLATE, cli.DAPP_DOCKER_COMPOSE):
            (self.app / path).write_bytes(b"test\r\nsecond line\r\n")
        payload = {}
        cli.add_register_app_file_fields(payload, self.app)
        roundtrip = json.loads(json.dumps(payload))
        self.assertEqual(roundtrip["caddyfile"].encode(), (self.app / cli.DAPP_CADDYFILE_TEMPLATE).read_bytes())
        self.assertEqual(roundtrip["docker_compose"].encode(), (self.app / cli.DAPP_DOCKER_COMPOSE).read_bytes())

    def snapshot(self):
        output = self.directory / "packaged"
        output.mkdir()
        metadata_path = output / "metadata.json"
        metadata_path.write_text(json.dumps(self.metadata) + "\n")
        (output / "pcrs.json").write_text(json.dumps({"application_root_hash": "c" * 64, "measurements": {"4": "d" * 64}}))
        selected = {"os_key": "e" * 64, "network": "preprod", "registry_address": "f" * 64,
                    "entry": {"release_version": "0.5.3"}}
        snapshot = validation.make_snapshot(self.app, metadata_path.read_bytes(), "internal",
            cli.DEFAULT_GUEST_ATTESTATION_IMAGE, "c" * 64, "d" * 64, selected, self.profile)
        (output / validation.SNAPSHOT_FILE).write_text(json.dumps(snapshot))
        return metadata_path

    def test_snapshot_detects_outbound_edits_and_caddy_compose_or_metadata_drift(self):
        metadata_file = self.snapshot()
        self.assertIsNotNone(validation.verify_snapshot(metadata_file, self.app, "internal"))
        for path in (self.app / "metadata.json", self.app / cli.DAPP_CADDYFILE_TEMPLATE, self.app / cli.DAPP_DOCKER_COMPOSE, metadata_file):
            before = path.read_bytes()
            with self.subTest(path=path.name):
                path.write_bytes(before + b"\n")
                with self.assertRaisesRegex(ValueError, "changed after packaging"):
                    validation.verify_snapshot(metadata_file, self.app, "internal")
                path.write_bytes(before)
        self.metadata["outbound"] = [{"host": "new.example", "ports": [443]}]
        self.write_metadata()
        with self.assertRaisesRegex(ValueError, "App source changed"):
            validation.verify_snapshot(metadata_file, self.app, "internal")

    def test_snapshot_ignores_generated_certs_but_checks_tls_and_measurements(self):
        metadata_file = self.snapshot()
        (self.app / "run.d/certs/new.pem").write_text("new runtime cert")
        validation.verify_snapshot(metadata_file, self.app, "internal")
        with self.assertRaisesRegex(ValueError, "TLS mode differs"):
            validation.verify_snapshot(metadata_file, self.app, "azure_vault")
        (metadata_file.parent / "pcrs.json").write_text('{"application_root_hash":"wrong","measurements":{}}')
        with self.assertRaisesRegex(ValueError, "measurements differ"):
            validation.verify_snapshot(metadata_file, self.app, "internal")

    def test_register_app_detects_drift_before_reading_the_app_key_or_posting(self):
        metadata_file = self.snapshot()
        (self.app / cli.DAPP_DOCKER_COMPOSE).write_text("changed after packaging")
        with mock.patch.object(cli, "resolve_app_key") as key, mock.patch.object(cli, "post_warden_json_response") as post:
            result = CliRunner().invoke(cli.app, ["register-app", "--metadata-path", str(metadata_file),
                "--app-dir", str(self.app), "--tls-mode", "internal", "--endpoint", "https://warden.example/dapps/register",
                "--address", "203.0.113.10", "--attestation-domain-name", "att.example", "--no-poll"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Registration input drift", str(result.exception))
        key.assert_not_called()
        post.assert_not_called()

    def test_guest_parser_matches_actual_released_awk_including_crlf(self):
        script = (ROOT / "projects/templates/run.d/main").read_text()
        awk = script.split("site_host() {", 1)[1].split("awk '", 1)[1].split("' Caddyfile.template", 1)[0]
        for caddy in ("a.example {\n}\nb.example {\n}\n", "a.example {\r\n}\r\nb.example {\r\n}\r\n",
                      "{\n  auto_https off\n}\n# note\na.example, x.example {\n}\nb.example { # comment\n}\n"):
            with self.subTest(caddy=caddy):
                actual = subprocess.run(["awk", awk], input=caddy, text=True, check=True, capture_output=True).stdout.splitlines()
                self.assertEqual(validation.guest_site_addresses(caddy), actual)

    def test_bundled_rules_do_not_inherit_an_environment_helper_override(self):
        with mock.patch.dict(os.environ, {"VERITEE_GUEST_ATTESTATION_IMAGE": "wrong:latest"}):
            profile = cli.local_registration_profile()
        self.assertEqual(profile["app_details"]["version"], 1)
        self.assertEqual(profile["rebuild"]["guest_attestation_image"], cli.DEFAULT_GUEST_ATTESTATION_IMAGE)

    def test_shared_serde_json_projection_vectors(self):
        fixture = json.loads((ROOT / "cli/tests/fixtures/registration-projection-v1.json").read_text())
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(len(validation.encoded_json(case["value"])), case["encoded_bytes"])
                if case["accepted"]:
                    validation.validate_projection({case["field"]: case["value"]}, self.profile, complete=False)
                else:
                    with self.assertRaises(ValueError):
                        validation.validate_projection({case["field"]: case["value"]}, self.profile, complete=False)

    def test_registration_checks_local_snapshot_without_validation_or_registry_requests(self):
        metadata_file = self.snapshot()
        (metadata_file.parent / "policy.json").write_text('{}')
        arguments = ["register-app", "--metadata-path", str(metadata_file), "--app-dir", str(self.app),
                     "--tls-mode", "internal", "--endpoint", "https://warden.example/dapps/register",
                     "--address", "203.0.113.10", "--attestation-domain-name", "att.example",
                     "--app-key", "fixture-only-key", "--no-poll"]
        with mock.patch.object(cli, "get_warden_json", side_effect=AssertionError("no extra Warden reads")) as get, \
                mock.patch.object(cli.os_release, "query_registry") as chain, \
                mock.patch.object(cli, "post_warden_json_response", return_value=(202,{"job_id":"fixture","status_url":"/jobs/fixture"})) as post:
            result = CliRunner().invoke(cli.app, arguments)
        self.assertEqual(result.exit_code, 0, result.exception)
        self.assertEqual(post.call_args.args[1]["metadata_json"].encode(), metadata_file.read_bytes())
        get.assert_not_called()
        chain.assert_not_called()
        for option, value, error in [("--address", "https://" + "x" * 63 + ".example.test", "app field address"),
                                      ("--base-os-version", "different", "packaged OS release")]:
            changed = list(arguments)
            if option in changed:
                changed[changed.index(option) + 1] = value
            else:
                changed += [option, value]
            with self.subTest(option=option), mock.patch.object(cli, "get_warden_json") as get, \
                    mock.patch.object(cli, "post_warden_json_response") as post:
                result = CliRunner().invoke(cli.app, changed)
                self.assertNotEqual(result.exit_code, 0)
                self.assertIn(error, str(result.exception))
                get.assert_not_called()
                post.assert_not_called()

    def test_deploy_enforces_the_vault_name_in_the_actual_packaged_metadata(self):
        packaged = self.directory / cli.DAPP_OUTPUT_DIR
        packaged.mkdir()
        (packaged / "metadata.json").write_text(json.dumps({**self.metadata, "tls_keyvault_name": "original-fixture-vault"}))
        (packaged / "pcrs.json").write_text(json.dumps({"application_root_hash": "c" * 64, "measurements": {"4": "d" * 64}}))
        (packaged / "tls_mode").write_text("azure_vault\n")
        with mock.patch.object(cli, "repo_root_from_cwd", return_value=self.directory), \
                mock.patch.object(cli, "require_azure_subscription_id") as subscription, \
                mock.patch.object(cli, "resize_azure_disk") as conversion, \
                self.assertRaisesRegex(cli.DeployerException, "does not match the Key Vault bound"):
            cli.create_vm(azure_snp=True, resource_group="fixture-rg", location="eastus",
                          tls_keyvault_name="different-fixture-vault", hydrate_policy=False)
        subscription.assert_not_called()
        conversion.assert_not_called()

    def test_packaging_records_the_frozen_inputs_next_to_outputs_and_never_embeds_certs(self):
        selected = {"os_key": "e" * 64, "network": "preprod", "registry_address": "f" * 64,
            "entry": {"release_version": "0.5.3", "pcr4": "d" * 64},
            "manifest": json.dumps({"publication": {"reference": self.metadata["base_os_image"]}})}
        certificate = self.app / "run.d/certs/privkey.pem"
        certificate.write_text("private certificate fixture must stay outside disk")
        before = Path.cwd()
        os.chdir(self.directory)
        self.addCleanup(os.chdir, before)
        events = []
        def build(command, **kwargs):
            events.append("build")
            staged = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--APP_DIR=")))
            self.assertFalse((staged / "run.d/certs").exists())
            output = self.directory / cli.DAPP_OUTPUT_DIR
            output.mkdir()
            (output / "pcrs.json").write_text(json.dumps({"application_root_hash": "c" * 64, "measurements": {"4": "d" * 64}}))
            return "fixture build output"
        with ExitStack() as patches:
            patches.enter_context(mock.patch.object(cli, "repo_root_from_cwd", return_value=ROOT))
            network = patches.enter_context(mock.patch.object(cli.requests, "get", side_effect=AssertionError("no extra Warden validation calls")))
            patches.enter_context(mock.patch.object(cli.os_release, "resolve_selection", side_effect=lambda *a, **k: events.append("os") or selected))
            patches.enter_context(mock.patch.object(cli.os_release, "pull_selected", side_effect=lambda *a: events.append("pull")))
            patches.enter_context(mock.patch.object(cli, "require_acr_name", return_value="fixture"))
            patches.enter_context(mock.patch.object(cli, "get_acr_access_token", return_value="fixture-token"))
            patches.enter_context(mock.patch.object(cli, "preflight_check_earthly_secrets"))
            patches.enter_context(mock.patch.object(cli, "preflight_check_earthly_copy_sources"))
            patches.enter_context(mock.patch.object(cli, "run_streamable_command", side_effect=build))
            patches.enter_context(mock.patch.object(cli, "write_application_root_hash", return_value="c" * 64))
            patches.enter_context(mock.patch.object(cli, "write_pcr_measurements"))
            patches.enter_context(mock.patch.object(cli, "resolve_policy_template", return_value=Path("fixture-policy")))
            patches.enter_context(mock.patch.object(cli, "write_os_security_files"))
            patches.enter_context(mock.patch.object(cli, "resize_azure_disk", side_effect=lambda *a: events.append("convert")))
            result = CliRunner().invoke(cli.app, ["package-dapp-deployable-vm-image", "--app-dir", str(self.app),
                "--tls-mode", "internal", "--no-push"])
        self.assertEqual(result.exit_code, 0, result.exception)
        self.assertEqual(events, ["os", "pull", "build", "convert"])
        network.assert_not_called()
        metadata_file = self.directory / cli.DAPP_OUTPUT_DIR / "metadata.json"
        snapshot_path = metadata_file.parent / validation.SNAPSHOT_FILE
        self.assertEqual(snapshot_path.stat().st_mode & 0o777, 0o600)
        snapshot = validation.verify_snapshot(metadata_file, self.app, "internal")
        self.assertEqual(snapshot["application_root_hash"], "c" * 64)
        self.assertFalse(any("certs" in p for p in snapshot["source"]["files"]))
        self.assertTrue(certificate.is_file())
        self.assertIn(validation.SNAPSHOT_FILE, cli.deployable_vm_push_artifacts())


if __name__ == "__main__":
    unittest.main()
