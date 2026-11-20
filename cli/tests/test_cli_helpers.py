import hashlib
import logging
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import typer

from veritee import cli
from typer.testing import CliRunner

cli.log.setLevel(logging.CRITICAL)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text="", reason="OK", json_error=False):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.reason = reason
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise ValueError("invalid json")
        return self._payload


class AttestedProveStatusTests(unittest.TestCase):
    def invoke_response(self, status, body):
        from veritee.attested_channel import HttpTunnelResponse

        with mock.patch("veritee.attested_channel.AttestedChannelClient") as client:
            client.return_value.request.return_value = HttpTunnelResponse(status=status, headers={}, body=body)
            return CliRunner().invoke(cli.app, [
                "attested-prove", "--dapp-id", "test-app", "--payload", "{}", "--skip-warden",
            ])

    def test_application_errors_and_redirects_exit_nonzero_without_printing_a_proof(self):
        for status in (307, 400, 500):
            with self.subTest(status=status):
                result = self.invoke_response(status, b"upstream error body")
                self.assertNotEqual(result.exit_code, 0)
                self.assertIsInstance(result.exception, cli.DeployerException)
                self.assertIn(f"HTTP {status}", str(result.exception))
                self.assertNotIn("upstream error body", result.stdout)

    def test_success_prints_the_binary_response(self):
        result = self.invoke_response(200, b"\x00\xff")
        self.assertEqual(result.exit_code, 0, result.exception)
        self.assertIn("AP8=", result.stdout)


class ExpectedApplicationVerificationTests(unittest.TestCase):
    def test_verify_sends_expected_application_only_when_supplied(self):
        for expected in (None, "ab" * 32):
            args = ["verify-attestation", "--dapp-id", "cd" * 32,
                    "--tee-attestation", "{}", "--payload", "payload", "--nonce", "nonce",
                    "--endpoint", "https://warden.example/dapps/verify_attestation"]
            if expected is not None:
                args += ["--expected-application-id", expected]
            with mock.patch.object(cli, "post_warden_json_response", return_value=(202, {"verified": True})) as post:
                result = CliRunner().invoke(cli.app, args)
            self.assertEqual(result.exit_code, 0, result.exception)
            body = post.call_args.args[1]
            if expected is None:
                self.assertNotIn("expected_application_id", body)
            else:
                self.assertEqual(body["expected_application_id"], expected)

    def test_attested_prove_forwards_expected_application(self):
        from veritee.attested_channel import HttpTunnelResponse
        with (mock.patch("veritee.attested_channel.make_warden_verifier") as verifier,
              mock.patch("veritee.attested_channel.AttestedChannelClient") as client):
            client.return_value.request.return_value = HttpTunnelResponse(200, {}, b"proof")
            result = CliRunner().invoke(cli.app, [
                "attested-prove", "--dapp-id", "cd" * 32, "--payload", "{}",
                "--warden-endpoint", "https://warden.example/dapps/verify_attestation",
                "--expected-application-id", "ab" * 32])
        self.assertEqual(result.exit_code, 0, result.exception)
        self.assertEqual(verifier.call_args.kwargs["expected_application_id"], "ab" * 32)


class RepoRootResolutionTests(unittest.TestCase):
    def test_finds_checkout_root_from_cli_subdirectories(self):
        repo_root = Path(__file__).resolve().parents[2]
        for directory in (repo_root, repo_root / "cli", repo_root / "cli/veritee"):
            with self.subTest(directory=directory):
                with mock.patch.object(cli.Path, "cwd", return_value=directory):
                    self.assertEqual(cli.repo_root_from_cwd(), repo_root)

    def test_preserves_cwd_outside_a_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            with mock.patch.object(cli.Path, "cwd", return_value=directory):
                self.assertEqual(cli.repo_root_from_cwd(), directory)


class DeployerTerraformLoggingTests(unittest.TestCase):
    def terraform_apply_environment(self, process_environment):
        with tempfile.TemporaryDirectory() as tmpdir:
            work_dir = Path(tmpdir)
            with (
                mock.patch.dict(os.environ, process_environment, clear=True),
                mock.patch.object(
                    cli.Deployer,
                    "_Deployer__assert_tf_available",
                ),
                mock.patch.object(
                    cli.Deployer,
                    "_Deployer__run_subprocess",
                ) as run_subprocess,
            ):
                cli.Deployer._Deployer__tf_apply(work_dir)

        return run_subprocess.call_args.kwargs["env"]

    def test_terraform_debug_logging_is_disabled_by_default(self):
        environment = self.terraform_apply_environment({})

        self.assertNotIn("TF_LOG", environment)
        self.assertNotIn("TF_LOG_PATH", environment)

    def test_temenos_debug_enables_terraform_debug_log(self):
        environment = self.terraform_apply_environment({"VERITEE_DEBUG": "1"})

        self.assertEqual(environment["TF_LOG"], "DEBUG")
        self.assertTrue(environment["TF_LOG_PATH"].endswith("terraform-debug.log"))


class RegistrationInputTests(unittest.TestCase):
    def test_validate_attestation_domain_name_accepts_domain_only(self):
        self.assertEqual(
            cli.validate_attestation_domain_name("Attestation.Example.COM."),
            "attestation.example.com",
        )

    def test_validate_attestation_domain_name_rejects_urls(self):
        for value in (
            "https://attestation.example.com",
            "attestation.example.com:443",
            "attestation.example.com/path",
        ):
            with self.subTest(value=value):
                with self.assertRaises(cli.typer.BadParameter):
                    cli.validate_attestation_domain_name(value)

    def test_load_register_app_disk_files_reads_selected_app_dir(self):
        app_dir = Path("projects/dapp")

        self.assertEqual(
            cli.load_register_app_disk_files(app_dir),
            {
                "caddyfile": (app_dir / "run.d" / "Caddyfile.template").read_text(),
                "docker_compose": (app_dir / "run.d" / "docker-compose.yml").read_text(),
            },
        )

    def test_load_register_app_disk_files_requires_caddyfile_and_compose(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            app_dir = Path(tmpdir)
            (app_dir / "run.d").mkdir()
            (app_dir / "run.d" / "Caddyfile.template").write_text("example.com {}\n")

            with self.assertRaises(cli.DeployerException) as raised:
                cli.load_register_app_disk_files(app_dir)

            self.assertIn("docker-compose.yml", str(raised.exception))

    def test_registration_replays_packaged_outbound_policy(self):
        source_metadata = {
            "name": "Example DApp",
            "description": "Example",
            "app_container_image": "registry.example/app:1",
            "base_os_image": "registry.example/base:1",
            "outbound": [{"host": "downloads.example.com", "ports": [443]}],
        }
        packaged_metadata = {
            **{key: source_metadata[key] for key in cli.APP_METADATA_FIELDS},
            "outbound_policy_version": 2,
            "outbound": [{"host": "downloads.example.com", "ports": [443]}],
            "platform_outbound": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source_dir = root / "source"
            source_dir.mkdir()
            source_path = source_dir / cli.APP_METADATA_FILE
            source_path.write_text(json.dumps(source_metadata))
            packaged_path = root / "metadata.json"
            packaged_text = json.dumps(packaged_metadata, indent=2) + "\n"
            packaged_path.write_text(packaged_text)

            self.assertEqual(
                cli.read_register_app_metadata_json(packaged_path, source_dir),
                packaged_text,
            )

    def test_default_attestation_domain_from_caddyfile_uses_first_site_host(self):
        caddyfile = Path("projects/dapp/run.d/Caddyfile.template").read_text()

        self.assertEqual(
            cli.default_attestation_domain_from_caddyfile(caddyfile),
            "attestation-endpoint.api.mydapp.midnight.io",
        )

    def test_generic_template_shared_upstream_keeps_both_tls_hostnames(self):
        caddyfile = Path("projects/dapp/run.d/Caddyfile.template")
        expected = [
            "attestation-endpoint.api.mydapp.midnight.io",
            "api.mydapp.midnight.io",
        ]
        self.assertEqual(cli.caddyfile_site_hosts(caddyfile), expected)

        # Run the guest's actual hostname extractor against the same template.
        startup = Path("projects/templates/run.d/main").read_text()
        start = startup.index("site_host() {")
        end = startup.index("\n}\n", start) + 2
        result = subprocess.run(
            ["bash", "-c", startup[start:end] + "\nsite_host 1\nsite_host 2\n"],
            cwd=caddyfile.parent,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.splitlines(), expected)

    def test_optional_deployment_domain_skips_hydration_when_metadata_is_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_file = Path(tmpdir) / "metadata.json"
            with mock.patch.object(cli.log, "warning") as warning:
                result = cli.resolve_optional_deployment_attestation_domain(
                    metadata_file,
                    None,
                )

        self.assertIsNone(result)
        warning.assert_called_once()
        self.assertIn("skipping automatic policy hydration", warning.call_args.args[0])

    def test_optional_deployment_domain_accepts_explicit_value_without_metadata(self):
        self.assertEqual(
            cli.resolve_optional_deployment_attestation_domain(
                Path("missing/metadata.json"),
                "Attestation.Example.COM.",
            ),
            "attestation.example.com",
        )

    def test_optional_deployment_domain_skips_hydration_without_matching_app_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            metadata_file = root / "metadata.json"
            metadata_file.write_text(
                Path("projects/dapp/metadata.json").read_text()
            )
            app_source_root = root / "projects"
            app_source_root.mkdir()

            with mock.patch.object(cli, "APP_SOURCE_ROOT", app_source_root):
                result = cli.resolve_optional_deployment_attestation_domain(
                    metadata_file,
                    None,
                )

        self.assertIsNone(result)

    def test_optional_deployment_domain_rejects_invalid_explicit_value(self):
        with self.assertRaises(typer.BadParameter):
            cli.resolve_optional_deployment_attestation_domain(
                Path("missing/metadata.json"),
                "https://attestation.example.com",
            )

    def test_caddyfile_site_hosts_ignores_global_options_block(self):
        caddyfile = Path("projects/recovery-proverd/run.d/Caddyfile.template").read_text()

        self.assertEqual(
            cli.caddyfile_site_hosts(caddyfile),
            [
                "attestation-endpoint.api.recovery-proverd.midnight.io",
                "api.recovery-proverd.midnight.io",
            ],
        )

    def test_single_caddy_site_is_both_attestation_and_api_host(self):
        app_dir = Path("projects/warden")

        self.assertEqual(
            cli.default_register_attestation_domain("azure_vault", app_dir),
            "warden.wastedp.io",
        )
        self.assertEqual(
            cli.default_register_address("azure_vault", app_dir),
            "https://warden.wastedp.io",
        )


class AppBuildSourceTests(unittest.TestCase):
    def test_persist_size_uses_metadata_default_and_explicit_override(self):
        metadata = {"persist_size": "16G"}

        self.assertEqual(cli.resolve_persist_size(None, metadata), "16G")
        self.assertEqual(cli.resolve_persist_size("32G", metadata), "32G")
        self.assertEqual(cli.resolve_persist_size(None, {}), cli.DEFAULT_PERSIST_SIZE)

    def test_warden_metadata_requests_persistent_build_cache_capacity(self):
        metadata = cli.load_app_source_metadata(Path("projects/warden"))

        self.assertEqual(metadata["persist_size"], "32G")

    def test_packaging_reuses_measured_keyvault_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            app_dir = Path(tmpdir)
            (app_dir / cli.APP_METADATA_FILE).write_text(
                json.dumps({"tls_keyvault_name": "custom-vault"})
            )

            self.assertEqual(
                cli.resolve_packaging_tls_keyvault_name(
                    tls_mode="azure_vault",
                    app_dir=app_dir,
                    app_name="Example DApp",
                    value=None,
                ),
                "custom-vault",
            )

    def test_stages_shipped_metadata_without_mutating_source(self):
        source_metadata = {
            "name": "Example DApp",
            "description": "Example",
            "app_container_image": "registry.example/app:1",
            "base_os_image": "registry.example/base:1",
            "outbound": [{"host": "downloads.example.com", "ports": [443]}],
        }
        shipped_metadata = {
            **{key: source_metadata[key] for key in cli.APP_METADATA_FIELDS},
            "outbound_policy_version": 2,
            "outbound": [{"host": "downloads.example.com", "ports": [443]}],
            "platform_outbound": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "app"
            source_dir.mkdir()
            repart_definition = Path(tmpdir) / "10-app.conf"
            repart_definition.write_text("[Partition]\nType=root\n")
            source_path = source_dir / cli.APP_METADATA_FILE
            source_text = json.dumps(source_metadata, indent=2) + "\n"
            source_path.write_text(source_text)
            run_dir = source_dir / "run.d"
            run_dir.mkdir()
            (run_dir / "docker-compose.yml").write_text(
                """services:
  app:
    image: dapp:tee
    networks: [constrained-app]
networks:
  constrained-app:
    driver: bridge
    internal: true
"""
            )

            with mock.patch.object(
                cli,
                "prepare_shipped_metadata",
                return_value=shipped_metadata,
            ):
                with cli.prepared_app_build_source(
                    source_dir,
                    tls_mode="internal",
                    tls_keyvault_name=None,
                ) as (staged_dir_name, staged_metadata):
                    staged_dir = Path(staged_dir_name)
                    self.assertTrue(staged_dir.is_dir())
                    self.assertEqual(
                        (staged_dir.parent / "10-app.conf").read_text(),
                        repart_definition.read_text(),
                    )
                    self.assertEqual(
                        json.loads((staged_dir / cli.APP_METADATA_FILE).read_text()),
                        shipped_metadata,
                    )
                    self.assertEqual(staged_metadata, shipped_metadata)
                    cli.preflight_check_earthly_copy_sources(
                        cli.EARTHLY_APP_DISK_TARGET,
                        {"APP_DIR": staged_dir_name},
                    )

                self.assertFalse(staged_dir.exists())
            self.assertEqual(source_path.read_text(), source_text)

class AzureResourceNameTests(unittest.TestCase):
    def test_default_vm_name_is_derived_from_app_name(self):
        self.assertEqual(
            cli.default_vm_name_for_app("Midnight Proof Server - preprod"),
            "temenos-midnight-proof-server-preprod-vm",
        )

    def test_default_gallery_name_is_derived_from_app_name(self):
        self.assertEqual(
            cli.default_gallery_name_for_app("Midnight Proof Server - preprod"),
            "temenos_midnight_proof_server_preprod_gallery",
        )

    def test_default_resource_names_are_bounded(self):
        long_name = "This DApp Name Is Ridiculously Long And Keeps Going For No Good Reason"

        self.assertLessEqual(len(cli.default_vm_name_for_app(long_name)), 64)
        self.assertLessEqual(len(cli.default_gallery_name_for_app(long_name)), 64)


class AzureDeploymentInventoryTests(unittest.TestCase):
    @staticmethod
    def _resource_group(
        name="temenos-demo-rg",
        deployment_id="demo-20260918t120000z-abcd1234",
        managed="true",
    ):
        return {
            "name": name,
            "location": "eastus",
            "tags": {
                cli.VERITEE_MANAGED_TAG: managed,
                cli.VERITEE_DEPLOYMENT_ID_TAG: deployment_id,
                "temenos_app_name": "Demo",
                "temenos_app_image": "registry/dapp:1.0.0",
                "temenos_base_os_image": "registry/os:0.3.1",
                "temenos_vm_name": "temenos-demo-vm",
                "temenos_created_at": "2026-09-18T12:00:00Z",
                "temenos_app_root_hash": "a" * 64,
                "temenos_tls_mode": "internal",
                "temenos_storage_account": "temenaccdemo",
                "temenos_storage_container": "temencondemo",
            },
        }

    def test_deployment_id_and_tags_capture_reproducibility_identity(self):
        created_at = datetime(2026, 9, 18, 12, 34, 56, tzinfo=timezone.utc)
        deployment_id = cli.generate_deployment_id(
            "Midnight Intents MPC Node",
            created_at=created_at,
            random_suffix="abcd1234",
        )
        tags = cli.build_deployment_tags(
            metadata={
                "name": "Midnight Intents MPC Node",
                "app_container_image": "registry/dapp@sha256:" + "1" * 64,
                "base_os_image": "registry/os@sha256:" + "2" * 64,
            },
            application_root_hash="3" * 64,
            deployment_id=deployment_id,
            vm_name="temenos-intents-vm",
            created_at=cli.utc_timestamp(created_at),
            git_sha="4" * 40,
            tls_mode="azure_vault",
            tls_keyvault_name="temenos-intents-tls",
        )

        self.assertEqual(
            deployment_id,
            "midnight-intents-mpc-node-20260918t123456z-abcd1234",
        )
        self.assertEqual(tags[cli.VERITEE_MANAGED_TAG], "true")
        self.assertEqual(tags[cli.VERITEE_DEPLOYMENT_ID_TAG], deployment_id)
        self.assertEqual(tags["temenos_created_at"], "2026-09-18T12:34:56Z")
        self.assertEqual(tags["temenos_app_root_hash"], "3" * 64)
        self.assertEqual(
            tags["temenos_app_image"],
            "registry/dapp@sha256:" + "1" * 64,
        )
        self.assertEqual(
            tags["temenos_base_os_image"],
            "registry/os@sha256:" + "2" * 64,
        )
        self.assertEqual(tags["temenos_app_image_digest"], "sha256:" + "1" * 64)
        self.assertEqual(tags["temenos_os_image_digest"], "sha256:" + "2" * 64)
        self.assertEqual(tags["temenos_git_sha"], "4" * 40)
        self.assertEqual(tags["temenos_tls_mode"], "azure_vault")
        self.assertEqual(tags["temenos_tls_keyvault_name"], "temenos-intents-tls")

    def test_deployment_summary_includes_image_references(self):
        summary = cli.deployment_summary(self._resource_group())

        self.assertEqual(summary["app_image"], "registry/dapp:1.0.0")
        self.assertEqual(summary["base_os_image"], "registry/os:0.3.1")
        self.assertEqual(summary["tls_mode"], "internal")

    def test_destroy_details_render_selected_deployment_without_raw_tags(self):
        with mock.patch.object(cli.typer, "echo") as echo:
            cli.print_deployment_details(self._resource_group())

        output = "\n".join(call.args[0] for call in echo.call_args_list)
        self.assertIn(
            "Deployment ID         : demo-20260918t120000z-abcd1234",
            output,
        )
        self.assertIn("Resource group        : temenos-demo-rg", output)
        self.assertIn("Base OS               : registry/os:0.3.1", output)
        self.assertIn("DApp image            : registry/dapp:1.0.0", output)
        self.assertIn("Application root hash : " + "a" * 64, output)
        self.assertNotIn("temenos_managed", output)

    def test_inventory_storage_is_discovered_from_azure_tags(self):
        account = {
            "name": "temenosinventorywus",
            "resourceGroup": "temenos-inventory-rg",
            "tags": {
                cli.INVENTORY_COMPONENT_TAG: cli.INVENTORY_COMPONENT_TAG_VALUE,
            },
        }
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                cli,
                "query_inventory_storage_accounts",
                return_value=[account],
            ) as query,
        ):
            resolved = cli.require_inventory_storage("sub")

        self.assertEqual(resolved, ("temenosinventorywus", "temenos-inventory"))
        query.assert_called_once_with("sub")

    def test_inventory_storage_environment_override_skips_discovery(self):
        with (
            mock.patch.dict(
                os.environ,
                {
                    cli.INVENTORY_STORAGE_ACCOUNT_ENV_VAR: "explicitaccount",
                    cli.INVENTORY_CONTAINER_ENV_VAR: "explicit-container",
                },
                clear=True,
            ),
            mock.patch.object(cli, "query_inventory_storage_accounts") as query,
        ):
            resolved = cli.require_inventory_storage("sub")

        self.assertEqual(resolved, ("explicitaccount", "explicit-container"))
        query.assert_not_called()

    def test_inventory_storage_requires_initialization_when_not_found(self):
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                cli,
                "query_inventory_storage_accounts",
                return_value=[],
            ),
        ):
            with self.assertRaisesRegex(cli.DeployerException, "init-inventory"):
                cli.require_inventory_storage("sub")

    def test_init_inventory_reuses_tagged_account(self):
        account = {
            "name": "temenosinventorywus",
            "resourceGroup": "temenos-inventory-rg",
            "tags": {
                cli.INVENTORY_COMPONENT_TAG: cli.INVENTORY_COMPONENT_TAG_VALUE,
            },
        }
        commands = []

        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(cli, "require_azure_subscription_id", return_value="sub"),
            mock.patch.object(cli, "query_azure_storage_accounts", return_value=[account]),
            mock.patch.object(cli, "print_phase"),
            mock.patch.object(cli, "wait_for_inventory_storage_account") as wait,
            mock.patch.object(
                cli,
                "run_checked",
                side_effect=lambda command, **_: commands.append(command)
                or SimpleNamespace(stdout=""),
            ),
            mock.patch.object(cli, "ensure_inventory_blob_access") as access,
            mock.patch.object(cli, "ensure_inventory_container") as container,
            mock.patch.object(cli.typer, "echo"),
        ):
            cli.init_inventory(
                resource_group="temenos-inventory-rg",
                location="westus",
                storage_account=None,
                container=None,
            )

        self.assertFalse(
            any(command[:3] == ["az", "group", "create"] for command in commands)
        )
        self.assertFalse(
            any(
                command[:4] == ["az", "storage", "account", "create"]
                for command in commands
            )
        )
        self.assertTrue(
            any(
                command[:4] == ["az", "storage", "account", "update"]
                for command in commands
            )
        )
        wait.assert_called_once_with("temenosinventorywus", "sub")
        access.assert_called_once_with("temenosinventorywus", "sub")
        container.assert_called_once_with(
            "temenosinventorywus",
            "temenos-inventory",
            "sub",
        )

    def test_init_inventory_creates_private_account(self):
        commands = []

        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(cli, "require_azure_subscription_id", return_value="sub"),
            mock.patch.object(cli, "query_azure_storage_accounts", return_value=[]),
            mock.patch.object(cli, "print_phase"),
            mock.patch.object(cli, "wait_for_inventory_storage_account"),
            mock.patch.object(
                cli,
                "run_checked",
                side_effect=lambda command, **_: commands.append(command)
                or SimpleNamespace(stdout=""),
            ),
            mock.patch.object(cli, "ensure_inventory_blob_access"),
            mock.patch.object(cli, "ensure_inventory_container"),
            mock.patch.object(cli.typer, "echo"),
        ):
            cli.init_inventory(
                resource_group="temenos-inventory-rg",
                location="westus",
                storage_account="newinventoryacct",
                container="temenos-inventory",
            )

        group_create = next(
            command
            for command in commands
            if command[:3] == ["az", "group", "create"]
        )
        account_create = next(
            command
            for command in commands
            if command[:4] == ["az", "storage", "account", "create"]
        )
        self.assertIn("temenos-inventory-rg", group_create)
        self.assertEqual(
            account_create[account_create.index("--allow-blob-public-access") + 1],
            "false",
        )
        self.assertEqual(
            account_create[account_create.index("--allow-shared-key-access") + 1],
            "false",
        )
        self.assertEqual(
            account_create[account_create.index("--https-only") + 1],
            "true",
        )

    def test_noninteractive_deploy_option_requires_flag(self):
        stdin = SimpleNamespace(isatty=lambda: False)
        with mock.patch.object(cli.sys, "stdin", stdin):
            with self.assertRaisesRegex(cli.typer.BadParameter, "--resource-group"):
                cli.resolve_deployment_option(
                    None,
                    option_name="--resource-group",
                    prompt="Resource group",
                    default="generated-rg",
                )

    def test_vm_size_uses_default_without_a_tty(self):
        stdin = SimpleNamespace(isatty=lambda: False)
        with mock.patch.object(cli.sys, "stdin", stdin):
            self.assertEqual(
                cli.resolve_vm_size(None),
                cli.DEFAULT_AZURE_VM_SIZE,
            )

    def test_vm_size_prompts_with_default_on_a_tty(self):
        stdin = SimpleNamespace(isatty=lambda: True)
        with (
            mock.patch.object(cli.sys, "stdin", stdin),
            mock.patch.object(
                cli.typer,
                "prompt",
                return_value="Standard_DC8ads_v5",
            ) as prompt,
        ):
            self.assertEqual(
                cli.resolve_vm_size(None),
                "Standard_DC8ads_v5",
            )

        prompt.assert_called_once_with(
            "Enter Azure VM size",
            default=cli.DEFAULT_AZURE_VM_SIZE,
        )

    def test_create_vm_missing_noninteractive_flag_stops_before_build(self):
        stdin = SimpleNamespace(isatty=lambda: False)
        metadata = {
            "name": "Demo",
            "description": "Demo",
            "app_container_image": "registry/dapp@sha256:" + "1" * 64,
            "base_os_image": "registry/os@sha256:" + "2" * 64,
        }
        with (
            mock.patch.object(cli.sys, "stdin", stdin),
            mock.patch.object(cli, "require_azure_subscription_id") as subscription,
            mock.patch.object(cli, "require_inventory_storage") as inventory,
            mock.patch.object(cli, "repo_root_from_cwd", return_value=Path("/tmp/temenos-test")),
            mock.patch.object(cli, "load_app_metadata", return_value=metadata),
            mock.patch.object(cli, "load_json_file", return_value=metadata),
            mock.patch.object(cli, "load_tee_measurements", return_value={"measurements": {}, "application_root_hash": "3" * 64}),
            mock.patch.object(cli, "print_phase"),
            mock.patch.object(cli.Deployer, "assert_available") as terraform,
            mock.patch.object(cli, "resize_azure_disk") as resize,
        ):
            with self.assertRaisesRegex(cli.typer.BadParameter, "--resource-group"):
                cli.create_vm(
                    azure_snp=True,
                    resource_group=None,
                    location="eastus",
                    tls_keyvault_name=None,
                    vm_name="temenos-demo-vm",
                    gallery_name="temenos_demo_gallery",
                    hydrate_policy=False,
                    use_tpm2_checkquote=False,
                    unbound_attestation=False,
                )

        terraform.assert_not_called()
        resize.assert_not_called()
        subscription.assert_not_called()
        inventory.assert_not_called()

    def test_terraform_workdir_is_private(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workdir = Path(tmpdir) / "deployment"
            with (
                mock.patch.object(cli.Deployer, "_Deployer__assert_tf_available"),
                mock.patch.object(cli, "repo_root_from_cwd", return_value=Path.cwd()),
            ):
                cli.Deployer.init(workdir, "deploy-azure-snp")

            self.assertEqual(workdir.stat().st_mode & 0o777, 0o700)

    def test_noninteractive_create_records_tagged_immutable_deployment(self):
        stdin = SimpleNamespace(isatty=lambda: False)
        metadata = {
            "name": "Demo",
            "description": "Demo",
            "app_container_image": "registry/dapp@sha256:" + "1" * 64,
            "base_os_image": "registry/os@sha256:" + "2" * 64,
        }
        outputs = {
            "resource_group_name": "temenos-demo-rg",
            "location": "eastus",
            "vm_name": "temenos-demo-vm",
            "storage_account_name": "temenaccdemo",
            "storage_container_name": "temencondemo",
            "vm_principal_id": "principal-id",
            "public_ip_address": None,
        }

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(cli.sys, "stdin", stdin))
            stack.enter_context(
                mock.patch.object(
                    cli,
                    "require_azure_subscription_id",
                    return_value="sub",
                )
            )
            stack.enter_context(
                mock.patch.object(
                    cli,
                    "require_inventory_storage",
                    return_value=("auditaccount", "temenos-inventory"),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    cli,
                    "repo_root_from_cwd",
                    return_value=Path("/repo"),
                )
            )
            stack.enter_context(
                mock.patch.object(cli, "load_app_metadata", return_value=metadata)
            )
            stack.enter_context(
                mock.patch.object(cli, "load_json_file", return_value=metadata)
            )
            stack.enter_context(
                mock.patch.object(
                    cli,
                    "load_tee_measurements",
                    return_value={
                        "measurements": {},
                        "application_root_hash": "3" * 64,
                    },
                )
            )
            stack.enter_context(
                mock.patch.object(
                    cli,
                    "generate_deployment_id",
                    return_value="demo-20260918t120000z-abcd1234",
                )
            )
            stack.enter_context(
                mock.patch.object(
                    cli,
                    "current_git_sha",
                    return_value="4" * 40,
                )
            )
            stack.enter_context(mock.patch.object(cli, "print_phase"))
            stack.enter_context(mock.patch.object(cli, "print_tee_step"))
            stack.enter_context(mock.patch.object(cli.Deployer, "assert_available"))
            stack.enter_context(
                mock.patch.object(cli, "ensure_inventory_storage_is_external")
            )
            stack.enter_context(mock.patch.object(cli, "ensure_inventory_container"))
            stack.enter_context(
                mock.patch.object(cli, "ensure_resource_group_is_new")
            )
            stack.enter_context(
                mock.patch.object(
                    cli,
                    "azure_operator",
                    return_value={"name": "operator", "type": "user"},
                )
            )
            stack.enter_context(
                mock.patch.object(cli, "resize_azure_disk", return_value=123)
            )
            init = stack.enter_context(mock.patch.object(cli.Deployer, "init"))
            launch = stack.enter_context(
                mock.patch.object(
                    cli.Deployer,
                    "launch_runner",
                    return_value=outputs,
                )
            )
            merge_tags = stack.enter_context(
                mock.patch.object(cli, "merge_resource_group_tags")
            )
            append_record = stack.enter_context(
                mock.patch.object(cli, "append_inventory_record")
            )
            echo = stack.enter_context(mock.patch.object(cli.typer, "echo"))
            cli.create_vm(
                azure_snp=True,
                resource_group="temenos-demo-rg",
                location="eastus",
                vm_size="Standard_DC8ads_v5",
                tls_keyvault_name=None,
                vm_name="temenos-demo-vm",
                gallery_name="temenos_demo_gallery",
                hydrate_policy=False,
                use_tpm2_checkquote=False,
                unbound_attestation=False,
            )

        workdir = Path("/repo/.temenos/deploy-azure-snp/demo-20260918t120000z-abcd1234")
        init.assert_called_once_with(workdir, "deploy-azure-snp")
        launch_workdir, tf_vars = launch.call_args.args
        self.assertEqual(launch_workdir, workdir)
        self.assertEqual(
            tf_vars["instance_type"],
            "Standard_DC8ads_v5",
        )
        rendered_tags = json.loads(tf_vars["deployment_tags"])
        self.assertEqual(rendered_tags[cli.VERITEE_MANAGED_TAG], "true")
        self.assertEqual(
            rendered_tags[cli.VERITEE_DEPLOYMENT_ID_TAG],
            "demo-20260918t120000z-abcd1234",
        )
        merge_tags.assert_called_once_with(
            "temenos-demo-rg",
            {
                "temenos_storage_account": "temenaccdemo",
                "temenos_storage_container": "temencondemo",
                "temenos_vm_principal_id": "principal-id",
            },
            "sub",
        )
        audit = append_record.call_args.kwargs
        self.assertEqual(audit["event"], "created")
        self.assertEqual(audit["record"]["resource_group"], "temenos-demo-rg")
        self.assertEqual(
            audit["record"]["tags"]["temenos_storage_account"],
            "temenaccdemo",
        )
        echo.assert_called_once_with(
            "Deployment ID: demo-20260918t120000z-abcd1234"
        )

    def test_noninteractive_destroy_requires_yes(self):
        stdin = SimpleNamespace(isatty=lambda: False)
        with mock.patch.object(cli.sys, "stdin", stdin):
            with self.assertRaisesRegex(cli.typer.BadParameter, "--yes"):
                cli.confirm_destroy("temenos-demo-rg", False)

        with (
            mock.patch.object(cli.sys, "stdin", stdin),
            mock.patch.object(cli, "require_azure_subscription_id") as subscription,
        ):
            with self.assertRaisesRegex(cli.typer.BadParameter, "--yes"):
                cli.destroy_vm(
                    deployment_id="demo-20260918t120000z-abcd1234",
                    resource_group=None,
                    yes=False,
                    keep_image=False,
                )

        subscription.assert_not_called()

    def test_selector_rejects_zero_multiple_unmanaged_and_both(self):
        group = self._resource_group()
        with self.assertRaises(cli.typer.BadParameter):
            cli.select_managed_resource_group(
                [group],
                deployment_id="id",
                resource_group="rg",
            )
        with self.assertRaisesRegex(cli.DeployerException, "found 0"):
            cli.select_managed_resource_group(
                [group],
                deployment_id="missing",
                resource_group=None,
            )
        with self.assertRaisesRegex(cli.DeployerException, "found 2"):
            cli.select_managed_resource_group(
                [group, dict(group)],
                deployment_id=group["tags"][cli.VERITEE_DEPLOYMENT_ID_TAG],
                resource_group=None,
            )
        unmanaged = self._resource_group(managed="false")
        with self.assertRaisesRegex(cli.DeployerException, "untagged"):
            cli.select_managed_resource_group(
                [unmanaged],
                deployment_id=None,
                resource_group=unmanaged["name"],
            )

    def test_deployment_id_round_trips_through_selector(self):
        group = self._resource_group()
        selected = cli.select_managed_resource_group(
            [group],
            deployment_id=group["tags"][cli.VERITEE_DEPLOYMENT_ID_TAG],
            resource_group=None,
        )
        self.assertIs(selected, group)

    def test_historical_summaries_keep_destroyed_deployments_discoverable(self):
        group = self._resource_group()
        deployment_id = group["tags"][cli.VERITEE_DEPLOYMENT_ID_TAG]
        creation_tags = dict(group["tags"])
        del creation_tags["temenos_base_os_image"]
        records = [
            {
                "deployment_id": deployment_id,
                "event": "created",
                "recorded_at": "2026-09-18T12:00:00Z",
                "resource_group": group["name"],
                "tags": creation_tags,
            },
            {
                "deployment_id": deployment_id,
                "event": "destroyed",
                "recorded_at": "2026-09-18T13:00:00Z",
                "resource_group": group["name"],
                "tags": group["tags"],
            },
        ]

        summaries = cli.deployment_history_summaries(records, [])

        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["deployment_id"], deployment_id)
        self.assertEqual(summaries[0]["status"], "destroyed")
        self.assertEqual(summaries[0]["base_os_image"], "registry/os:0.3.1")

    def test_live_resource_group_wins_over_historical_status(self):
        group = self._resource_group()
        deployment_id = group["tags"][cli.VERITEE_DEPLOYMENT_ID_TAG]
        records = [
            {
                "deployment_id": deployment_id,
                "event": "destroy_requested",
                "recorded_at": "2026-09-18T13:00:00Z",
                "resource_group": group["name"],
                "tags": group["tags"],
            }
        ]

        summaries = cli.deployment_history_summaries(records, [group])

        self.assertEqual(summaries[0]["status"], "active")

    def test_missing_resource_group_completes_destroy_requested_status(self):
        rows = [
            {
                "deployment_id": "demo-20260918t120000z-abcd1234",
                "resource_group": "temenos-demo-rg",
                "status": "destroy requested",
            }
        ]
        with mock.patch.object(
            cli,
            "azure_resource_group_exists",
            return_value=False,
        ) as exists:
            cli.reconcile_destroy_requested_statuses(rows, "sub")

        self.assertEqual(rows[0]["status"], "destroyed")
        exists.assert_called_once_with("temenos-demo-rg", "sub")

    def test_list_deployments_all_reads_durable_history(self):
        group = self._resource_group()
        record = {
            "deployment_id": group["tags"][cli.VERITEE_DEPLOYMENT_ID_TAG],
            "event": "destroyed",
            "recorded_at": "2026-09-18T13:00:00Z",
            "resource_group": group["name"],
            "tags": group["tags"],
        }
        with (
            mock.patch.object(cli, "require_azure_subscription_id", return_value="sub"),
            mock.patch.object(cli, "query_managed_resource_groups", return_value=[]),
            mock.patch.object(
                cli,
                "require_inventory_storage",
                return_value=("auditaccount", "temenos-inventory"),
            ),
            mock.patch.object(cli, "load_inventory_records", return_value=[record]),
            mock.patch.object(cli.typer, "echo") as echo,
        ):
            cli.list_deployments(as_json=False, include_all=True)

        output = "\n".join(call.args[0] for call in echo.call_args_list)
        self.assertIn("STATUS", output)
        self.assertIn("destroyed", output)
        self.assertIn(record["deployment_id"], output)

    def test_empty_live_list_points_to_historical_inventory(self):
        with (
            mock.patch.object(cli, "require_azure_subscription_id", return_value="sub"),
            mock.patch.object(cli, "query_managed_resource_groups", return_value=[]),
            mock.patch.object(cli.typer, "echo") as echo,
        ):
            cli.list_deployments(as_json=False, include_all=False)

        echo.assert_called_once_with(
            "No live Veritee deployments found. "
            "Use `veritee list-deployments --all` to include deployment history."
        )

    def test_destroy_orders_retention_audit_cleanup_and_delete(self):
        group = self._resource_group()
        order = []

        with (
            mock.patch.object(cli, "require_azure_subscription_id", return_value="sub"),
            mock.patch.object(cli, "require_inventory_storage", return_value=("auditaccount", "temenos-inventory")),
            mock.patch.object(cli, "resolve_managed_resource_group", return_value=group),
            mock.patch.object(cli, "print_phase"),
            mock.patch.object(cli, "ensure_inventory_storage_is_external"),
            mock.patch.object(cli, "ensure_inventory_container"),
            mock.patch.object(cli, "preserve_deployment_vhd", side_effect=lambda **_: order.append("retain") or "retained.vhd"),
            mock.patch.object(cli, "azure_operator", return_value={"name": "operator", "type": "user"}),
            mock.patch.object(
                cli,
                "append_inventory_record",
                side_effect=lambda **kwargs: order.append(kwargs["event"]),
            ),
            mock.patch.object(cli, "remove_external_keyvault_role_assignment", side_effect=lambda *_: order.append("cleanup")),
            mock.patch.object(cli, "delete_resource_group_and_wait", side_effect=lambda *_: order.append("delete")),
            mock.patch.object(cli.typer, "echo"),
        ):
            cli.destroy_vm(
                deployment_id=group["tags"][cli.VERITEE_DEPLOYMENT_ID_TAG],
                resource_group=None,
                yes=True,
                keep_image=True,
            )

        self.assertEqual(
            order,
            ["retain", "destroy_requested", "cleanup", "delete", "destroyed"],
        )

    def test_keyvault_role_cleanup_uses_supported_delete_assignee_flag(self):
        group = self._resource_group()
        group["tags"].update(
            {
                "temenos_tls_mode": "azure_vault",
                "temenos_tls_keyvault_name": "temenos-demo-vault",
                "temenos_vm_principal_id": "principal-id",
            }
        )
        with mock.patch.object(
            cli,
            "run_checked",
            side_effect=[
                SimpleNamespace(stdout="/subscriptions/sub/vaults/temenos-demo-vault\n"),
                SimpleNamespace(stdout=""),
            ],
        ) as run:
            cli.remove_external_keyvault_role_assignment(group, "sub")

        delete_command = run.call_args_list[1].args[0]
        self.assertIn("--assignee", delete_command)
        self.assertNotIn("--assignee-object-id", delete_command)
        self.assertEqual(delete_command[delete_command.index("--assignee") + 1], "principal-id")

    def test_resource_group_delete_uses_no_wait_and_polls(self):
        with (
            mock.patch.object(cli, "run_checked", return_value=SimpleNamespace(stdout="")) as run,
            mock.patch.object(
                cli,
                "azure_resource_group_exists",
                side_effect=[True, False],
            ) as exists,
            mock.patch.object(cli.time, "monotonic", side_effect=[0, 1]),
            mock.patch.object(cli.time, "sleep") as sleep,
        ):
            cli.delete_resource_group_and_wait(
                "temenos-demo-rg",
                "sub",
                poll_seconds=1,
            )

        command = run.call_args.args[0]
        self.assertIn("--no-wait", command)
        self.assertEqual(exists.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_inventory_storage_must_be_outside_deployment_group(self):
        with mock.patch.object(
            cli,
            "inventory_storage_resource_group",
            return_value="temenos-demo-rg",
        ):
            with self.assertRaisesRegex(cli.DeployerException, "must be outside"):
                cli.ensure_inventory_storage_is_external(
                    "auditaccount",
                    "temenos-demo-rg",
                    "sub",
                )

    def test_inventory_upload_is_append_only(self):
        captured = {}

        def capture(command, **_kwargs):
            captured["command"] = command
            record_path = Path(command[command.index("--file") + 1])
            captured["payload"] = json.loads(record_path.read_text())
            return SimpleNamespace(stdout="")

        with (
            mock.patch.object(cli, "run_checked", side_effect=capture),
            mock.patch.object(cli, "utc_timestamp", return_value="2026-09-18T12:00:00Z"),
            mock.patch.object(cli.secrets, "token_hex", return_value="abcd1234"),
        ):
            blob_name = cli.append_inventory_record(
                storage_account="auditaccount",
                container="temenos-inventory",
                subscription_id="sub",
                deployment_id="demo-20260918t120000z-abcd1234",
                event="created",
                record={"resource_group": "temenos-demo-rg"},
            )

        self.assertIn("--overwrite", captured["command"])
        overwrite_index = captured["command"].index("--overwrite")
        self.assertEqual(captured["command"][overwrite_index + 1], "false")
        self.assertEqual(captured["payload"]["event"], "created")
        self.assertEqual(
            blob_name,
            "records/demo-20260918t120000z-abcd1234/"
            "20260918T120000Z-created-abcd1234.json",
        )

    def test_inventory_record_listing_uses_azure_login(self):
        blobs = [
            "records/demo-20260918t120000z-abcd1234/"
            "20260918T120000Z-created-abcd1234.json"
        ]
        with mock.patch.object(
            cli,
            "run_checked",
            return_value=SimpleNamespace(stdout=json.dumps(blobs)),
        ) as run:
            result = cli.list_inventory_record_blobs(
                storage_account="auditaccount",
                container="temenos-inventory",
                subscription_id="sub",
                deployment_id="demo-20260918t120000z-abcd1234",
            )

        self.assertEqual(result, blobs)
        command = run.call_args.args[0]
        self.assertEqual(
            command[command.index("--prefix") + 1],
            "records/demo-20260918t120000z-abcd1234/",
        )
        self.assertEqual(command[command.index("--auth-mode") + 1], "login")

    def test_azure_flag_and_terraform_destroy_helpers_are_removed(self):
        result = CliRunner().invoke(cli.app, ["create-vm", "--azure"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("No such option", result.output)
        self.assertFalse(hasattr(cli.Deployer, "destroy_runner"))
        self.assertFalse(hasattr(cli.Deployer, "_Deployer__tf_exclude"))

    def test_terraform_resource_group_uses_deployment_tags(self):
        variables = Path("cli/deploy-azure-snp/variables.tf").read_text()
        main = Path("cli/deploy-azure-snp/main.tf").read_text()

        self.assertIn('variable "deployment_tags"', variables)
        self.assertIn("tags     = var.deployment_tags", main)


class ExplicitTrustConfigurationTests(unittest.TestCase):
    def test_warden_endpoint_requires_environment_or_option(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                cli.DeployerException,
                cli.WARDEN_URL_ENV_VAR,
            ):
                cli.resolve_warden_endpoint(None, cli.WARDEN_REGISTER_ROUTE)

    def test_warden_endpoint_is_derived_from_configured_base_url(self):
        with mock.patch.dict(
            os.environ,
            {cli.WARDEN_URL_ENV_VAR: "https://warden.example/temenos/"},
            clear=True,
        ):
            self.assertEqual(
                cli.resolve_warden_endpoint(None, cli.WARDEN_REGISTER_ROUTE),
                "https://warden.example/temenos/dapps/register",
            )

    def test_explicit_warden_endpoint_does_not_require_environment(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                cli.resolve_warden_endpoint(
                    "http://localhost:3000/dapps/verify_attestation",
                    cli.WARDEN_VERIFY_ATTESTATION_ROUTE,
                ),
                "http://localhost:3000/dapps/verify_attestation",
            )

    def test_warden_url_rejects_relative_or_credentialed_values(self):
        for value in ("warden.example", "https://user:secret@warden.example"):
            with self.subTest(value=value):
                with self.assertRaises(cli.DeployerException):
                    cli.validate_warden_url(value)

    def test_acr_name_is_required(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                cli.DeployerException,
                cli.ACR_NAME_ENV_VAR,
            ):
                cli.require_acr_name()


class BaseOsBuildOptionTests(unittest.TestCase):
    def test_unbound_attestation_requires_debug_image(self):
        with self.assertRaisesRegex(
            cli.typer.BadParameter,
            "requires --debug",
        ):
            cli.validate_unbound_attestation_build(
                debug=False,
                allow_unbound_attestation=True,
            )

    def test_debug_image_can_explicitly_allow_unbound_attestation(self):
        cli.validate_unbound_attestation_build(
            debug=True,
            allow_unbound_attestation=True,
        )

    def test_release_image_defaults_to_bound_attestation(self):
        cli.validate_unbound_attestation_build(
            debug=False,
            allow_unbound_attestation=False,
        )


class AzureVhdHashTests(unittest.TestCase):
    @staticmethod
    def _sha256(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def test_azure_vhd_size_mib_rounds_up_to_next_mib(self):
        self.assertEqual(cli.azure_vhd_size_mib(1), 1)
        self.assertEqual(cli.azure_vhd_size_mib(1024 * 1024), 1)
        self.assertEqual(cli.azure_vhd_size_mib(1024 * 1024 + 1), 2)

    def test_deterministic_azure_vhd_uuid_matches_legacy_shell_formula(self):
        self.assertEqual(
            cli.deterministic_azure_vhd_uuid(
                "658459d7022e797a8341ba0c56f6693b05b17b349361420d406566b5cf6bcc5d"
            ),
            "658459d7-022e-597a-8341-ba0c56f6693b",
        )

    def test_patch_fixed_azure_vhd_footer_sets_deterministic_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vhd_path = Path(tmpdir) / "disk.img.vhd"
            raw_hash = "658459d7022e797a8341ba0c56f6693b05b17b349361420d406566b5cf6bcc5d"
            footer = bytearray(cli.VHD_FOOTER_SIZE)
            footer[: len(cli.VHD_FOOTER_COOKIE)] = cli.VHD_FOOTER_COOKIE
            footer[
                cli.VHD_FOOTER_TIMESTAMP_OFFSET : cli.VHD_FOOTER_TIMESTAMP_OFFSET + 4
            ] = (123).to_bytes(4, "big")
            vhd_path.write_bytes(b"payload" + footer)

            cli.patch_fixed_azure_vhd_footer(vhd_path, raw_hash)

            patched_footer = vhd_path.read_bytes()[-cli.VHD_FOOTER_SIZE :]
            self.assertEqual(
                patched_footer[
                    cli.VHD_FOOTER_TIMESTAMP_OFFSET : cli.VHD_FOOTER_TIMESTAMP_OFFSET + 4
                ],
                b"\0\0\0\0",
            )
            self.assertEqual(
                patched_footer[
                    cli.VHD_FOOTER_UNIQUE_ID_OFFSET : cli.VHD_FOOTER_UNIQUE_ID_OFFSET + 16
                ],
                bytes.fromhex("658459d7022e597a8341ba0c56f6693b"),
            )
            self.assertEqual(
                int.from_bytes(
                    patched_footer[
                        cli.VHD_FOOTER_CHECKSUM_OFFSET : cli.VHD_FOOTER_CHECKSUM_OFFSET + 4
                    ],
                    "big",
                ),
                cli.azure_vhd_footer_checksum(patched_footer),
            )

    def test_resize_reuses_vhd_only_when_raw_and_vhd_hashes_match(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            disk_dir = Path(tmpdir)
            raw_content = b"raw"
            vhd_content = b"vhd"
            (disk_dir / "disk.raw").write_bytes(raw_content)
            (disk_dir / "disk.img.vhd").write_bytes(vhd_content)
            (disk_dir / cli.AZURE_VHD_SOURCE_RAW_HASH_FILE).write_text(
                self._sha256(raw_content) + "\n"
            )
            (disk_dir / cli.AZURE_VHD_HASH_FILE).write_text(
                self._sha256(vhd_content) + "\n"
            )

            with mock.patch.object(cli, "qemu_virtual_size", return_value=123) as qemu:
                self.assertEqual(cli.resize_azure_disk(Path("."), disk_dir), 123)

            qemu.assert_called_once_with(disk_dir / "disk.img.vhd")

    def test_resize_regenerates_vhd_when_recorded_vhd_hash_is_stale(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            disk_dir = Path(tmpdir)
            raw_content = b"raw"
            vhd_content = b"new-vhd"
            (disk_dir / "disk.raw").write_bytes(raw_content)
            (disk_dir / "disk.img.vhd").write_bytes(b"stale-vhd")
            (disk_dir / cli.AZURE_VHD_SOURCE_RAW_HASH_FILE).write_text(
                self._sha256(raw_content) + "\n"
            )
            (disk_dir / cli.AZURE_VHD_HASH_FILE).write_text("wrong\n")
            (disk_dir / cli.AZURE_VHD_LEGACY_RAW_HASH_FILE).write_text("legacy\n")

            def fake_run(command):
                if command[1] == "convert":
                    (disk_dir / "disk.img.vhd.tmp").write_bytes(vhd_content)
                return SimpleNamespace(stdout="")

            with (
                mock.patch.object(cli, "qemu_virtual_size", side_effect=[1025, 456]) as qemu,
                mock.patch.object(cli.shutil, "which", return_value=None),
                mock.patch.object(cli, "run_checked", side_effect=fake_run) as run,
                mock.patch.object(cli, "patch_fixed_azure_vhd_footer") as patch_footer,
            ):
                self.assertEqual(cli.resize_azure_disk(Path("."), disk_dir), 456)

            self.assertEqual(qemu.call_args_list[0].args[0], disk_dir / "disk.raw")
            self.assertEqual(qemu.call_args_list[1].args[0], disk_dir / "disk.img.vhd.tmp")
            self.assertEqual(run.call_count, 4)
            self.assertEqual(
                run.call_args_list[0].args[0],
                ["cp", "--reflink=auto", "--sparse=always",
                 str(disk_dir / "disk.raw"), str(disk_dir / "disk.azure.raw.tmp")],
            )
            self.assertEqual(
                run.call_args_list[1].args[0],
                ["qemu-img", "resize", "-f", "raw", str(disk_dir / "disk.azure.raw.tmp"), "1M"],
            )
            self.assertEqual(run.call_args_list[2].args[0][0:4], ["qemu-img", "convert", "-q", "-f"])
            self.assertEqual(
                run.call_args_list[3].args[0],
                ["qemu-img", "compare", "-q", "-f", "raw", "-F", "vpc",
                 str(disk_dir / "disk.azure.raw.tmp"), str(disk_dir / "disk.img.vhd.tmp")],
            )
            patch_footer.assert_called_once_with(
                disk_dir / "disk.img.vhd.tmp",
                self._sha256(raw_content),
            )
            self.assertFalse((disk_dir / "disk.azure.raw.tmp").exists())
            self.assertFalse((disk_dir / "disk.img.vhd.tmp").exists())
            self.assertEqual((disk_dir / "disk.img.vhd").read_bytes(), vhd_content)
            self.assertEqual(
                (disk_dir / cli.AZURE_VHD_SOURCE_RAW_HASH_FILE).read_text().strip(),
                self._sha256(raw_content),
            )
            self.assertEqual(
                (disk_dir / cli.AZURE_VHD_HASH_FILE).read_text().strip(),
                self._sha256(vhd_content),
            )
            self.assertFalse((disk_dir / cli.AZURE_VHD_LEGACY_RAW_HASH_FILE).exists())

    def test_failed_conversion_preserves_existing_vhd_and_hashes(self):
        for failing_step in ("convert", "compare"):
            with self.subTest(failing_step=failing_step), tempfile.TemporaryDirectory() as tmpdir:
                disk_dir = Path(tmpdir)
                (disk_dir / "disk.raw").write_bytes(b"raw")
                vhd_path = disk_dir / "disk.img.vhd"
                vhd_path.write_bytes(b"previous-vhd")
                source_hash_path = disk_dir / cli.AZURE_VHD_SOURCE_RAW_HASH_FILE
                source_hash_path.write_text("previous-source-hash\n")
                vhd_hash_path = disk_dir / cli.AZURE_VHD_HASH_FILE
                vhd_hash_path.write_text("previous-vhd-hash\n")

                def fake_run(command):
                    if command[0] == "cp":
                        (disk_dir / "disk.azure.raw.tmp").write_bytes(b"raw")
                    if command[1] == "convert":
                        (disk_dir / "disk.img.vhd.tmp").write_bytes(b"partial-vhd")
                    if command[1] == failing_step:
                        raise subprocess.CalledProcessError(1, command)
                    return SimpleNamespace(stdout="")

                with (
                    mock.patch.object(cli.shutil, "which", return_value=None),
                    mock.patch.object(cli, "qemu_virtual_size", return_value=1025),
                    mock.patch.object(cli, "run_checked", side_effect=fake_run),
                    mock.patch.object(cli, "patch_fixed_azure_vhd_footer"),
                    self.assertRaises(subprocess.CalledProcessError),
                ):
                    cli.resize_azure_disk(Path("."), disk_dir)

                self.assertEqual(vhd_path.read_bytes(), b"previous-vhd")
                self.assertEqual(source_hash_path.read_text(), "previous-source-hash\n")
                self.assertEqual(vhd_hash_path.read_text(), "previous-vhd-hash\n")
                self.assertEqual((disk_dir / "disk.raw").read_bytes(), b"raw")
                self.assertFalse((disk_dir / "disk.azure.raw.tmp").exists())
                self.assertFalse((disk_dir / "disk.img.vhd.tmp").exists())

    @unittest.skipIf(shutil.which("qemu-img") is None, "qemu-img is not installed")
    def test_resize_generates_reproducible_valid_vhd(self):
        raw_content = b"abc123" * 170000
        vhd_hashes = []

        for _ in range(2):
            with tempfile.TemporaryDirectory() as tmpdir:
                disk_dir = Path(tmpdir)
                raw_path = disk_dir / "disk.raw"
                vhd_path = disk_dir / "disk.img.vhd"
                roundtrip_path = disk_dir / "roundtrip.raw"
                raw_path.write_bytes(raw_content)

                cli.resize_azure_disk(Path("."), disk_dir)
                vhd_hashes.append(self._sha256(vhd_path.read_bytes()))

                info = subprocess.run(
                    ["qemu-img", "info", "-f", "vpc", "--output", "json", str(vhd_path)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                virtual_size = json.loads(info.stdout)["virtual-size"]
                subprocess.run(
                    ["qemu-img", "convert", "-f", "vpc", "-O", "raw", str(vhd_path), str(roundtrip_path)],
                    check=True,
                )

                expected_roundtrip = raw_content + b"\0" * (virtual_size - len(raw_content))
                self.assertEqual(roundtrip_path.read_bytes(), expected_roundtrip)

        self.assertEqual(vhd_hashes[0], vhd_hashes[1])


class WardenJobHelperTests(unittest.TestCase):
    def test_absolute_job_url_does_not_require_warden_environment(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                cli.resolve_warden_job_endpoint(
                    None,
                    "https://warden.example/jobs/job-1",
                ),
                "https://warden.example/jobs/job-1",
            )

    def test_relative_job_url_requires_warden_environment(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                cli.DeployerException,
                cli.WARDEN_URL_ENV_VAR,
            ):
                cli.resolve_warden_job_endpoint(None, "/jobs/job-1")

    def test_resolve_warden_job_url_accepts_absolute_status_url(self):
        self.assertEqual(
            cli.resolve_warden_job_url(
                "https://warden.wastedp.io/dapps/register",
                "https://other.example/jobs/job-1",
            ),
            "https://other.example/jobs/job-1",
        )

    def test_resolve_warden_job_url_resolves_relative_status_url_from_host_root(self):
        self.assertEqual(
            cli.resolve_warden_job_url(
                "https://warden.wastedp.io/dapps/register",
                "jobs/job-1",
            ),
            "https://warden.wastedp.io/jobs/job-1",
        )

    def test_queued_payload_from_job_reference_accepts_plain_job_id(self):
        self.assertEqual(
            cli.queued_payload_from_job_reference("job-1"),
            {
                "job_id": "job-1",
                "status_url": "/jobs/job-1",
            },
        )

    def test_queued_payload_from_job_reference_extracts_job_id_from_url(self):
        self.assertEqual(
            cli.queued_payload_from_job_reference("https://warden.wastedp.io/jobs/job-1"),
            {
                "job_id": "job-1",
                "status_url": "https://warden.wastedp.io/jobs/job-1",
            },
        )

    def test_queued_payload_from_warden_response_requires_accepted_job(self):
        with self.assertRaises(cli.DeployerException):
            cli.queued_payload_from_warden_response(200, {"job_id": "job-1"}, "register DApp")

        with self.assertRaises(cli.DeployerException):
            cli.queued_payload_from_warden_response(
                202,
                {"job_id": "job-1"},
                "register DApp",
            )

    def test_queued_payload_from_nested_job_validates_shape(self):
        payload = {
            "verification_recording": {
                "job_id": "job-2",
                "status_url": "/jobs/job-2",
                "status": "queued",
            },
        }

        self.assertEqual(
            cli.queued_payload_from_nested_job(
                payload,
                "verification_recording",
                "verify attestation",
            ),
            {
                "job_id": "job-2",
                "status_url": "/jobs/job-2",
                "status": "queued",
            },
        )


class WardenHttpHelperTests(unittest.TestCase):
    def test_warden_response_json_returns_success_payload(self):
        self.assertEqual(
            cli.warden_response_json(FakeResponse(payload={"ok": True}), "test"),
            {"ok": True},
        )

    def test_warden_response_json_raises_on_http_error_with_body(self):
        with self.assertRaises(cli.DeployerException) as raised:
            cli.warden_response_json(
                FakeResponse(status_code=400, text="bad request", reason="Bad Request"),
                "test",
            )

        self.assertIn("400 Bad Request", str(raised.exception))
        self.assertIn("bad request", str(raised.exception))

    def test_warden_response_json_raises_on_invalid_json(self):
        with self.assertRaises(cli.DeployerException) as raised:
            cli.warden_response_json(FakeResponse(json_error=True), "test")

        self.assertIn("invalid JSON", str(raised.exception))

    def test_post_warden_json_response_sends_expected_request(self):
        with mock.patch.object(
            cli.requests,
            "post",
            return_value=FakeResponse(status_code=202, payload={"job_id": "job-1"}),
        ) as post:
            self.assertEqual(
                cli.post_warden_json_response(
                    "https://warden.example/register",
                    {"x": 1},
                    "register",
                    timeout=(1, 2),
                ),
                (202, {"job_id": "job-1"}),
            )

        post.assert_called_once_with(
            "https://warden.example/register",
            json={"x": 1},
            headers={"Accept": "application/json"},
            timeout=(1, 2),
        )

    def test_post_warden_json_response_wraps_timeout(self):
        with mock.patch.object(cli.requests, "post", side_effect=cli.requests.Timeout):
            with self.assertRaises(cli.DeployerException) as raised:
                cli.post_warden_json_response(
                    "https://warden.example/register",
                    {},
                    "register",
                    timeout=(1, 2),
                )

        self.assertIn("Timed out", str(raised.exception))
        self.assertIn("read=2s", str(raised.exception))

    def test_get_warden_json_response_returns_error_text_without_json_parsing(self):
        with mock.patch.object(
            cli.requests,
            "get",
            return_value=FakeResponse(status_code=500, text="boom"),
        ):
            self.assertEqual(
                cli.get_warden_json_response("https://warden.example/jobs/1", "fetch"),
                (500, "boom"),
            )

    def test_get_warden_json_requires_dict_payload(self):
        with mock.patch.object(
            cli.requests,
            "get",
            return_value=FakeResponse(payload=["not", "a", "dict"]),
        ):
            with self.assertRaises(cli.DeployerException):
                cli.get_warden_json("https://warden.example/jobs/1", "fetch")


class AttestationHttpHelperTests(unittest.TestCase):
    def test_resolve_attestation_tls_mode_reads_packaged_artifact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_dir = Path(tmpdir)
            (artifact_dir / cli.TLS_MODE_FILE).write_text("internal\n")

            self.assertEqual(
                cli.resolve_attestation_tls_mode(None, artifact_dir),
                "internal",
            )

    def test_resolve_attestation_tls_mode_requires_file_or_override(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_dir = Path(tmpdir)
            self.assertEqual(
                cli.resolve_attestation_tls_mode("azure_vault", artifact_dir),
                "azure_vault",
            )
            with self.assertRaisesRegex(cli.DeployerException, "--tls-mode"):
                cli.resolve_attestation_tls_mode(None, artifact_dir)

    def test_normalize_public_attestation_url_accepts_https_endpoint(self):
        self.assertEqual(
            cli.normalize_public_attestation_url(
                "https://attestation.example/tee_attestation"
            ),
            "https://attestation.example/tee_attestation",
        )

    def test_normalize_public_attestation_url_rejects_direct_http_port(self):
        with self.assertRaisesRegex(typer.BadParameter, "public HTTPS"):
            cli.normalize_public_attestation_url("http://1.2.3.4:8000/")

    def test_normalize_public_attestation_url_rejects_wrong_path(self):
        with self.assertRaisesRegex(typer.BadParameter, "/tee_attestation"):
            cli.normalize_public_attestation_url("https://attestation.example/")

    def test_normalize_public_attestation_url_rejects_bare_ip(self):
        with self.assertRaisesRegex(typer.BadParameter, "full HTTP\\(S\\) URL"):
            cli.normalize_public_attestation_url("1.2.3.4")

    def test_normalize_attestation_url_requires_full_url(self):
        with self.assertRaisesRegex(typer.BadParameter, "full HTTP\\(S\\) URL"):
            cli.normalize_attestation_url("1.2.3.4")

    def test_normalize_attestation_url_accepts_explicit_local_debug_url(self):
        self.assertEqual(
            cli.normalize_attestation_url("http://localhost:8000/"),
            "http://localhost:8000/",
        )

    def test_internal_tls_root_ca_requires_matching_evidence_hash(self):
        root_ca = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"
        document = {
            "webserver_rootca": root_ca,
            "webserver_tls": {
                "mode": "internal_ca",
                "root_ca_sha256": hashlib.sha256(root_ca.encode()).hexdigest(),
            },
        }

        self.assertEqual(cli.internal_tls_root_ca(document), root_ca)

        document["webserver_tls"]["root_ca_sha256"] = "00" * 32
        with self.assertRaisesRegex(cli.DeployerException, "does not match"):
            cli.internal_tls_root_ca(document)

    def test_fetch_attestation_selects_bootstrap_from_tls_mode(self):
        with mock.patch.object(
            cli,
            "fetch_internal_tls_attestation_json",
            return_value={"attestation": "ok"},
        ) as fetch:
            result = cli.fetch_attestation_json(
                "https://attestation.example/tee_attestation",
                nonce="fresh",
                resolved_host="1.2.3.4",
                tls_mode="internal",
            )

        self.assertEqual(result, {"attestation": "ok"})
        fetch.assert_called_once_with(
            "https://attestation.example/tee_attestation",
            params={"nonce": "fresh"},
            timeout_seconds=30,
            resolved_host="1.2.3.4",
        )

    def test_internal_tls_fetch_bootstraps_ca_then_verifies_live_endpoint(self):
        root_ca = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"
        static_document = {
            "webserver_rootca": root_ca,
            "webserver_tls": {
                "mode": "internal_ca",
                "root_ca_sha256": hashlib.sha256(root_ca.encode()).hexdigest(),
            },
        }
        live_attestation = {"attestation": "ok"}
        bootstrap_context = mock.Mock()
        trusted_context = mock.Mock()

        with (
            mock.patch.object(
                cli,
                "fetch_resolved_https_json",
                side_effect=[static_document, live_attestation],
            ) as fetch,
            mock.patch.object(
                cli.ssl,
                "SSLContext",
                side_effect=[bootstrap_context, trusted_context],
            ) as context_class,
        ):
            result = cli.fetch_internal_tls_attestation_json(
                "https://attestation.example/tee_attestation",
                params={"nonce": "fresh"},
                timeout_seconds=10,
                resolved_host="1.2.3.4",
            )

        self.assertEqual(result, live_attestation)
        self.assertEqual(
            context_class.call_args_list,
            [
                mock.call(cli.ssl.PROTOCOL_TLS_CLIENT),
                mock.call(cli.ssl.PROTOCOL_TLS_CLIENT),
            ],
        )
        self.assertFalse(bootstrap_context.check_hostname)
        self.assertEqual(bootstrap_context.verify_mode, cli.ssl.CERT_NONE)
        trusted_context.load_verify_locations.assert_called_once_with(cadata=root_ca)
        first_fetch, second_fetch = fetch.call_args_list
        self.assertEqual(first_fetch.args, ("https://attestation.example/attestation.json", "1.2.3.4"))
        self.assertEqual(first_fetch.kwargs["params"], {})
        self.assertIs(first_fetch.kwargs["context"], bootstrap_context)
        self.assertEqual(second_fetch.args, ("https://attestation.example/tee_attestation", "1.2.3.4"))
        self.assertEqual(second_fetch.kwargs["params"], {"nonce": "fresh"})
        self.assertIs(second_fetch.kwargs["context"], trusted_context)

    def test_resolved_https_fetch_preserves_hostname_and_query(self):
        response = mock.Mock(status=200, reason="OK")
        response.read.return_value = b'{"attestation":"ok"}'
        connection = mock.Mock()
        connection.getresponse.return_value = response
        context = mock.Mock()

        with mock.patch.object(
            cli,
            "ResolvedHttpsConnection",
            return_value=connection,
        ) as connection_class:
            result = cli.fetch_resolved_https_json(
                "https://attestation.example/tee_attestation?existing=1",
                "1.2.3.4",
                params={"nonce": "fresh"},
                timeout_seconds=10,
                context=context,
            )

        self.assertEqual(result, {"attestation": "ok"})
        connection_class.assert_called_once_with(
            "attestation.example",
            "1.2.3.4",
            port=443,
            timeout=10,
            context=context,
        )
        connection.request.assert_called_once_with(
            "GET",
            "/tee_attestation?existing=1&nonce=fresh",
            headers={"Accept": "application/json", "Host": "attestation.example"},
        )
        connection.close.assert_called_once_with()


class EarthfileHelperTests(unittest.TestCase):
    def test_earthfile_target_secrets_reads_only_selected_target(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            earthfile = Path(tmpdir) / "Earthfile"
            earthfile.write_text(
                "\n".join(
                    [
                        "target-a:",
                        "    RUN --secret=+secrets/acr_token echo push",
                        "    RUN --secret dockerhub_user \\",
                        "        --secret dockerhub_token echo pull",
                        "",
                        "target-b:",
                        "    RUN --secret unrelated echo nope",
                    ]
                )
                + "\n"
            )

            self.assertEqual(
                cli.earthfile_target_secrets("target-a", earthfile),
                {"acr_token", "dockerhub_user", "dockerhub_token"},
            )

    def test_earthfile_target_copy_sources_drops_flags_and_destination(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            earthfile = Path(tmpdir) / "Earthfile"
            earthfile.write_text(
                "\n".join(
                    [
                        "target-a:",
                        "    COPY --dir ${APP_DIR}/run.d ./run.d",
                        "    COPY file.txt other.txt /dest/",
                        "",
                        "target-b:",
                        "    COPY ignored.txt /dest/",
                    ]
                )
                + "\n"
            )

            self.assertEqual(
                cli.earthfile_target_copy_sources("target-a", earthfile),
                ["${APP_DIR}/run.d", "file.txt", "other.txt"],
            )

    def test_preflight_check_earthly_copy_sources_substitutes_args(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app" / "run.d").mkdir(parents=True)
            (root / "file.txt").write_text("ok\n")
            earthfile = root / "Earthfile"
            earthfile.write_text(
                "\n".join(
                    [
                        "target-a:",
                        "    COPY --dir ${APP_DIR}/run.d ./run.d",
                        "    COPY file.txt /dest/",
                    ]
                )
                + "\n"
            )

            cli.preflight_check_earthly_copy_sources(
                "target-a",
                {"APP_DIR": "app"},
                earthfile,
            )

    def test_preflight_check_earthly_copy_sources_reports_missing_sources(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            earthfile = Path(tmpdir) / "Earthfile"
            earthfile.write_text(
                "\n".join(
                    [
                        "target-a:",
                        "    COPY missing.txt /dest/",
                    ]
                )
                + "\n"
            )

            with self.assertRaises(cli.DeployerException) as raised:
                cli.preflight_check_earthly_copy_sources("target-a", {}, earthfile)

            self.assertIn("missing.txt", str(raised.exception))

    def test_preflight_check_earthly_secrets_reports_missing_secret(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            earthfile = Path(tmpdir) / "Earthfile"
            earthfile.write_text(
                "\n".join(
                    [
                        "target-a:",
                        "    RUN --secret needed echo nope",
                    ]
                )
                + "\n"
            )

            with self.assertRaises(cli.DeployerException) as raised:
                cli.preflight_check_earthly_secrets(
                    "target-a",
                    frozenset({"acr_token"}),
                    earthfile,
                )

            self.assertIn("needed", str(raised.exception))

    def test_preflight_accepts_optional_dockerhub_secrets_when_unset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            earthfile = Path(tmpdir) / "Earthfile"
            earthfile.write_text(
                "target-a:\n"
                "    RUN --secret dockerhub_user --secret dockerhub_token echo pull\n"
            )

            with mock.patch.dict(os.environ, {}, clear=True):
                cli.preflight_check_earthly_secrets("target-a", earthfile=earthfile)


class EnvironmentAndCommandHelperTests(unittest.TestCase):
    def test_positive_float_env_reads_default_and_value(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(cli.positive_float_env("MISSING_ENV", 3.0), 3.0)

        with mock.patch.dict(os.environ, {"SECONDS_ENV": "1.5"}):
            self.assertEqual(cli.positive_float_env("SECONDS_ENV", 3.0), 1.5)

    def test_positive_float_env_rejects_invalid_values(self):
        for value in ("0", "-1", "nope"):
            with self.subTest(value=value):
                with mock.patch.dict(os.environ, {"SECONDS_ENV": value}):
                    with self.assertRaises(cli.DeployerException):
                        cli.positive_float_env("SECONDS_ENV", 3.0)

    def test_dockerhub_env_secrets_requires_both_values(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(cli.dockerhub_env_secrets(), {})

        with mock.patch.dict(os.environ, {cli.DOCKERHUB_USER_ENV_VAR: "user"}, clear=True):
            with self.assertRaises(cli.DeployerException):
                cli.dockerhub_env_secrets()

        with mock.patch.dict(
            os.environ,
            {
                cli.DOCKERHUB_USER_ENV_VAR: "user",
                cli.DOCKERHUB_TOKEN_ENV_VAR: "token",
            },
            clear=True,
        ):
            self.assertEqual(
                cli.dockerhub_env_secrets(),
                {"dockerhub_user": "user", "dockerhub_token": "token"},
            )

    def test_anonymous_dockerhub_pull_uses_empty_earthly_secrets_and_warns(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                cli.earthly_dockerhub_secrets(),
                {"dockerhub_user": "", "dockerhub_token": ""},
            )
            with self.assertLogs("veritee", level="WARNING") as captured:
                cli.warn_if_anonymous_dockerhub_pull()

        self.assertIn("pulls will be anonymous", captured.output[0])

    def test_earthly_command_supplies_empty_optional_dockerhub_secrets(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            command = cli.build_earthly_app_disk_command(
                app_dir="projects/dapp",
                app_container_image="docker.io/example/app@sha256:abc",
                guest_attestation_image="docker.io/example/attester@sha256:def",
                registry="example.azurecr.io",
                acr_token="acr-token",
                tls_mode="internal",
            )

        self.assertIn("dockerhub_user=", command)
        self.assertIn("dockerhub_token=", command)

    def test_secret_flags_and_redaction(self):
        command = [
            "earthly",
            "--secret",
            "acr_token=secret",
            "--secret",
            "dockerhub_token=token",
            "+target",
        ]

        self.assertEqual(
            cli.secret_flags({"one": "1", "two": "2"}),
            ["--secret", "one=1", "--secret", "two=2"],
        )
        self.assertEqual(
            cli.redact_earthly_command(command),
            [
                "earthly",
                "--secret",
                "acr_token=<redacted>",
                "--secret",
                "dockerhub_token=<redacted>",
                "+target",
            ],
        )

    def test_run_checked_redacts_sensitive_subprocess_output(self):
        secret = "https://storage.example/vhd?sig=secret"
        result = SimpleNamespace(
            returncode=1,
            stdout=f"copy source: {secret}\n",
            stderr=f"failed to copy {secret}\n",
        )
        with mock.patch.object(cli.subprocess, "run", return_value=result):
            with self.assertRaises(cli.DeployerSubProcessException) as raised:
                cli.run_checked(
                    ["copy", secret],
                    display_command=["copy", "<redacted-sas-uri>"],
                    redact_values=[secret],
                )

        self.assertNotIn(secret, str(raised.exception))
        self.assertIn("<redacted>", str(raised.exception))


class PayloadAndArtifactHelperTests(unittest.TestCase):
    def test_parse_payload_accepts_inline_json_and_text(self):
        self.assertEqual(cli.parse_payload('{"x": 1}'), {"x": 1})
        self.assertEqual(cli.parse_payload("plain"), "plain")

    def test_parse_payload_reads_file_without_reserializing_text(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "payload.txt"
            path.write_text("raw text\n")

            self.assertEqual(cli.parse_payload(f"@{path}"), "raw text\n")

    def test_parse_json_argument_requires_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "payload.json"
            path.write_text(json.dumps({"x": 1}))

            self.assertEqual(cli.parse_json_argument(f"@{path}", "payload"), {"x": 1})

        with self.assertRaises(cli.typer.BadParameter):
            cli.parse_json_argument("not-json", "payload")

    def test_artifact_payload_size_sums_existing_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "a").write_bytes(b"123")
            (root / "b").write_bytes(b"45")

            self.assertEqual(cli.artifact_payload_size(root, ["a", "b"]), 5)

    def test_artifact_payload_size_reports_missing_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(cli.DeployerException):
                cli.artifact_payload_size(Path(tmpdir), ["missing"])


if __name__ == "__main__":
    unittest.main()
