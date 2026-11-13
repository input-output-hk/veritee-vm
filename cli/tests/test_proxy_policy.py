import json
import os
import tempfile
import unittest
from pathlib import Path

from veritee import cli
from veritee.outbound import OutboundPolicyError, prepare_shipped_metadata
from veritee.proxy_policy import (
    PROXY_POLICY_PATH,
    install_proxy_policy,
    validate_proxy_allowed_paths,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class ProxyPolicyTests(unittest.TestCase):
    def metadata(self, **extra):
        return {
            "name": "Example DApp",
            "description": "Example",
            "app_container_image": "registry.example/app:1",
            "base_os_image": "registry.example/base:1",
            **extra,
        }

    def test_missing_or_empty_routes_publish_deny_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run" / "dapp-proxy.json"
            for metadata in ({}, {"proxy_allowed_paths": []}):
                install_proxy_policy(metadata, output)
                self.assertEqual(
                    json.loads(output.read_text()),
                    {"version": 1, "allowed_paths": []},
                )
                self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)

    def test_proof_app_routes_are_preserved_by_packaging(self):
        source = REPO_ROOT / "projects/proof_server_preprod/metadata.json"
        original = source.read_bytes()
        metadata = json.loads(original)
        packaged = prepare_shipped_metadata(
            metadata, tls_mode="internal", tls_keyvault_name=None
        )
        self.assertEqual(packaged["proxy_allowed_paths"], ["/check", "/prove"])
        self.assertEqual(source.read_bytes(), original)

    def test_invalid_routes_fail_cli_and_packaging(self):
        invalid = [
            None, "/check", [None], ["prove"], ["//other.example/check"],
            ["/../admin"], ["/%2e%2e/admin"], ["/a/%2f/admin"],
            ["/a/%5c/admin"], ["/a\\admin"], ["/check?token=1"],
            ["/check#part"], ["/http://other.example/check"], ["/bad%escape"],
            ["/check\n"], ["/check", "/check"], ["/" + "a" * 1024],
            [f"/route/{number}" for number in range(65)],
        ]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "metadata.json"
            for paths in invalid:
                with self.subTest(paths=paths):
                    metadata = self.metadata(proxy_allowed_paths=paths)
                    source.write_text(json.dumps(metadata))
                    with self.assertRaises(cli.DeployerException):
                        cli.load_app_metadata(source)
                    with self.assertRaises(OutboundPolicyError):
                        prepare_shipped_metadata(
                            metadata, tls_mode="internal", tls_keyvault_name=None
                        )

    def test_registration_replays_exact_policy_and_rejects_source_mismatch(self):
        source_metadata = self.metadata(proxy_allowed_paths=["/check", "/prove"])
        shipped = prepare_shipped_metadata(
            source_metadata, tls_mode="internal", tls_keyvault_name=None
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            metadata_file = source / "metadata.json"
            metadata_file.write_text(json.dumps(source_metadata))
            packaged = root / "metadata.json"
            exact_bytes = json.dumps(shipped, indent=4) + "\n"
            packaged.write_text(exact_bytes)
            self.assertEqual(
                cli.read_register_app_metadata_json(packaged, source), exact_bytes
            )
            source_metadata["proxy_allowed_paths"] = ["/prove"]
            metadata_file.write_text(json.dumps(source_metadata))
            with self.assertRaisesRegex(cli.DeployerException, "does not match"):
                cli.read_register_app_metadata_json(packaged, source)

    def test_packaging_does_not_invent_routes_for_other_dapps(self):
        metadata = self.metadata()
        self.assertEqual(validate_proxy_allowed_paths(metadata), [])
        shipped = prepare_shipped_metadata(
            metadata, tls_mode="internal", tls_keyvault_name=None
        )
        self.assertNotIn("proxy_allowed_paths", shipped)

    def test_systemd_and_both_os_targets_use_shared_policy_installer(self):
        unit = (REPO_ROOT / "services/attestation_server.service").read_text()
        self.assertIn(f"Environment=DAPP_PROXY_POLICY_FILE={PROXY_POLICY_PATH}\n", unit)
        earthfile = (REPO_ROOT / "Earthfile").read_text()
        self.assertEqual(
            earthfile.count(
                "COPY cli/veritee/proxy_policy.py "
                "mkosi.extra/opt/measured_setup/proxy_policy.py"
            ),
            2,
        )


if __name__ == "__main__":
    unittest.main()
