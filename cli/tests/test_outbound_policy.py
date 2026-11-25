import tempfile
import unittest
from pathlib import Path

from veritee.outbound import (
    OutboundPolicyError,
    prepare_shipped_metadata,
    validate_compose_egress_boundary,
)


BASE_METADATA = {
    "name": "Example",
    "description": "Example DApp",
    "app_container_image": "registry.example/app@sha256:deadbeef",
    "base_os_image": "registry.example/base-os:1.0.0",
}


class OutboundMetadataTests(unittest.TestCase):
    def test_rejects_unsupported_policy_version(self):
        with self.assertRaisesRegex(
            OutboundPolicyError, "unsupported outbound_policy_version: 3"
        ):
            prepare_shipped_metadata(
                {**BASE_METADATA, "outbound_policy_version": 3},
                tls_mode="internal",
                tls_keyvault_name=None,
            )

    def test_preserves_and_canonicalizes_authored_hostname_policy(self):
        metadata = {
            **BASE_METADATA,
            "outbound": [
                {"host": "Downloads.Example.com.", "ports": [8443, 443]},
                {"host": "1.1.1.1", "ports": [5432]},
            ],
        }

        shipped = prepare_shipped_metadata(
            metadata,
            tls_mode="internal",
            tls_keyvault_name=None,
        )

        self.assertEqual(shipped["outbound_policy_version"], 2)
        self.assertEqual(
            shipped["outbound"],
            [
                {"ip": "1.1.1.1", "ports": [5432]},
                {
                    "host": "downloads.example.com",
                    "ports": [443, 8443],
                },
            ],
        )
        self.assertEqual(
            shipped["platform_outbound"],
            [
                {
                    "host": "midnightl2.eus.attest.azure.net",
                    "ports": [443],
                }
            ],
        )

    def test_packaged_policy_replays_identically(self):
        first = prepare_shipped_metadata(
            {**BASE_METADATA, "outbound": [{"host": "downloads.example.com", "ports": [443]}]},
            tls_mode="internal",
            tls_keyvault_name=None,
        )

        replayed = prepare_shipped_metadata(
            first,
            tls_mode="internal",
            tls_keyvault_name=None,
        )

        self.assertEqual(replayed, first)

    def test_azure_vault_destination_is_measured_and_bound(self):
        shipped = prepare_shipped_metadata(
            BASE_METADATA,
            tls_mode="azure_vault",
            tls_keyvault_name="example-vault",
        )

        self.assertEqual(shipped["tls_keyvault_name"], "example-vault")
        self.assertIn(
            {
                "host": "example-vault.vault.azure.net",
                "ports": [443],
            },
            shipped["platform_outbound"],
        )

        replayed = prepare_shipped_metadata(
            shipped,
            tls_mode="azure_vault",
            tls_keyvault_name=None,
        )
        self.assertEqual(replayed, shipped)

    def test_raw_attestation_image_does_not_grant_maa_egress(self):
        shipped = prepare_shipped_metadata(
            {
                **BASE_METADATA,
                "base_os_image": "registry.example/base-os:1.0.0-raw-sev-snp",
            },
            tls_mode="internal",
            tls_keyvault_name=None,
        )

        self.assertEqual(shipped["platform_outbound"], [])

    def test_rejects_unsafe_or_ambiguous_entries(self):
        invalid_entries = (
            {"host": "https://downloads.example.com/path", "ports": [443]},
            {"host": "*.example.com", "ports": [443]},
            {"host": "downloads.example.com:443", "ports": [443]},
            {"host": "downloads.example.com", "ports": [0]},
            {"host": "downloads.example.com", "ports": [443, 443]},
            {"host": "8.8.8.8", "ports": [53]},
            {"host": "169.254.169.254", "ports": [80]},
            {"host": "127.0.0.1", "ports": [443]},
            {"host": "10.0.0.8", "ports": [443]},
            {"host": "192.0.2.8", "ports": [443]},
            {"host": "2001:db8::8", "ports": [443]},
        )

        for entry in invalid_entries:
            with self.subTest(entry=entry):
                with self.assertRaises(OutboundPolicyError):
                    prepare_shipped_metadata(
                        {**BASE_METADATA, "outbound": [entry]},
                        tls_mode="internal",
                        tls_keyvault_name=None,
                    )

    def test_warden_profile_is_measured_and_exclusive(self):
        with self.assertRaisesRegex(OutboundPolicyError, "explicit packaging override"):
            prepare_shipped_metadata(
                {**BASE_METADATA, "egress_profile": "warden"},
                tls_mode="internal",
                tls_keyvault_name=None,
            )

        shipped = prepare_shipped_metadata(
            {**BASE_METADATA, "egress_profile": "warden"},
            tls_mode="internal",
            tls_keyvault_name=None,
            allow_warden_profile=True,
        )
        self.assertEqual(shipped["egress_profile"], "warden")
        self.assertNotIn("outbound", shipped)

        with self.assertRaises(OutboundPolicyError):
            prepare_shipped_metadata(
                {**BASE_METADATA, "egress_profile": "warden", "outbound": []},
                tls_mode="internal",
                tls_keyvault_name=None,
                allow_warden_profile=True,
            )

    def test_unrestricted_profile_is_measured_and_exclusive(self):
        shipped = prepare_shipped_metadata(
            {**BASE_METADATA, "egress_profile": "unrestricted"},
            tls_mode="internal",
            tls_keyvault_name=None,
        )

        self.assertEqual(shipped["egress_profile"], "unrestricted")
        self.assertNotIn("outbound", shipped)

        with self.assertRaises(OutboundPolicyError):
            prepare_shipped_metadata(
                {
                    **BASE_METADATA,
                    "egress_profile": "unrestricted",
                    "outbound": [],
                },
                tls_mode="internal",
                tls_keyvault_name=None,
            )

    def test_rejects_authored_or_tampered_platform_policy(self):
        with self.assertRaisesRegex(OutboundPolicyError, "generated by packaging"):
            prepare_shipped_metadata(
                {**BASE_METADATA, "platform_outbound": []},
                tls_mode="internal",
                tls_keyvault_name=None,
            )

        packaged = prepare_shipped_metadata(
            BASE_METADATA,
            tls_mode="internal",
            tls_keyvault_name=None,
        )
        packaged["platform_outbound"][0]["host"] = "attacker.example.com"
        with self.assertRaisesRegex(OutboundPolicyError, "required attestation/TLS"):
            prepare_shipped_metadata(
                packaged,
                tls_mode="internal",
                tls_keyvault_name=None,
            )


class ComposeBoundaryTests(unittest.TestCase):
    def validate_text(
        self,
        compose: str,
        *,
        allow_warden_host_access: bool = False,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "docker-compose.yml"
            path.write_text(compose)
            validate_compose_egress_boundary(
                path,
                allow_warden_host_access=allow_warden_host_access,
            )

    def test_current_application_compose_files_are_accepted(self):
        repo_root = Path(__file__).resolve().parents[2]
        compose_files = sorted(
            path for source in (repo_root / "examples", repo_root / "projects")
            for path in source.glob("*/run.d/docker-compose.yml")
        )
        self.assertTrue(compose_files)
        for path in compose_files:
            with self.subTest(path=path):
                validate_compose_egress_boundary(
                    path,
                    allow_warden_host_access=(path.parents[1].name == "warden"),
                )

    def test_rejects_compose_escape_routes(self):
        unsafe_fragments = (
            "privileged: true",
            "network_mode: host",
            "pid: host",
            "cap_add: [NET_ADMIN]",
            "volumes: [/var/run/docker.sock:/var/run/docker.sock]",
            "devices: [/dev/net/tun:/dev/net/tun]",
            "use_api_socket: true",
        )
        for fragment in unsafe_fragments:
            with self.subTest(fragment=fragment):
                compose = f"""services:
  app:
    image: dapp:tee
    networks: [constrained-app]
    {fragment}
networks:
  constrained-app:
    driver: bridge
    internal: true
"""
                with self.assertRaises(OutboundPolicyError):
                    self.validate_text(compose)

    def test_only_caddy_may_join_a_non_internal_bridge(self):
        compose = """services:
  app:
    image: dapp:tee
    networks: [constrained-app, internet-access]
networks:
  constrained-app:
    driver: bridge
    internal: true
  internet-access:
    driver: bridge
"""
        with self.assertRaisesRegex(OutboundPolicyError, "non-internal"):
            self.validate_text(compose)

    def test_warden_profile_allows_only_exact_host_worker_access(self):
        compose = """services:
  app:
    image: dapp:tee
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      constrained-app: {}
      warden-platform:
        ipv4_address: 172.30.254.2
networks:
  constrained-app:
    driver: bridge
    internal: true
  warden-platform:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.254.0/28
"""
        self.validate_text(compose, allow_warden_host_access=True)

        with self.assertRaisesRegex(OutboundPolicyError, "measured Warden profile"):
            self.validate_text(compose)

        redirected_socket = compose.replace(
            "/var/run/docker.sock:/var/run/docker.sock",
            "/var/run/docker.sock:/tmp/docker.sock",
        )
        with self.assertRaisesRegex(OutboundPolicyError, "runtime socket"):
            self.validate_text(
                redirected_socket,
                allow_warden_host_access=True,
            )

        wrong_address = compose.replace("172.30.254.2", "172.30.254.3")
        with self.assertRaisesRegex(OutboundPolicyError, "172.30.254.2"):
            self.validate_text(wrong_address, allow_warden_host_access=True)


if __name__ == "__main__":
    unittest.main()
