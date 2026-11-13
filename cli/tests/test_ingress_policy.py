import re
import unittest
from pathlib import Path

import yaml

from veritee.cli import caddyfile_site_hosts
from veritee.outbound import validate_compose_egress_boundary


REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_PROJECT = REPO_ROOT / "projects/proof_server_preprod"


class IngressPolicyTests(unittest.TestCase):
    def test_guest_attestation_is_private_and_agrees_with_the_startup_hook(self):
        compose_files = sorted(
            path for source in (REPO_ROOT / "examples", REPO_ROOT / "projects")
            for path in source.glob("*/run.d/docker-compose.yml")
        )
        self.assertTrue(compose_files)
        for path in compose_files:
            with self.subTest(project=path.parents[1].name):
                compose = yaml.safe_load(path.read_text())
                helper = compose["services"]["guest-attestation"]
                self.assertEqual(helper["image"], "guest-attestation")
                self.assertEqual(helper["env_file"], ["./.guest-attestation.env"])
                self.assertEqual(helper["networks"], ["constrained-attestation"])
                self.assertNotIn("ports", helper)
                self.assertTrue(compose["networks"]["constrained-attestation"]["internal"])
                caddy = compose["services"]["caddy"]
                self.assertIn(
                    "caddy-in-constrained-attestation-generator-network",
                    caddy["networks"]["constrained-attestation"]["aliases"],
                )
                self.assertFalse(any("2019" in str(port) for port in caddy["ports"]))
                self.assertNotIn("constrained-attestation", compose["services"]["app"]["networks"])
                hook = path.parent / "main"
                if not hook.exists():
                    hook = REPO_ROOT / "veritee-os/app-disk/run.d/main"
                self.assertIn("cat > .guest-attestation.env", hook.read_text())

    def test_azure_nsg_does_not_expose_attestation_port(self):
        terraform = (REPO_ROOT / "cli/deploy-azure-snp/main.tf").read_text()

        self.assertNotRegex(
            terraform,
            re.compile(r'destination_port_range\s*=\s*"8000"'),
        )

    def test_guest_firewall_limits_attestation_port_to_docker_bridges(self):
        ipv4_rules = (
            REPO_ROOT
            / "veritee-os/mkosi/rootfs/mkosi.extra/etc/iptables/rules.v4.j2"
        ).read_text()
        ipv6_rules = (
            REPO_ROOT
            / "veritee-os/mkosi/rootfs/mkosi.extra/etc/iptables/rules.v6.j2"
        ).read_text()
        port_rules = [
            line for line in ipv4_rules.splitlines() if "--dport 8000" in line
        ]

        self.assertEqual(len(port_rules), 1)
        self.assertIn("-i br+", port_rules[0])
        self.assertNotIn("--dport 8000", ipv6_rules)

    def test_caddy_keeps_public_tls_attestation_route(self):
        caddyfile = (
            TEST_PROJECT / "run.d/Caddyfile.template"
        ).read_text()

        self.assertIn("handle_path /tee_attestation*", caddyfile)
        self.assertIn("reverse_proxy attestation:8000", caddyfile)

    def test_proof_server_host_hop_is_loopback_only_on_caddy(self):
        compose_path = (
            TEST_PROJECT / "run.d/docker-compose.yml"
        )
        compose = yaml.safe_load(compose_path.read_text())

        self.assertIn("127.0.0.1:8080:8080", compose["services"]["caddy"]["ports"])
        self.assertNotIn("ports", compose["services"]["app"])
        self.assertEqual(compose["services"]["app"]["networks"], ["constrained-app"])
        self.assertTrue(compose["networks"]["constrained-app"]["internal"])
        validate_compose_egress_boundary(compose_path)

    def test_proof_server_host_hop_preserves_upstream_paths_and_public_hosts(self):
        caddyfile = (
            TEST_PROJECT / "run.d/Caddyfile.template"
        ).read_text()
        host_hop = caddyfile.split("http://:8080 {", 1)[1]

        # The attestation server enforces the route allowlist. This local hop
        # must preserve the selected path instead of hardcoding /prove.
        self.assertIn("reverse_proxy {$APP_UPSTREAM}", host_hop)
        compose = yaml.safe_load((TEST_PROJECT / "run.d/docker-compose.yml").read_text())
        self.assertEqual(compose["services"]["caddy"]["environment"]["APP_UPSTREAM"], "app:6300")
        self.assertNotIn("handle_path", host_hop)
        self.assertNotRegex(host_hop, r"(?m)^\s*(?:rewrite|uri|redir)\b")
        self.assertEqual(
            caddyfile_site_hosts(caddyfile),
            ["attestation.proofserver.preprod.example.test", "api.proofserver.preprod.example.test"],
        )


if __name__ == "__main__":
    unittest.main()
