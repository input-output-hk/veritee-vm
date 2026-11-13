import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import egress


class FakeIptables:
    def __init__(self):
        self.commands = []
        self.chains = {
            "iptables": {"INPUT", "OUTPUT", "FORWARD"},
            "ip6tables": {"INPUT", "OUTPUT", "FORWARD"},
        }
        self.rules = {
            "iptables": {chain: set() for chain in self.chains["iptables"]},
            "ip6tables": {chain: set() for chain in self.chains["ip6tables"]},
        }

    def __call__(self, command, check=True):
        self.commands.append(command)
        tool = command[0]
        action = command[3]
        if action == "-nL":
            return 0 if command[4] in self.chains[tool] else 1
        if action == "-N":
            self.chains[tool].add(command[4])
            self.rules[tool][command[4]] = set()
            return 0
        if action == "-C":
            return 0 if tuple(command[5:]) in self.rules[tool][command[4]] else 1
        if action == "-D":
            self.rules[tool][command[4]].discard(tuple(command[5:]))
            return 0
        if action in ("-I", "-A"):
            rule_start = 6 if action == "-I" and command[5].isdigit() else 5
            self.rules[tool][command[4]].add(tuple(command[rule_start:]))
            return 0
        if action == "-F":
            self.rules[tool][command[4]].clear()
            return 0
        return 0


class EgressPolicyTests(unittest.TestCase):
    def shipped_metadata(self):
        return {
            "outbound_policy_version": 2,
            "outbound": [
                {
                    "host": "downloads.example.com",
                    "ports": [443],
                },
                {"ip": "2606:4700:4700::1111", "ports": [8443]},
            ],
            "platform_outbound": [
                {
                    "host": "midnightl2.eus.attest.azure.net",
                    "ports": [443],
                }
            ],
        }

    def test_rejects_invalid_or_privileged_dapp_entries(self):
        invalid = (
            {"host": "*.example.com", "ports": [443]},
            {"ip": "169.254.169.254", "ports": [80]},
            {"ip": "10.0.0.8", "ports": [443]},
            {"ip": "192.0.2.8", "ports": [443]},
            {"ip": "fe80::1", "ports": [443]},
            {"ip": "2001:db8::8", "ports": [443]},
            {"ip": "8.8.8.8", "ports": [53]},
            {"ip": "203.0.113.8", "ports": [70000]},
        )
        for entry in invalid:
            with self.subTest(entry=entry):
                metadata = self.shipped_metadata()
                metadata["outbound"] = [entry]
                with self.assertRaises(egress.EgressPolicyError):
                    egress.policy_from_metadata(metadata)

    def test_only_proxy_users_receive_declared_ports_and_dns(self):
        policy = egress.policy_from_metadata(self.shipped_metadata())
        runner = FakeIptables()

        egress.apply_policy(policy, runner, proxy_uids=(4242, 4343))

        commands = [" ".join(command) for command in runner.commands]
        for tool, uid, port in (
            ("iptables", 4242, 443),
            ("iptables", 4343, 443),
            ("ip6tables", 4242, 8443),
        ):
            self.assertTrue(
                any(
                    command.startswith(
                        f"{tool} -w 5 -I {egress.HOST_CHAIN} "
                    )
                    and f"--uid-owner {uid}" in command
                    and f"--dport {port}" in command
                    for command in commands
                )
            )
        for uid in (4242, 4343):
            for protocol in ("udp", "tcp"):
                self.assertTrue(
                    any(
                        command.startswith(
                            f"iptables -w 5 -I {egress.HOST_CHAIN} "
                        )
                        and f"-p {protocol} -d {egress.AZURE_DNS_IP} --dport 53"
                        in command
                        and f"--uid-owner {uid}" in command
                        for command in commands
                    )
                )
        self.assertFalse(
            any(
                egress.CONTAINER_CHAIN in command and "--dport 53" in command
                for command in commands
            )
        )
        self.assertFalse(any("2606:4700:4700::1111" in command for command in commands))
        for tool in ("iptables", "ip6tables"):
            self.assertIn(
                f"{tool} -w 5 -A TEMENOS-CONTAINER-EGRESS -j DROP",
                commands,
            )
            self.assertIn(
                f"{tool} -w 5 -I DOCKER-USER 1 -j TEMENOS-CONTAINER-EGRESS",
                commands,
            )
            for interface in ("br+", "docker+"):
                self.assertIn(
                    f"{tool} -w 5 -I {egress.HOST_CHAIN} "
                    f"-o {interface} -j ACCEPT",
                    commands,
                )

        self.assertFalse(any(" -F " in command for command in commands))

        before = len(runner.commands)
        egress.apply_policy(policy, runner, proxy_uids=(4242, 4343))
        repeated_commands = [" ".join(command) for command in runner.commands[before:]]
        self.assertFalse(
            any(
                " -A " in command or " -I TEMENOS-APP-OUTBOUND " in command
                or " -I TEMENOS-CONTAINER-EGRESS " in command
                for command in repeated_commands
            )
        )

    def test_warden_profile_allows_https_and_imds(self):
        metadata = self.shipped_metadata()
        metadata.pop("outbound")
        metadata["egress_profile"] = "warden"
        policy = egress.policy_from_metadata(metadata)
        runner = FakeIptables()

        egress.apply_policy(policy, runner, proxy_uids=(4242, 4343))

        commands = [" ".join(command) for command in runner.commands]
        for tool in ("iptables", "ip6tables"):
            self.assertTrue(
                any(
                    command.startswith(
                        f"{tool} -w 5 -I {egress.HOST_CHAIN} "
                    )
                    and "--dport 443" in command
                    and "--uid-owner 4242" in command
                    for command in commands
                )
            )
            self.assertFalse(
                any(
                    command.startswith(
                        f"{tool} -w 5 -I {egress.HOST_CHAIN} "
                    )
                    and "--dport 80" in command
                    and "--uid-owner 4242" in command
                    for command in commands
                )
            )
            self.assertFalse(
                any(
                    command.startswith(f"{tool} -w 5 -I ")
                    and "--dport 8000" in command
                    for command in commands
                )
            )

        self.assertTrue(
            any(
                command.startswith(
                    f"iptables -w 5 -I {egress.CONTAINER_CHAIN} "
                )
                and f"-s {egress.WARDEN_PLATFORM_APP_IP}/32" in command
                and f"-d {egress.AZURE_IMDS_IP}/32" in command
                and "--dport 80" in command
                for command in commands
            )
        )
        for protocol in ("udp", "tcp"):
            self.assertTrue(
                any(
                    command.startswith(
                        f"iptables -w 5 -I {egress.CONTAINER_CHAIN} "
                    )
                    and f"-s {egress.WARDEN_PLATFORM_APP_IP}/32" in command
                    and f"-d {egress.AZURE_DNS_IP}/32" in command
                    and f"-p {protocol}" in command
                    and "--dport 53" in command
                    for command in commands
                )
            )
            self.assertTrue(
                any(
                    command.startswith(
                        f"iptables -w 5 -I {egress.CONTAINER_CHAIN} "
                    )
                    and f"-s {egress.BUILDER_NETWORK_SUBNET}" in command
                    and f"-d {egress.AZURE_DNS_IP}/32" in command
                    and f"-p {protocol}" in command
                    and "--dport 53" in command
                    for command in commands
                )
            )
        self.assertTrue(
            any(
                command.startswith(
                    f"iptables -w 5 -I {egress.CONTAINER_CHAIN} "
                )
                and f"-s {egress.WARDEN_PLATFORM_APP_IP}/32" in command
                and "-p tcp" in command
                and "--dport 443" in command
                for command in commands
            )
        )
        self.assertFalse(
            any(
                command.startswith(
                    f"ip6tables -w 5 -I {egress.CONTAINER_CHAIN} "
                )
                and egress.AZURE_IMDS_IP in command
                for command in commands
            )
        )
        self.assertFalse(
            any(
                f"-s {egress.BUILDER_NETWORK_SUBNET}" in command
                and egress.AZURE_IMDS_IP in command
                for command in commands
            )
        )
        self.assertFalse(
            any(
                f"-s {egress.BUILDER_NETWORK_SUBNET}" in command
                and "--dport 443" in command
                for command in commands
            )
        )
        self.assertFalse(
            any(
                f"-s {egress.BUILDER_NETWORK_SUBNET}" in command
                and "--dport 80" in command
                and command.endswith("-j ACCEPT")
                for command in commands
            )
        )

    def test_builder_network_is_created_with_the_reserved_subnet(self):
        commands = []
        state = {"network": None}

        def runner(command, check=True):
            commands.append(command)
            state["network"] = {
                "Driver": "bridge",
                "Internal": False,
                "IPAM": {
                    "Config": [
                        {
                            "Subnet": egress.BUILDER_NETWORK_SUBNET,
                            "Gateway": egress.BUILDER_NETWORK_GATEWAY,
                        }
                    ]
                },
            }
            return 0

        egress.ensure_builder_network(
            runner=runner,
            inspector=lambda _name: state["network"],
        )

        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][-1], egress.BUILDER_NETWORK)
        self.assertIn(egress.BUILDER_NETWORK_SUBNET, commands[0])
        self.assertIn(egress.BUILDER_NETWORK_GATEWAY, commands[0])

    def test_builder_network_rejects_an_unexpected_subnet(self):
        network = {
            "Driver": "bridge",
            "Internal": False,
            "IPAM": {"Config": [{"Subnet": "172.30.0.0/16"}]},
        }

        with self.assertRaisesRegex(
            egress.EgressPolicyError,
            "must be a non-internal bridge",
        ):
            egress.ensure_builder_network(
                inspector=lambda _name: network,
            )

    def test_unrestricted_profile_allows_proxy_all_public_tcp_ports(self):
        metadata = self.shipped_metadata()
        metadata.pop("outbound")
        metadata["egress_profile"] = "unrestricted"
        policy = egress.policy_from_metadata(metadata)
        runner = FakeIptables()

        egress.apply_policy(policy, runner, proxy_uids=(4242, 4343))

        commands = [" ".join(command) for command in runner.commands]
        for tool in ("iptables", "ip6tables"):
            app_rules = [
                command
                for command in commands
                if command.startswith(f"{tool} -w 5 -I {egress.HOST_CHAIN} ")
                and "--uid-owner 4242" in command
                and "-p tcp" in command
            ]
            self.assertTrue(any("--dport" not in command for command in app_rules))

        self.assertFalse(
            any(
                command.startswith(
                    f"iptables -w 5 -I {egress.CONTAINER_CHAIN} "
                )
                and "--uid-owner 4242" in command
                for command in commands
            )
        )

    def test_install_persists_policy_before_applying_it(self):
        events = []

        def runner(command, check=True):
            events.append(("command", command))
            if command[3] in ("-nL", "-C"):
                return 1
            return 0

        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_path = Path(tmpdir) / "metadata.json"
            state_path = Path(tmpdir) / "policy.json"
            metadata_path.write_text(json.dumps(self.shipped_metadata()))

            original_write = egress.write_policy_state

            def recording_write(policy, path=egress.POLICY_STATE_PATH):
                events.append(("write", path))
                original_write(policy, path)

            with mock.patch.object(egress, "write_policy_state", recording_write):
                egress.install_from_metadata(
                    metadata_path,
                    state_path=state_path,
                    runner=runner,
                    proxy_uids=(4242, 4343),
                )

            self.assertEqual(events[0], ("write", state_path))
            state = json.loads(state_path.read_text())
            self.assertEqual(state["version"], 2)
            self.assertIn(
                {"host": "downloads.example.com", "port": 443},
                state["outbound"],
            )

    def test_install_creates_builder_network_only_for_warden_profile(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_path = Path(tmpdir) / "metadata.json"
            state_path = Path(tmpdir) / "policy.json"
            metadata = self.shipped_metadata()
            metadata.pop("outbound")
            metadata["egress_profile"] = "warden"
            metadata_path.write_text(json.dumps(metadata))
            builder_network_manager = mock.Mock()

            egress.install_from_metadata(
                metadata_path,
                state_path=state_path,
                runner=FakeIptables(),
                proxy_uids=(4242, 4343),
                builder_network_manager=builder_network_manager,
            )

            builder_network_manager.assert_called_once_with()
            builder_network_manager.reset_mock()
            metadata_path.write_text(json.dumps(self.shipped_metadata()))

            egress.install_from_metadata(
                metadata_path,
                state_path=state_path,
                runner=FakeIptables(),
                proxy_uids=(4242, 4343),
                builder_network_manager=builder_network_manager,
            )

            builder_network_manager.assert_not_called()

    def test_rejects_invalid_derived_policy_before_reapplying(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.json"
            policy_path.write_text(json.dumps({"version": 2, "outbound": []}))

            with self.assertRaisesRegex(egress.EgressPolicyError, "invalid derived policy"):
                egress.install_from_policy_file(
                    policy_path,
                    runner=FakeIptables(),
                    proxy_uids=(4242, 4343),
                )

    def test_guest_rejects_compose_escape_routes(self):
        base = {
            "services": {
                "app": {
                    "image": "dapp:tee",
                    "networks": {"constrained-app": None},
                },
                "proof-server": {
                    "image": "proof-server:tee",
                    "networks": {"constrained-app": None},
                },
            },
            "networks": {
                "constrained-app": {
                    "driver": "bridge",
                    "internal": True,
                }
            },
        }
        self.assertEqual(
            egress.validate_compose_config(base),
            {"app", "proof-server"},
        )

        unsafe_services = (
            {"privileged": True},
            {"network_mode": "host"},
            {"pid": "host"},
            {"cap_add": ["CAP_NET_ADMIN"]},
            {
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/var/run/docker.sock",
                        "target": "/var/run/docker.sock",
                    }
                ]
            },
            {
                "devices": [
                    {
                        "source": "/dev/net/tun",
                        "target": "/dev/net/tun",
                    }
                ]
            },
        )
        for override in unsafe_services:
            with self.subTest(override=override):
                compose = json.loads(json.dumps(base))
                compose["services"]["app"].update(override)
                with self.assertRaises(egress.EgressPolicyError):
                    egress.validate_compose_config(compose)

    def test_guest_accepts_measured_warden_host_worker_access(self):
        compose = {
            "services": {
                "app": {
                    "image": "dapp:tee",
                    "volumes": [
                        {
                            "type": "bind",
                            "source": "/var/run/docker.sock",
                            "target": "/var/run/docker.sock",
                        }
                    ],
                    "networks": {
                        "constrained-app": None,
                        "warden-platform": {
                            "ipv4_address": "172.30.254.2",
                        },
                    },
                }
            },
            "networks": {
                "constrained-app": {
                    "driver": "bridge",
                    "internal": True,
                },
                "warden-platform": {
                    "driver": "bridge",
                    "ipam": {
                        "config": [{"subnet": "172.30.254.0/28"}],
                    },
                },
            },
        }

        self.assertEqual(
            egress.validate_compose_config(
                compose,
                allow_warden_host_access=True,
            ),
            {"app"},
        )
        with self.assertRaisesRegex(
            egress.EgressPolicyError,
            "measured Warden profile",
        ):
            egress.validate_compose_config(compose)


class StaticFirewallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[2]

    def test_ipv4_rules_are_default_deny_without_customer_ips_or_dns_bypass(self):
        rules = (
            self.repo_root
            / "veritee-os/mkosi/rootfs/mkosi.extra/etc/iptables/rules.v4.j2"
        ).read_text()

        self.assertIn("-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", rules)
        self.assertIn("-A OUTPUT -j DROP", rules)
        self.assertIn("-A TEMENOS-CONTAINER-EGRESS -j DROP", rules)
        self.assertIn("-A FORWARD -j DOCKER-USER", rules)
        self.assertIn("-A INPUT -i br+ -p tcp --dport 18080", rules)
        self.assertIn("-d 255.255.255.255 --sport 68 --dport 67", rules)
        self.assertNotIn("--dport 53", rules)
        self.assertNotIn("--sport 53", rules)
        self.assertNotIn("98.88.171.11", rules)

    def test_proxy_service_accepts_loopback_and_docker_bridge_clients(self):
        unit = (
            self.repo_root
            / "veritee-os/mkosi/rootfs/mkosi.extra/etc/systemd/system/temenos-egress-proxy@.service"
        ).read_text()

        self.assertIn("--policy-file /run/temenos/egress-policy.json", unit)
        self.assertIn("--allow-client-cidr 127.0.0.0/8", unit)
        self.assertIn("--allow-client-cidr 172.30.255.0/24", unit)
        self.assertNotIn(egress.BUILDER_NETWORK_SUBNET, unit)
        self.assertNotIn("--allow-client-cidr 10.0.0.0/8", unit)
        self.assertNotIn("--allow-client-cidr 172.16.0.0/12", unit)
        self.assertNotIn("--allow-client-cidr 192.168.0.0/16", unit)
        self.assertIn("--dns-server 168.63.129.16", unit)

    def test_warden_uses_azure_dns_for_non_proxy_aware_clients(self):
        compose = (
            self.repo_root
            / "examples/warden/run.d/docker-compose.yml"
        ).read_text()

        self.assertIn("dns:\n      - 168.63.129.16", compose)

    def test_warden_routes_earthly_buildkit_through_the_builder_network(self):
        compose = (
            self.repo_root
            / "examples/warden/run.d/docker-compose.yml"
        ).read_text()
        earthly_config = (
            self.repo_root
            / "examples/warden/run.d/earthly-config.yml"
        ).read_text()
        earthly_args = (
            self.repo_root
            / "examples/warden/run.d/earthly-proxy.arg"
        ).read_text()
        earthfile = (self.repo_root / "Earthfile").read_text()
        run_script = (
            self.repo_root / "examples/warden/run.d/main"
        ).read_text()

        self.assertIn(
            'EARTHLY_ARG_FILE_PATH: "/etc/temenos/earthly-proxy.arg"',
            compose,
        )
        self.assertIn('EARTHLY_CONFIG: "/etc/temenos/earthly-config.yml"', compose)
        self.assertIn(
            "./earthly-proxy.arg:/etc/temenos/earthly-proxy.arg:ro",
            compose,
        )
        self.assertIn("--network\n    - temenos-builder", earthly_config)
        self.assertIn("--dns\n    - 168.63.129.16", earthly_config)
        self.assertIn("HTTPS_PROXY=http://172.29.254.1:18080", earthly_config)
        self.assertIn("HTTPS_PROXY=http://172.29.254.1:18080", earthly_args)
        git_config_prefix = "- EARTHLY_GIT_CONFIG="
        encoded_git_config = next(
            line.strip()[len(git_config_prefix) :]
            for line in earthly_config.splitlines()
            if line.strip().startswith(git_config_prefix)
        )
        self.assertEqual(
            base64.b64decode(encoded_git_config).decode(),
            "[http]\n\tproxy = http://172.29.254.1:18080\n",
        )
        self.assertNotIn("HTTP_PROXY=http://172.29.254.1:18080", earthly_config)
        self.assertNotIn("HTTP_PROXY=http://172.29.254.1:18080", earthly_args)
        self.assertIn('ARG --global HTTP_PROXY=""', earthfile)
        self.assertIn('ARG --global https_proxy=""', earthfile)
        for variable in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
        ):
            self.assertIn(f"ENV {variable}=${variable}", earthfile)
        self.assertIn("docker network inspect", run_script)
        self.assertIn("TEMENOS_BUILDER_GATEWAY", run_script)

    def test_warden_persists_earthly_cache_outside_docker_tmpfs(self):
        run_script = (
            self.repo_root / "examples/warden/run.d/main"
        ).read_text()
        metadata = json.loads(
            (
                self.repo_root / "examples/warden/metadata.json"
            ).read_text()
        )

        self.assertEqual(metadata["persist_size"], "32G")
        self.assertIn(
            "warden_persist_dir=/mnt/persist/temenos-warden",
            run_script,
        )
        self.assertIn(
            'earthly_cache_dir="$warden_persist_dir/earthly-cache"',
            run_script,
        )
        self.assertIn("docker volume inspect earthly-cache", run_script)
        self.assertIn("docker volume create", run_script)
        self.assertIn('--opt "device=$earthly_cache_dir"', run_script)

    def test_debian_snapshot_bootstraps_pinned_ca_over_https(self):
        earthfile = (self.repo_root / "Earthfile").read_text()
        ca_package = (
            self.repo_root
            / "veritee-os/bootstrap/ca-certificates_20250419_all.deb"
        )

        self.assertNotIn("http://snapshot.debian.org", earthfile)
        self.assertIn(
            "https://snapshot.debian.org/archive/debian/20251208T000000Z/",
            earthfile,
        )
        self.assertEqual(
            hashlib.sha256(ca_package.read_bytes()).hexdigest(),
            "ef590f89563aa4b46c8260d49d1cea0fc1b181d19e8df3782694706adf05c184",
        )
        self.assertIn(
            'Acquire::https::CaInfo "/usr/local/share/veritee/bootstrap-ca.crt";',
            earthfile,
        )

    def test_docker_daemon_uses_the_measured_proxy(self):
        drop_in = (
            self.repo_root
            / "veritee-os/mkosi/rootfs/mkosi.extra/etc/systemd/system/"
            "docker.service.d/temenos-egress.conf"
        ).read_text()

        self.assertIn("HTTP_PROXY=http://127.0.0.1:18080", drop_in)
        self.assertIn("HTTPS_PROXY=http://127.0.0.1:18080", drop_in)

    def test_vm_kernel_probe_uses_a_routable_bridge_and_drop_counter(self):
        script = (
            self.repo_root / "scripts/test-proof-server-kernel-egress.sh"
        ).read_text()

        self.assertIn("docker network create --driver bridge", script)
        self.assertNotIn("docker network create --internal", script)
        self.assertIn("-L TEMENOS-CONTAINER-EGRESS", script)
        self.assertIn("after <= before", script)

    def test_ipv6_rules_are_default_deny(self):
        rules = (
            self.repo_root
            / "veritee-os/mkosi/rootfs/mkosi.extra/etc/iptables/rules.v6.j2"
        ).read_text()
        self.assertIn("-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", rules)
        self.assertIn("-A OUTPUT -j TEMENOS-APP-OUTBOUND", rules)
        self.assertIn("-A OUTPUT -j DROP", rules)
        self.assertIn("-A TEMENOS-CONTAINER-EGRESS -j DROP", rules)
        self.assertIn("-d ff02::1:2 --sport 546 --dport 547", rules)

    def test_os_build_copies_only_measured_setup_runtime_files(self):
        earthfile = (self.repo_root / "Earthfile").read_text()

        self.assertNotIn("COPY veritee-os/measured_setup/*", earthfile)
        self.assertEqual(
            earthfile.count(
                "COPY veritee-os/measured_setup/main.py "
                "mkosi.extra/opt/measured_setup/main.py"
            ),
            2,
        )
        self.assertEqual(
            earthfile.count(
                "COPY veritee-os/measured_setup/egress.py "
                "mkosi.extra/opt/measured_setup/egress.py"
            ),
            2,
        )
    def test_compose_files_do_not_give_dapps_a_routable_egress_bridge(self):
        compose_files = sorted(
            path for source in (self.repo_root / "examples", self.repo_root / "projects")
            for path in source.glob("*/run.d/docker-compose.yml")
        )
        self.assertTrue(compose_files)
        for compose_file in compose_files:
            with self.subTest(compose_file=compose_file):
                self.assertNotIn("app-egress", compose_file.read_text())
                self.assertNotIn("controlled-egress", compose_file.read_text())


if __name__ == "__main__":
    unittest.main()
