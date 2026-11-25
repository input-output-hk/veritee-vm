import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

from veritee import build, os_release

ROOT = Path(__file__).resolve().parents[2]


class NativeBuildTests(unittest.TestCase):
    def test_os_runner_accepts_new_project_files_without_component_wiring(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, tools, workspace = (root / name for name in ("src", "tools", "workdir"))
            project = source / "project"
            for path in (tools, workspace / "out", project / "docker-packages",
                         project / "initrd", project / "rootfs/mkosi.extra/opt/new-service"):
                path.mkdir(parents=True)
            for name in ("config-azure.yaml", "initrd/mkosi.conf.j2", "rootfs/mkosi.conf.j2",
                         "rootfs/mkosi.postinst.j2", "rootfs/mkosi.extra/opt/new-service/config.j2",
                         "rootfs/mkosi.extra/opt/new-service/payload"):
                (project / name).write_text("fixture\n")
            (project / "rootfs/mkosi.postinst.j2").chmod(0o755)
            renderer = tools / "render_template"
            renderer.write_text('#!/bin/sh\ncat "$2" > "${2%.j2}"\n')
            renderer.chmod(0o755)
            mkosi = tools / "mkosi"
            mkosi.write_text('''#!/bin/sh
set -eu
if [ "${PWD##*/}" = initrd ]; then
    printf initrd > image.cpio.zst
    ln -s image.cpio.zst image
else
    test -f mkosi.extra/opt/new-service/payload
    test -f mkosi.extra/opt/new-service/config
    test ! -e mkosi.extra/opt/new-service/config.j2
    test -x mkosi.postinst
    printf rootfs > image.raw
fi
printf manifest > image.manifest
''')
            mkosi.chmod(0o755)
            script = (ROOT / "build/azure-snp-os.sh").read_text()
            script = script.replace("/src/", str(source) + "/")
            script = script.replace("/root/.local/bin/", str(tools) + "/")
            script = script.replace("/workdir", str(workspace))
            environment = {**os.environ, "OS_CONFIG": "config-azure.yaml", "ATTESTATION_MODE": "raw-sev-snp",
                           "ALLOW_UNBOUND_ATTESTATION": "false", "OUTPUT_UID": str(os.getuid()),
                           "OUTPUT_GID": str(os.getgid())}
            result = subprocess.run(["bash", "-c", script], cwd=workspace, env=environment,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            expected = {"disk.raw": b"rootfs", "disk.manifest": b"manifest",
                        "initrd_image.cpio.zst": b"initrd", "initrd.manifest": b"manifest"}
            self.assertEqual({p.name: p.read_bytes() for p in (workspace / "out").iterdir()}, expected)

    def test_warden_routes_buildkit_through_the_builder_network(self):
        compose = yaml.safe_load((ROOT / "examples/warden/run.d/docker-compose.yml").read_text())
        environment = compose["services"]["app"]["environment"]
        self.assertEqual(environment["VERITEE_BUILD_NETWORK"], "temenos-builder")
        self.assertEqual(environment["VERITEE_BUILD_HTTPS_PROXY"], "http://172.29.254.1:18080")
        self.assertNotIn("HTTPS_PROXY", environment)
        self.assertNotIn("HTTP_PROXY", environment)
        proof_environment = compose["services"]["proof-server"]["environment"]
        self.assertEqual(proof_environment["HTTPS_PROXY"], "http://egress-proxy:18080")
        self.assertEqual(proof_environment["HTTP_PROXY"], proof_environment["HTTPS_PROXY"])
        self.assertNotIn("VERITEE_BUILD_HTTPS_PROXY", proof_environment)

    def test_credentials_stay_in_private_runtime_files(self):
        token = "private-acr-credential"
        with mock.patch.dict(os.environ, {}, clear=True):
            with build.registry_config("source.azurecr.io", token) as directory:
                config = directory / "config.json"
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)
                auth = json.loads(config.read_text())["auths"]["source.azurecr.io"]["auth"]
                self.assertEqual(base64.b64decode(auth).decode().split(":", 1)[1], token)
            self.assertFalse(directory.exists())

    def test_incomplete_credentials_fail_before_building(self):
        for environment in [{"DOCKERHUB_USER": "user"}, {"DOCKERHUB_TOKEN": "token"}]:
            with self.subTest(environment=environment), mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(build.BuildError), build.registry_config():
                    pass

    def test_builder_rejects_host_network_and_invalid_names(self):
        for environment in [{"VERITEE_BUILD_NETWORK": "host"}, {"VERITEE_BUILD_NETWORK": "none"},
                            {"VERITEE_BUILD_BUILDER": "bad/name"}]:
            with self.subTest(environment=environment), mock.patch.object(build, "_command") as run:
                with self.assertRaises(build.BuildError):
                    build.ensure_builder(ROOT, environment, False)
                run.assert_not_called()

    def test_existing_builder_with_other_network_fails_closed(self):
        details = [{"Config": {"Image": build.BUILDKIT_IMAGE, "Env": []},
                    "HostConfig": {"NetworkMode": "bridge"}}]
        with mock.patch.object(build.subprocess, "run", return_value=mock.Mock(returncode=0)), \
                mock.patch.object(build, "_command", side_effect=["", json.dumps(details)]):
            with self.assertRaisesRegex(build.BuildError, "different image/network/proxy"):
                build.ensure_builder(ROOT, {"VERITEE_BUILD_NETWORK": "temenos-builder"}, False)

    def test_runtime_uses_the_configured_network_and_cleans_up_on_failure(self):
        calls = []
        def execute(command, **kwargs):
            calls.append(command)
            if command[:2] == ["docker", "run"]:
                self.assertIn("temenos-builder", command)
                self.assertNotIn("sensitive-token", " ".join(command))
                raise build.BuildError("image pull failed")
            return ""
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(build, "check_inputs"), \
                mock.patch.object(build, "ensure_builder", return_value=("veritee-build", "temenos-builder")), \
                mock.patch.object(build, "_command", side_effect=execute), \
                mock.patch.object(build.subprocess, "run") as cleanup:
            command = build.application_command("app", app_dir=str(ROOT / "projects/proof_server_preprod"),
                image="example/app:1", guest_image="example/helper:1", tls_mode="internal")
            with self.assertRaisesRegex(build.BuildError, "image pull failed"):
                build.run(command, repo=directory, registry="source.azurecr.io", token="sensitive-token")
            self.assertEqual(cleanup.call_count, 2)
            self.assertIn("buildx", calls[0])
            self.assertFalse(list(Path(directory).glob(".veritee-build-*")))

    def test_missing_sources_and_unknown_recipes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(build.BuildError, "Missing build input"):
                build.check_inputs(directory, "azure-snp-base")
        with self.assertRaisesRegex(build.BuildError, "Unsupported build action"):
            build.check_inputs(ROOT, "tpm")

    def test_new_build_manifest_identifies_docker_and_keeps_artifacts_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "build").mkdir()
            recipe = output / "build/Dockerfile"
            recipe.write_text("FROM scratch\n")
            (output / "disk.raw").write_bytes(b"fixture disk")
            (output / "pcrs.json").write_text(json.dumps({"measurements": {"4": "a" * 64}}))
            source = {"commit": "a" * 40, "tree": "b" * 40, "modified": False}
            command = build.base_command("config-azure.yaml", "raw-sev-snp", False)
            with mock.patch.object(os_release, "source_identity", return_value=source):
                os_release.record_build(output, output, source, command, "raw-sev-snp")
            manifest = os_release.create_manifest(output, "native-release", "0.6.0",
                "registry.example/os@sha256:" + "c" * 64, "https://example.test/source")
            self.assertEqual(manifest["build"]["recipe_version"], 2)
            self.assertEqual(manifest["build"]["dockerfile_sha256"], os_release.digest(recipe.read_bytes()))
            self.assertNotIn("earthly_target", manifest["build"])
            self.assertEqual((output / "disk.raw").read_bytes(), b"fixture disk")


if __name__ == "__main__":
    unittest.main()
