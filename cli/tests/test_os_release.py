import base64
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import copy
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, HTTPSHandler

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from typer.testing import CliRunner

from veritee import cli, os_release
from veritee.os_release_carrier import (BoundedReader, CarrierTarInfo, NoRedirect, RegistryRedirect,
                                       CARRIER_ARTIFACT_PREFIX, PublicHTTPSHandler, acr_blob_redirect, public_address,
                                       fetch_carrier, read_json)


class ReleaseSigningTests(unittest.TestCase):
    def test_acceptance_view_is_bound_to_its_historical_signer_and_file_report(self):
        fixture = read_json((Path(__file__).parent / "fixtures/os-release-v1.json").read_bytes())
        envelope = fixture["envelope"]
        manifest = read_json(envelope["manifest"])
        payload_bytes = base64.urlsafe_b64decode(envelope["jws"]["payload"] + "==")
        header = read_json(base64.urlsafe_b64decode(envelope["jws"]["protected"] + "=="))
        developer = {"identity": "fixture-developer", "public_key_pem": fixture["public_key_pem"], "operations": ["approve_release"]}
        report = os_release.canonical({"artifacts": manifest["artifacts"], "pcr4": manifest["measurements"]["pcr4"],
                                       "validation": "published_files_checked_not_reproduced"})
        jws = os_release.canonical(envelope["jws"])
        receipt = {"os_key": fixture["manifest_digest"][7:], "release_manifest_digest": fixture["manifest_digest"],
                   "acceptance": "dev_signature_verified", "raw_disk_sha256": manifest["artifacts"][0]["sha256"],
                   "measurements": manifest["measurements"], "audience": fixture["audience"],
                   "developer": {"kid": header["kid"], **developer},
                   "configuration": {"developers": {header["kid"]: developer}, "audience": fixture["audience"],
                                     "limits": {"max_validity_seconds": 3600, "clock_skew_seconds": 30}},
                   "accepted_at": int(datetime(2026, 10, 26, 12, tzinfo=timezone.utc).timestamp()),
                   "artifact_report_digest": "sha256:" + os_release.digest(report.encode()),
                   "signature_digest": "sha256:" + os_release.digest(jws.encode()),
                   "payload_digest": "sha256:" + os_release.digest(payload_bytes)}
        evidence = os_release.canonical(receipt)
        selection = {"os_key": receipt["os_key"], "network": fixture["audience"]["network"],
                     "registry_address": fixture["audience"]["os_registry_address"], "manifest": envelope["manifest"],
                     "evidence": evidence, "report": report, "jws": jws, "payload": payload_bytes.decode(),
                     "entry": {"acceptance": "dev_signature_verified", "raw_disk_sha256": receipt["raw_disk_sha256"],
                               "pcr4": manifest["measurements"]["pcr4"], "evidence_digest": "sha256:" + os_release.digest(evidence.encode())}}
        os_release.verify_acceptance_evidence(selection)
        changed = copy.deepcopy(selection)
        changed["report"] += " "
        with self.assertRaisesRegex(ValueError, "digest"):
            os_release.verify_acceptance_evidence(changed)
        receipt["accepted_at"] += 7200
        changed = copy.deepcopy(selection)
        changed["evidence"] = os_release.canonical(receipt)
        changed["entry"]["evidence_digest"] = "sha256:" + os_release.digest(changed["evidence"].encode())
        with self.assertRaisesRegex(ValueError, "acceptance time"):
            os_release.verify_acceptance_evidence(changed)

    def test_manifest_emission_rejects_stale_outputs_and_does_not_change_measurements(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            disk, pcrs = directory / "disk.raw", directory / "pcrs.json"
            disk.write_bytes(b"a fake base OS")
            pcrs.write_text('{"measurements":{"4":"' + "e" * 64 + '"}}')
            before = pcrs.read_bytes()
            source = {"commit": "a" * 40, "tree": "b" * 40, "modified": False}
            command = cli.build_base_os_command(os_config="config-azure.yaml",
                attestation_mode=cli.AttestationMode.RAW_SEV_SNP, allow_unbound_attestation=False)
            (directory / "build").mkdir()
            (directory / "build/Dockerfile").write_text("FROM scratch\n")
            with mock.patch.object(os_release, "source_identity", return_value=source):
                os_release.record_build(directory, directory, source, command, "raw-sev-snp")
            with self.assertRaisesRegex(ValueError, "digest-pinned"):
                os_release.create_manifest(directory, "test-release", "0.6.0-raw-sev-snp",
                    "registry.example/temenos/os:v1", "https://github.com/input-output-hk/temenos-vm")
            manifest = os_release.create_manifest(directory, "test-release", "0.6.0-raw-sev-snp",
                "registry.example/temenos/os:v1@sha256:" + "1" * 64, "https://github.com/input-output-hk/temenos-vm")
            self.assertEqual(manifest["measurements"]["pcr4"], "e" * 64)
            self.assertEqual(pcrs.read_bytes(), before)
            self.assertNotIn("release_manifest_digest", manifest)
            disk.write_bytes(b"changed output")
            with self.assertRaisesRegex(ValueError, "outputs changed"):
                os_release.create_manifest(directory, "test-release", "0.6.0-raw-sev-snp",
                    "registry.example/temenos/os:v1@sha256:" + "1" * 64, "https://github.com/input-output-hk/temenos-vm")

    def test_shared_signature_fixture(self):
        fixture = read_json((Path(__file__).parent / "fixtures/os-release-v1.json").read_bytes())
        envelope = fixture["envelope"]
        self.assertEqual(fixture["manifest_digest"], "sha256:" + os_release.digest(envelope["manifest"].encode()))
        self.assertEqual(os_release.canonical(read_json(envelope["manifest"])), envelope["manifest"])
        jws = envelope["jws"]
        raw = base64.urlsafe_b64decode(jws["signature"] + "==")
        signature = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        key = serialization.load_pem_public_key(fixture["public_key_pem"].encode())
        key.verify(signature, f'{jws["protected"]}.{jws["payload"]}'.encode(), ec.ECDSA(hashes.SHA256()))

    def test_canonical_closed_domain_matches_jcs_utf16_order(self):
        value = {"\ufffd": "bmp", "\U0001f600": "astral", "b": True, "a": 1}
        self.assertEqual(os_release.canonical(value), '{"a":1,"b":true,"\U0001f600":"astral","\ufffd":"bmp"}')
        for invalid in (float("nan"), 1.5, 2**53, "\ud800"):
            with self.subTest(invalid=repr(invalid)), self.assertRaises((ValueError, UnicodeError)):
                os_release.canonical(invalid)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            read_json('{"a":1,"a":1}')

    def test_signs_flattened_es256_with_raw_signature_not_der(self):
        key = ec.generate_private_key(ec.SECP256R1())
        manifest = b'{"release_id":"test"}'
        audience = {"warden_id": "test", "network": "preprod", "os_registry_address": "a" * 64}
        result = os_release.sign_manifest(manifest, key, audience, "request-1", datetime(2026, 10, 26, tzinfo=timezone.utc), 3600)
        jws = result["jws"]
        decode = lambda data: base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
        raw = decode(jws["signature"])
        self.assertEqual(len(raw), 64)
        signature = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        key.public_key().verify(signature, f'{jws["protected"]}.{jws["payload"]}'.encode(), ec.ECDSA(hashes.SHA256()))
        payload = read_json(decode(jws["payload"]))
        self.assertEqual(payload["audience"], audience)
        self.assertEqual(payload["release_manifest_digest"], "sha256:" + hashlib.sha256(manifest).hexdigest())
        self.assertNotIn("signature", read_json(manifest))

    def test_keygen_keeps_private_key_private_and_does_not_replace_it(self):
        with tempfile.TemporaryDirectory() as temp:
            private, public = Path(temp) / "developer.pem", Path(temp) / "developer.pub.pem"
            args = ["os-release", "keygen", "--private-key", str(private), "--public-key", str(public)]
            result = CliRunner().invoke(cli.app, args)
            self.assertEqual(result.exit_code, 0, result.exception)
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            before = private.read_bytes()
            self.assertNotEqual(CliRunner().invoke(cli.app, args).exit_code, 0)
            self.assertEqual(private.read_bytes(), before)

    def test_unknown_os_fails_before_any_packaging_or_metadata_mutation(self):
        with mock.patch.object(os_release, "resolve_selection", side_effect=ValueError("unknown OS")), \
                mock.patch.object(cli, "run_streamable_command") as build, \
                mock.patch.object(cli, "load_app_source_metadata", return_value={"base_os_image": "registry/os:v1"}):
            result = CliRunner().invoke(cli.app, ["package-dapp-deployable-vm-image", "--no-push"])
            self.assertNotEqual(result.exit_code, 0)
            build.assert_not_called()


class AutomaticSelectionTests(unittest.TestCase):
    def setUp(self):
        self.reference = "registry.example/os:v1@sha256:" + "d" * 64
        self.entry = {"release_version": "0.6.0", "attestation_mode": "raw-sev-snp"}
        self.selected = {"os_key": "a" * 64, "entry": self.entry,
                         "manifest": os_release.canonical({"publication": {"reference": self.reference}})}
        env = mock.patch.dict(os.environ, {}, clear=True)
        env.start()
        self.addCleanup(env.stop)

    def test_resolves_the_exact_project_image_without_a_key(self):
        with mock.patch.object(os_release, "query_registry", return_value=[{"os_key": "a" * 64, **self.entry}]) as query, \
                mock.patch.object(os_release, "selection_from_entry", return_value=self.selected) as view:
            self.assertEqual(os_release.resolve_selection(base_os_image=self.reference), self.selected)
        query.assert_called_once_with("list-os-releases")
        view.assert_called_once_with("a" * 64, self.entry)

    def test_missing_and_ambiguous_approvals_never_select_first_or_latest(self):
        for candidates, message in (([], "no confirmed"), ([self.selected, self.selected], "Multiple")):
            with self.subTest(message=message), mock.patch.object(os_release, "confirmed_selections", return_value=iter(candidates)), \
                    self.assertRaisesRegex(ValueError, message):
                os_release.resolve_selection(base_os_image=self.reference)
        with mock.patch.object(os_release, "confirmed_selections", return_value=iter([self.selected])), \
                self.assertRaisesRegex(ValueError, "no confirmed"):
            os_release.resolve_selection(base_os_image="another/image@sha256:" + "b" * 64)

    def test_malformed_or_duplicate_chain_listing_fails(self):
        row = {"os_key": "a" * 64, **self.entry}
        for rows in ({}, [None], [{"os_key": "invalid"}], [row, row]):
            with self.subTest(rows=rows), mock.patch.object(os_release, "query_registry", return_value=rows), \
                    mock.patch.object(os_release, "selection_from_entry", return_value=self.selected), \
                    self.assertRaisesRegex(ValueError, "Invalid|duplicate"):
                list(os_release.confirmed_selections())

    def test_advanced_override_cannot_change_the_project_image(self):
        with mock.patch.object(os_release, "query_registry", return_value=self.entry) as query, \
                mock.patch.object(os_release, "selection_from_entry", return_value=self.selected):
            with mock.patch.dict(os.environ, {"TEMENOS_OS_RELEASE_KEY": "a" * 64}):
                self.assertEqual(os_release.resolve_selection(base_os_image=self.reference), self.selected)
            query.assert_called_once_with("get-os-release", os_key="a" * 64)
            with self.assertRaisesRegex(ValueError, "disagrees"):
                os_release.resolve_selection("a" * 64, base_os_image="other/image@sha256:" + "d" * 64)

    def test_optional_tags_do_not_change_a_digest_pinned_carrier_identity(self):
        tagged = os_release.carrier_identity(self.reference).replace("@sha256:", ":release-tag@sha256:")
        with mock.patch.object(os_release, "confirmed_selections", return_value=iter([self.selected])):
            self.assertEqual(os_release.resolve_selection(base_os_image=tagged), self.selected)
        duplicate = {**self.selected, "manifest": os_release.canonical({"publication": {"reference": tagged}})}
        with mock.patch.object(os_release, "confirmed_selections", return_value=iter([self.selected, duplicate])):
            with self.assertRaisesRegex(ValueError, "Multiple"):
                os_release.resolve_selection(base_os_image=self.reference)

    def test_listing_is_partial_but_automatic_selection_cannot_hide_an_unavailable_match(self):
        rows = [{"os_key": "b" * 64, **self.entry}, {"os_key": "a" * 64, **self.entry}]
        def view(key, entry):
            if key == "b" * 64:
                raise ValueError("missing evidence")
            return self.selected
        with mock.patch.object(os_release, "query_registry", return_value=rows), \
                mock.patch.object(os_release, "selection_from_entry", side_effect=view), \
                self.assertLogs("veritee", level="WARNING") as logs:
            self.assertEqual(list(os_release.confirmed_selections(strict=False)), [self.selected])
        self.assertIn("Skipping", logs.output[0])
        with mock.patch.object(os_release, "query_registry", return_value=rows), \
                mock.patch.object(os_release, "selection_from_entry", side_effect=view), \
                self.assertRaisesRegex(ValueError, "resolution is incomplete"):
            os_release.resolve_selection(base_os_image=self.reference)
        with mock.patch.object(os_release, "query_registry", return_value=self.entry), \
                mock.patch.object(os_release, "selection_from_entry", side_effect=view):
            self.assertEqual(os_release.resolve_selection("a" * 64, base_os_image=self.reference), self.selected)

    def test_download_timeout_is_configurable_and_bounded(self):
        selected = {"manifest": os_release.canonical({"artifacts": [{"size": "1"}]})}
        with tempfile.TemporaryDirectory() as temp:
            for value, expected in (("1800", 1800), ("7200", 7200)):
                with mock.patch.dict(os.environ, {"TEMENOS_OS_DOWNLOAD_TIMEOUT_SECONDS": value}), \
                        mock.patch.object(os_release, "fetch_carrier", side_effect=RuntimeError("stop before download")) as fetch:
                    with self.assertRaisesRegex(RuntimeError, "stop"):
                        os_release.pull_selected(selected, Path(temp) / "output")
                    self.assertEqual(fetch.call_args.args[-1], expected)
            for invalid in ("0", "-1", "86401", "not-a-number"):
                with mock.patch.dict(os.environ, {"TEMENOS_OS_DOWNLOAD_TIMEOUT_SECONDS": invalid}), \
                        self.assertRaisesRegex(ValueError, "TIMEOUT_SECONDS"):
                    os_release.pull_selected(selected, Path(temp) / "output")

    def test_tag_only_images_are_not_offered_for_packaging(self):
        with self.assertRaisesRegex(ValueError, "digest-pinned"):
            os_release.resolve_selection(base_os_image="registry.example/os:v1")
        selected = {**self.selected, "manifest": '{"publication":{"reference":"registry.example/os:v1"}}'}
        with mock.patch.object(os_release, "confirmed_selections", return_value=iter([selected])):
            result = CliRunner().invoke(cli.app, ["os-release", "list"])
            self.assertEqual(result.exit_code, 0, result.exception)
            self.assertIn("No confirmed, digest-pinned OS releases available.", result.stdout)

    def test_available_os_listing_is_readable_with_json_for_automation(self):
        with mock.patch.object(os_release, "confirmed_selections", side_effect=lambda **kwargs: iter([self.selected])):
            result = CliRunner().invoke(cli.app, ["os-release", "list"])
            self.assertEqual(result.exit_code, 0, result.exception)
            for value in ("OS VERSION", "MODE", "IMAGE", "0.6.0", "raw-sev-snp", self.reference):
                self.assertIn(value, result.stdout)
            self.assertNotIn("os_key", result.stdout)
            result = CliRunner().invoke(os_release.commands, ["list", "--json"])
            self.assertEqual(result.exit_code, 0, result.exception)
            self.assertEqual(json.loads(result.stdout), [{**self.entry, "os_key": "a" * 64, "base_os_image": self.reference}])

    def test_empty_listing_is_explicit(self):
        with mock.patch.object(os_release, "confirmed_selections", return_value=iter([])):
            result = CliRunner().invoke(cli.app, ["os-release", "list"])
            self.assertEqual(result.exit_code, 0, result.exception)
            self.assertIn("No confirmed, digest-pinned OS releases available.", result.stdout)


class RegistrationSelectionTests(unittest.TestCase):
    def test_registration_needs_no_os_key_registry_cli_or_selection_sidecar(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            metadata = {"name": "Test DApp", "description": "", "app_container_image": "registry.example/app:v1",
                        "base_os_image": "registry.example/os@sha256:" + "d" * 64}
            metadata_path = directory / "metadata.json"
            metadata_path.write_text(json.dumps(metadata) + "\n")
            original = metadata_path.read_bytes()
            (directory / "run.d").mkdir()
            for name in ("Caddyfile.template", "docker-compose.yml"):
                (directory / "run.d" / name).write_text("test fixture")
            (directory / "pcrs.json").write_text('{"measurements":{},"application_root_hash":"test"}')
            (directory / "policy.json").write_text('{}')
            # A stale local selector must not dictate the server's OS association.
            (directory / "os-release-selection.json").write_text('{"os_key":"stale"}')
            with mock.patch.dict(os.environ, {"TEMENOS_OS_RELEASE_KEY": "not-an-os-key"}, clear=True), \
                    mock.patch.object(os_release, "query_registry") as query, \
                    mock.patch.object(cli, "post_warden_json_response", return_value=(202, {"job_id": "test-job", "status_url": "/jobs/test-job"})) as post:
                result = CliRunner().invoke(cli.app, [
                    "register-app", "--metadata-path", str(metadata_path), "--app-dir", str(directory),
                    "--endpoint", "https://warden.example/dapps/register", "--tls-mode", "internal",
                    "--address", "203.0.113.10", "--attestation-domain-name", "attestation.example",
                    "--app-key", "f" * 64, "--no-poll",
                ])
            self.assertEqual(result.exit_code, 0, result.exception)
            query.assert_not_called()
            sent = post.call_args.args[1]
            self.assertEqual(sent["metadata_json"].encode(), original)
            for field in ("os_release_key", "os_network", "os_registry_address", "base_os_version"):
                self.assertNotIn(field, sent)
            self.assertEqual(metadata_path.read_bytes(), original)

    def test_registration_no_longer_advertises_an_os_key_flag(self):
        result = CliRunner().invoke(cli.app, ["register-app", "--help"])
        self.assertEqual(result.exit_code, 0, result.exception)
        self.assertNotIn("--os-release-key", result.stdout)


class CarrierTests(unittest.TestCase):
    def carrier(self, member_name="temenos/disk.raw", link=False, wrong_measurement=False):
        disk = b"a small, fake disk for the transport test"
        pcrs = json.dumps({"measurements": {"4": "e" * 64}}).encode()
        content = {"disk.raw": disk, "pcrs.json": pcrs}
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            for name, value in content.items():
                member = tarfile.TarInfo(member_name if name == "disk.raw" else CARRIER_ARTIFACT_PREFIX + name)
                member.size = len(value)
                if link and name == "disk.raw":
                    member.type, member.linkname, member.size = tarfile.SYMTYPE, "/etc/passwd", 0
                archive.addfile(member, None if member.issym() else io.BytesIO(value))
        layer = gzip.compress(data.getvalue(), mtime=0)
        config = b'{"architecture":"amd64","os":"linux"}'
        sha = lambda value: "sha256:" + hashlib.sha256(value).hexdigest()
        image = json.dumps({"schemaVersion": 2, "config": {"digest": sha(config)}, "layers": [
            {"digest": sha(layer), "size": len(layer), "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]}).encode()
        responses = {"https://registry.example/v2/temenos/os/manifests/v1": image,
                     f"https://registry.example/v2/temenos/os/blobs/{sha(config)}": config,
                     f"https://registry.example/v2/temenos/os/blobs/{sha(layer)}": layer}
        manifest = {"publication": {"reference": "registry.example/temenos/os:v1"},
                    "artifacts": [{"name": name, "size": str(len(value)), "sha256": sha(value)[7:]} for name, value in content.items()],
                    "measurements": {"pcr4": ("f" if wrong_measurement else "e") * 64}}
        class Opener:
            def open(self, request, **_):
                return io.BytesIO(responses[request.full_url])
        return manifest, Opener()

    def test_fetches_and_checks_files_without_docker_or_execution(self):
        self.assertEqual("/" + CARRIER_ARTIFACT_PREFIX.rstrip("/"), cli.ACR_OS_ARTIFACT_PREFIX)
        manifest, opener = self.carrier()
        original = os_release.canonical(manifest)
        with tempfile.TemporaryDirectory() as temp, mock.patch("veritee.os_release_carrier.build_opener", return_value=opener):
            report = fetch_carrier(manifest, Path(temp) / "files", 1024 * 1024, 1024 * 1024, 30)
            self.assertEqual(report["validation"], "published_files_checked_not_reproduced")
            self.assertEqual((Path(temp) / "files/disk.raw").read_bytes(), b"a small, fake disk for the transport test")
        self.assertEqual(os_release.canonical(manifest), original)

    def test_rejects_traversal_symlinks_and_measurement_mismatches(self):
        for kwargs in ({"member_name": "../disk.raw"}, {"member_name": "temenos/../disk.raw"},
                       {"member_name": "disk.raw"}, {"link": True}, {"wrong_measurement": True}):
            with self.subTest(kwargs=kwargs):
                manifest, opener = self.carrier(**kwargs)
                with tempfile.TemporaryDirectory() as temp, mock.patch("veritee.os_release_carrier.build_opener", return_value=opener), self.assertRaises(ValueError):
                    fetch_carrier(manifest, Path(temp) / "files", 1024 * 1024, 1024 * 1024, 30)

    def test_limits_download_extraction_and_rejects_changed_disk(self):
        for maximum, extracted, change in ((10, 1024, False), (1024 * 1024, 10, False), (1024 * 1024, 1024, True)):
            manifest, opener = self.carrier()
            if change:
                manifest["artifacts"][0]["sha256"] = "0" * 64
            with tempfile.TemporaryDirectory() as temp, mock.patch("veritee.os_release_carrier.build_opener", return_value=opener), self.assertRaises(ValueError):
                fetch_carrier(manifest, Path(temp) / "files", maximum, extracted, 30)

    def test_refuses_redirects_and_stream_overruns(self):
        with self.assertRaises(ValueError):
            NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://evil.example")
        with self.assertRaises(ValueError):
            BoundedReader(io.BytesIO(b"1234"), 3, float("inf")).read()

    def test_acr_blob_redirects_do_not_receive_registry_credentials(self):
        manifest, original = self.carrier()
        manifest["publication"]["reference"] = "temenostest.azurecr.io/temenos/os:v1"
        external = []
        class Opener:
            def open(self, request, **kwargs):
                url = urlsplit(request.full_url)
                if url.path == "/oauth2/token":
                    return io.BytesIO(b'{"token":"registry-only-token"}')
                if url.hostname == "temenostest.azurecr.io":
                    if not request.get_header("Authorization"):
                        raise HTTPError(request.full_url, 401, "auth", {
                            "WWW-Authenticate": 'Bearer realm="https://temenostest.azurecr.io/oauth2/token"',
                        }, None)
                    if "/blobs/" in url.path:
                        raise RegistryRedirect("https://atemanaged90.blob.core.windows.net/blobs/" + url.path.rsplit("/", 1)[1] + "?sig=test-only")
                    return original.open(Request(request.full_url.replace("temenostest.azurecr.io", "registry.example")))
                external.append(request.get_header("Authorization"))
                return original.open(Request("https://registry.example/v2/temenos/os/blobs/" + url.path.rsplit("/", 1)[1]))
        with tempfile.TemporaryDirectory() as temp, mock.patch("veritee.os_release_carrier.build_opener", return_value=Opener()):
            report = fetch_carrier(manifest, Path(temp) / "files", 1024 * 1024, 1024 * 1024, 30)
        self.assertEqual(external, [None, None])
        self.assertEqual(report["validation"], "published_files_checked_not_reproduced")

    def test_redirect_allowlist_requires_acr_and_azure_https_storage(self):
        for location in ("https://atemanaged90.blob.core.windows.net/a?sig=test-only",
                         "https://temenostest.westus.data.azurecr.io/a"):
            self.assertTrue(acr_blob_redirect("temenostest.azurecr.io", location))
        for location in ("http://atemanaged90.blob.core.windows.net/a", "https://evil.example/a",
                         "https://atemanaged90.blob.core.windows.net.evil.example/a",
                         "https://user:password@atemanaged90.blob.core.windows.net/a",
                         "https://atemanaged90.blob.core.windows.net:8443/a",
                         "https://atemanaged90.blob.core.windows.net/a#fragment",
                         "https://other.westus.data.azurecr.io/a"):
            with self.subTest(location=location):
                self.assertFalse(acr_blob_redirect("temenostest.azurecr.io", location))
        self.assertFalse(acr_blob_redirect("registry.example", "https://atemanaged90.blob.core.windows.net/a"))

    def test_redirect_loops_and_manifest_redirects_are_rejected(self):
        for redirect_manifest in (False, True):
            manifest, original = self.carrier()
            manifest["publication"]["reference"] = "temenostest.azurecr.io/temenos/os:v1"
            class Opener:
                def open(self, request, **kwargs):
                    if not redirect_manifest and "/manifests/" in request.full_url:
                        return original.open(Request(request.full_url.replace("temenostest.azurecr.io", "registry.example")))
                    raise RegistryRedirect("https://atemanaged90.blob.core.windows.net/a")
            with tempfile.TemporaryDirectory() as temp, mock.patch("veritee.os_release_carrier.build_opener", return_value=Opener()), self.assertRaisesRegex(ValueError, "redirect"):
                fetch_carrier(manifest, Path(temp) / "files", 1024 * 1024, 1024 * 1024, 30)

    def test_token_endpoint_cannot_opt_into_blob_redirects(self):
        manifest, _ = self.carrier()
        manifest["publication"]["reference"] = "temenostest.azurecr.io/temenos/os:v1"
        class Opener:
            def open(self, request, **kwargs):
                if "/manifests/" in request.full_url:
                    raise HTTPError(request.full_url, 401, "auth", {
                        "WWW-Authenticate": 'Bearer realm="https://temenostest.azurecr.io/v2/temenos/os/blobs/sha256:fake"',
                    }, None)
                raise RegistryRedirect("https://atemanaged90.blob.core.windows.net/a")
        with tempfile.TemporaryDirectory() as temp, mock.patch("veritee.os_release_carrier.build_opener", return_value=Opener()), self.assertRaisesRegex(ValueError, "redirect"):
            fetch_carrier(manifest, Path(temp) / "files", 1024 * 1024, 1024 * 1024, 30)

    def test_direct_carrier_connections_pin_only_public_addresses(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "168.63.129.16", "::1", "::ffff:127.0.0.1"):
            with self.subTest(address=address), mock.patch("veritee.os_release_carrier.socket.getaddrinfo", return_value=[(0, 0, 0, "", (address, 443))]), self.assertRaisesRegex(ValueError, "public"):
                public_address("atemanaged90.blob.core.windows.net", 443)
        handler = PublicHTTPSHandler()
        request = Request("https://atemanaged90.blob.core.windows.net/a")
        with mock.patch("veritee.os_release_carrier.public_address", return_value="8.8.8.8"), \
                mock.patch("veritee.os_release_carrier.ResolvedHttpsConnection") as connection, \
                mock.patch.object(handler, "do_open", side_effect=lambda factory, req, **kwargs: factory("atemanaged90.blob.core.windows.net", **kwargs)):
            handler.https_open(request)
        connection.assert_called_once_with("atemanaged90.blob.core.windows.net", "8.8.8.8", context=handler._context)

    def test_configured_proxy_keeps_dns_resolution_in_the_proxy(self):
        request = Request("https://atemanaged90.blob.core.windows.net/a")
        request.set_proxy("127.0.0.1:18081", "https")
        with mock.patch("veritee.os_release_carrier.public_address") as dns, \
                mock.patch.object(HTTPSHandler, "https_open", return_value="proxied"):
            self.assertEqual(PublicHTTPSHandler().https_open(request), "proxied")
        dns.assert_not_called()

    def test_rejects_large_extension_headers_before_tarfile_allocates_them(self):
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_SPARSE):
            member = tarfile.TarInfo("metadata")
            member.type, member.size = kind, 1024 * 1024
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                CarrierTarInfo.frombuf(member.tobuf(), "utf-8", "strict")


if __name__ == "__main__":
    unittest.main()
