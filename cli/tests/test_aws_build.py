import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from typer.testing import CliRunner

from veritee import aws, build, cli, os_release


ROOT = Path(__file__).resolve().parents[2]
SOURCE = {'commit': 'a' * 40, 'tree': 'b' * 40, 'modified': True}


class AwsBuildTests(unittest.TestCase):
    def test_cli_routes_aws_without_generating_azure_measurements(self):
        with mock.patch.object(aws, 'build_image', return_value='built') as aws_build, \
                mock.patch.object(cli, 'write_pcr_measurements') as pcrs, \
                mock.patch.object(cli, 'write_os_security_files') as policy:
            result = CliRunner().invoke(cli.app, ['build-base-os-image', '--provider', 'aws'])
        self.assertEqual(result.exit_code, 0, result.exception)
        aws_build.assert_called_once_with(Path.cwd(), verbose=False, run=cli.run_native_build)
        pcrs.assert_not_called()
        policy.assert_not_called()

    def test_incompatible_options_fail_before_starting_any_builder(self):
        for flags in (['--azuresnp'], ['--attestation-mode', 'maa'], ['--debug'], ['--allow-unbound-attestation']):
            with self.subTest(flags=flags), mock.patch.object(aws, 'build_image') as aws_build, \
                    mock.patch.object(cli, 'run_native_build') as native:
                result = CliRunner().invoke(cli.app, ['build-base-os-image', '--provider', 'aws', *flags])
                self.assertNotEqual(result.exit_code, 0)
                aws_build.assert_not_called()
                native.assert_not_called()

    def test_backend_rejects_cross_provider_profiles_before_docker(self):
        cases = [('aws', 'config-azure.yaml', 'raw-sev-snp', False),
                 ('aws', 'config-aws.yaml', 'maa', False),
                 ('aws', 'config-aws.yaml', 'raw-sev-snp', True),
                 ('azure', 'config-aws.yaml', 'raw-sev-snp', False)]
        for provider, profile, mode, unbound in cases:
            with self.subTest(provider=provider, profile=profile, mode=mode, unbound=unbound), \
                    mock.patch.object(build, 'ensure_builder') as builder:
                command = build.base_command(profile, mode, unbound, provider=provider)
                with self.assertRaises(build.BuildError):
                    build.run(command, repo=ROOT)
                builder.assert_not_called()

    def _repository(self, directory):
        repo = Path(directory)
        for filename in ('build/Dockerfile', 'build/aws-snp-os.sh', 'build/aws-snpguest-lock.patch',
                         'update_systemd.sh', 'veritee-os/config-aws.yaml',
                         'veritee-os/bootstrap/ca-certificates_20250419_all.deb'):
            p = repo / filename
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b'fixture\n')
        return repo

    def test_build_record_retains_actual_inputs_and_separate_aws_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory)
            def execute(command, **kwargs):
                self.assertIn('aws-snp-base', command)
                self.assertIn('config-aws.yaml', command)
                output = repo / aws.OUTPUT_DIR
                output.mkdir()
                (output / 'disk.raw').write_bytes(b'AWS disk')
                (output / 'disk.manifest').write_text('{"packages": []}')
                return 'built'
            with mock.patch.object(os_release, 'source_identity', return_value=SOURCE):
                aws.build_image(repo, verbose=False, run=execute)
            output = repo / aws.OUTPUT_DIR
            record = json.loads((output / 'aws-build.json').read_text())
            self.assertEqual(record['provider'], 'aws')
            self.assertEqual(record['source'], SOURCE)
            self.assertEqual(record['attestation_device'], '/dev/sev-guest')
            self.assertEqual(record['vmpl'], 0)
            self.assertEqual(record['inputs']['build/aws-snp-os.sh'], os_release.digest(b'fixture\n'))
            self.assertEqual(record['artifacts'][0]['sha256'], os_release.digest(b'AWS disk'))
            self.assertFalse((output / 'pcrs.json').exists())
            self.assertFalse((output / 'os-build.json').exists())
            self.assertFalse((repo / 'local-base-os').exists())

    def test_aws_build_rejects_input_drift_even_when_git_was_already_dirty(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory)
            def change_source(*args, **kwargs):
                (repo / 'veritee-os/config-aws.yaml').write_text('changed during build')
            with mock.patch.object(os_release, 'source_identity', return_value=SOURCE):
                with self.assertRaisesRegex(ValueError, 'Source changed'):
                    aws.build_image(repo, verbose=False, run=change_source)

    def test_existing_azure_measurements_in_aws_output_fail_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = repo / aws.OUTPUT_DIR
            output.mkdir()
            (output / 'pcrs.json').write_text('{"measurements": {"4": "old Azure value"}}')
            run = mock.Mock()
            with self.assertRaisesRegex(ValueError, 'Azure measurement'):
                aws.build_image(repo, verbose=False, run=run)
            run.assert_not_called()

    def test_guest_collector_passes_exact_client_data_to_vmpl_zero_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / 'request.bin'
            request.write_bytes(bytes(range(64)))
            tool = root / 'snpguest'
            tool.write_text('''#!/usr/bin/env python3
import json, pathlib, sys
with pathlib.Path(__file__).with_name('calls.jsonl').open('a') as f:
    f.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1]=='report':
    pathlib.Path(sys.argv[2]).write_bytes(pathlib.Path(sys.argv[3]).read_bytes())
elif sys.argv[1]=='certificates':
    pathlib.Path(sys.argv[3]).mkdir()
else:
    print('fixture report')
''')
            tool.chmod(0o755)
            source = ROOT / 'veritee-os/mkosi/aws/mkosi.extra/usr/local/bin/veritee-snp-report'
            # Substitute only the device check in this test; there is no SNP hardware here.
            collector = root / 'collector'
            collector.write_text(source.read_text().replace('/dev/sev-guest', '/dev/null'))
            env = {**os.environ, 'PATH': str(root) + ':' + os.environ['PATH']}
            output = root / 'evidence'
            result = subprocess.run(['bash', str(collector), str(request), str(output)], env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((output / 'report-data.bin').read_bytes(), request.read_bytes())
            calls = [json.loads(line) for line in (root / 'calls.jsonl').read_text().splitlines()]
            self.assertEqual(calls[0], ['report', str(output / 'report.bin'), str(output / 'report-data.bin'), '--vmpl', '0'])
            self.assertNotIn('--random', sum(calls, []))
            self.assertNotIn('--platform', sum(calls, []))
            before = (output / 'report.bin').read_bytes()
            repeated = subprocess.run(['bash', str(collector), str(request), str(output)], env=env,
                                      capture_output=True, text=True)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual((output / 'report.bin').read_bytes(), before)
            for size in (63, 65):
                request.write_bytes(b'x' * size)
                invalid = subprocess.run(['bash', str(collector), str(request), str(root / str(size))],
                                         env=env, capture_output=True, text=True)
                self.assertNotEqual(invalid.returncode, 0)
                self.assertFalse((root / str(size)).exists())


if __name__ == '__main__':
    unittest.main()
