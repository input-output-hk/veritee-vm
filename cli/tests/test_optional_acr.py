import json
import os
from contextlib import ExitStack, nullcontext
from pathlib import Path
import unittest
from unittest import mock

from typer.testing import CliRunner
from veritee import cli


class OptionalAcrTests(unittest.TestCase):
    def test_public_inputs_do_not_authenticate_the_publish_registry(self):
        for image in ['docker.io/example/app@sha256:' + 'a' * 64, 'example/app:latest', 'ghcr.io/example/app:v1']:
            with self.subTest(image=image), mock.patch.dict(os.environ, {cli.ACR_NAME_ENV_VAR: 'publishregistry'}, clear=True), \
                    mock.patch.object(cli, 'get_acr_access_token') as token:
                self.assertEqual(cli.application_image_pull_auth(image), ('', ''))
                token.assert_not_called()

    def test_private_input_uses_its_own_registry(self):
        with mock.patch.dict(os.environ, {cli.ACR_NAME_ENV_VAR: 'publishregistry'}, clear=True), \
                mock.patch.object(cli, 'get_acr_access_token', return_value='private-token') as token:
            self.assertEqual(cli.application_image_pull_auth('inputregistry.azurecr.io/app@sha256:' + 'a' * 64),
                             ('inputregistry.azurecr.io', 'private-token'))
            token.assert_called_once_with('inputregistry')

    def test_push_requires_configuration_before_os_lookup(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(cli, 'load_app_source_metadata', return_value={'name': 'test'}), \
                mock.patch.object(cli.os_release, 'resolve_selection') as lookup:
            result = CliRunner().invoke(cli.app, ['package-dapp-deployable-vm-image', '--push', '--tls-mode', 'internal'])
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn(cli.ACR_NAME_ENV_VAR, str(result.exception))
            lookup.assert_not_called()

    def test_package_defaults_to_local_and_push_is_explicit(self):
        for options, should_push in [([], False), (['--no-push'], False), (['--push'], True)]:
            with self.subTest(options=options), CliRunner().isolated_filesystem(), ExitStack() as stack:
                metadata = {'name': 'test', 'description': 'test', 'base_os_image': 'registry.example/os@sha256:' + 'a' * 64,
                            'app_container_image': 'docker.io/example/app@sha256:' + 'b' * 64}
                selected = {'entry': {'pcr4': 'c' * 64},
                            'manifest': json.dumps({'publication': {'reference': metadata['base_os_image']}})}
                output = Path(cli.DAPP_OUTPUT_DIR)
                output.mkdir()
                stack.enter_context(mock.patch.dict(os.environ, {cli.ACR_NAME_ENV_VAR: 'publishregistry'} if should_push else {}, clear=True))
                for name, value in [('load_app_source_metadata', metadata), ('resolve_persist_size', '2G'),
                                    ('resolve_packaging_tls_keyvault_name', None), ('write_application_root_hash', 'd' * 64),
                                    ('load_pcr4_measurement', 'c' * 64), ('resolve_policy_template', Path('policy.template.json'))]:
                    stack.enter_context(mock.patch.object(cli, name, return_value=value))
                stack.enter_context(mock.patch.object(cli.os_release, 'resolve_selection', return_value=selected))
                stack.enter_context(mock.patch.object(cli.os_release, 'pull_selected'))
                source_record = {"files": {"metadata.json": "e" * 64}, "directories": []}
                stack.enter_context(mock.patch.object(cli, 'app_build_context', return_value=nullcontext(Path('source'))))
                stack.enter_context(mock.patch.object(cli, 'local_registration_profile', return_value={}))
                stack.enter_context(mock.patch.object(cli, 'validate_dapp_packaging', return_value={
                    'profile': {}, 'source': source_record, 'shipped_metadata': metadata}))
                stack.enter_context(mock.patch.object(cli.pack_validation, 'source_tree', return_value=source_record))
                stack.enter_context(mock.patch.object(cli.pack_validation, 'file_hash', return_value='e' * 64))
                stack.enter_context(mock.patch.object(cli.pack_validation, 'make_snapshot', return_value={}))
                stack.enter_context(mock.patch.object(cli, 'prepared_app_build_source', return_value=nullcontext(('source', metadata))))
                for name in ['preflight_check_build_inputs', 'run_native_build',
                             'write_pcr_measurements', 'write_os_security_files', 'write_tls_mode',
                             'resize_azure_disk', 'ensure_publish_disk_space']:
                    stack.enter_context(mock.patch.object(cli, name))
                token = stack.enter_context(mock.patch.object(cli, 'get_acr_access_token'))
                publish = stack.enter_context(mock.patch.object(cli, 'push_scratch_artifact_image'))
                result = CliRunner().invoke(cli.app, ['package-dapp-deployable-vm-image', '--tls-mode', 'internal', *options])
                self.assertEqual(result.exit_code, 0, result.exception)
                token.assert_not_called()
                self.assertEqual(publish.call_count, int(should_push))
                if should_push:
                    self.assertEqual(publish.call_args.args[0], 'publishregistry')


if __name__ == '__main__':
    unittest.main()
