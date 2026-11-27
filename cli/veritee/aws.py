"""Build records for the AWS bare-attestation prototype."""
from pathlib import Path

from . import build, os_release


OUTPUT_DIR = Path('local-aws-snp')


def _inputs(repository):
    files = [repository / path for path in (
        'build/Dockerfile', 'build/aws-snp-os.sh', 'build/aws-snpguest-lock.patch',
        'update_systemd.sh', 'veritee-os/config-aws.yaml',
        'veritee-os/bootstrap/ca-certificates_20250419_all.deb',
    )]
    for directory in ('veritee-os/mkosi/aws', 'veritee-os/render_template'):
        files.extend(p for p in (repository / directory).rglob('*')
                     if p.is_file() and '__pycache__' not in p.parts and not p.name.endswith('.pyc'))
    return {str(p.relative_to(repository)): os_release.digest(p.read_bytes()) for p in sorted(files)}


def build_image(repository, *, verbose, run):
    repository = Path(repository).resolve()
    output = repository / OUTPUT_DIR
    if any((output / name).exists() for name in ('pcrs.json', 'os-build.json', 'policy.json')):
        raise ValueError('AWS output contains Azure measurement/approval files; use a clean local-aws-snp directory')
    source = os_release.source_identity(repository)
    inputs = _inputs(repository)
    command = build.base_command('config-aws.yaml', 'raw-sev-snp', False, provider='aws')
    transcript = run(command, verbose=verbose, cwd=repository)
    if os_release.source_identity(repository) != source or _inputs(repository) != inputs:
        raise ValueError('Source changed during AWS image build')
    record = {
        'version': 1,
        'provider': 'aws',
        'purpose': 'bare_attestation_prototype',
        'source': source,
        'command': command,
        'attestation_mode': 'raw-sev-snp',
        'attestation_device': '/dev/sev-guest',
        'vmpl': 0,
        'inputs': inputs,
        'recipe': {
            'docker_target': 'aws-snp-os-builder',
            'dockerfile_sha256': os_release.digest((repository / 'build/Dockerfile').read_bytes()),
            'profile_sha256': os_release.digest((repository / 'veritee-os/config-aws.yaml').read_bytes()),
        },
        'artifacts': [os_release.file_descriptor(output / name) for name in ('disk.raw', 'disk.manifest')],
    }
    # This is a build record, not an Azure OS approval or a live SNP measurement.
    (output / 'aws-build.json').write_text(os_release.canonical(record), encoding='utf-8')
    print(f'AWS bare-attestation image: {output / "disk.raw"}')
    print('Build record: ' + str(output / 'aws-build.json'))
    return transcript
