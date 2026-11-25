"""Containerized Azure SNP builds using Docker, mkosi and systemd-repart."""
from contextlib import contextmanager
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid


PROXY_ENV = ('HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy')
BUILDKIT_IMAGE = 'moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8'


class BuildError(RuntimeError):
    pass


def base_command(os_config, attestation_mode, allow_unbound_attestation):
    return ['python3', '-m', 'veritee.build', 'azure-snp-base', '--os-config', os_config,
            '--attestation-mode', attestation_mode,
            '--allow-unbound-attestation', str(allow_unbound_attestation).lower()]


def application_command(action, *, app_dir, image, guest_image, tls_mode, persist_size=None):
    command = ['python3', '-m', 'veritee.build', action, '--app-dir', app_dir, '--image', image,
               '--guest-image', guest_image, '--tls-mode', tls_mode]
    if persist_size is not None:
        command += ['--persist-size', persist_size]
    return command


def check_inputs(repo, action, app_dir=None):
    repo = Path(repo).resolve()
    required = ['build/Dockerfile', 'update_systemd.sh', 'veritee-os/docker-apt/verify.py']
    if action == 'azure-snp-base':
        required += ['build/azure-snp-os.sh', 'veritee-os/config-azure.yaml',
                     'veritee-os/config-azure.debug.yaml', 'server/azure_attestation_server/Cargo.lock',
                     'server/egress_proxy/Cargo.lock', 'cli/veritee/proxy_policy.py']
    elif action in ('app', 'extend'):
        required += ['build/app-disk.sh', 'build/app-images.conf', 'veritee-os/app-disk/run.d/main', 'veritee-os/app-disk/setup.d/main',
                     'veritee-os/app-disk/10-app.conf', 'veritee-os/app-disk/11-app-verity.conf']
        if app_dir is None:
            raise BuildError('Application source is required')
        app = Path(app_dir)
        if not app.is_absolute():
            app = repo / app
        required += [app / 'metadata.json', app / 'run.d/docker-compose.yml', app / 'run.d/Caddyfile.template']
        if action == 'extend':
            required += ['local-base-os/disk.raw']
    else:
        raise BuildError('Unsupported build action')
    for name in required:
        path = Path(name)
        path = path if path.is_absolute() else repo / path
        if not path.is_file():
            raise BuildError(f'Missing build input: {path}')


def _command(command, *, cwd, env, verbose):
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            stdout=None if verbose else subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise BuildError(f'{command[0]} {command[1]} failed ({result.returncode})\n{result.stdout or ""}')
    return result.stdout or ''


def ensure_builder(repo, environment, verbose):
    """Keep a pinned builder/cache; never change the user's selected builder.

    On Warden both BuildKit and the image-export container join the platform's
    builder network. Its proxy environment applies to registry fetches and RUN
    steps. A missing or unusable configured network is an error, not a fallback.
    """
    name = environment.get('VERITEE_BUILD_BUILDER', 'veritee-build')
    network = environment.get('VERITEE_BUILD_NETWORK', 'bridge')
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,47}', name):
        raise BuildError('Invalid VERITEE_BUILD_BUILDER')
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', network) or network in ('host', 'none'):
        raise BuildError('VERITEE_BUILD_NETWORK must name a Docker bridge network')
    # Serialize only first-use/bootstrap, not independent build requests.
    lock_dir = Path.home() / '.cache/veritee/builders'
    lock_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    lock = lock_dir / (name + '.lock')
    with lock.open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        existing = subprocess.run(['docker', 'buildx', 'inspect', name], cwd=repo,
                                  env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if existing.returncode:
            command = ['docker', 'buildx', 'create', '--name', name, '--driver', 'docker-container',
                       '--driver-opt', 'image=' + BUILDKIT_IMAGE,
                       '--driver-opt', 'network=' + network]
            for key in PROXY_ENV:
                if environment.get(key):
                    command += ['--driver-opt', 'env.' + key + '=' + environment[key]]
            _command(command, cwd=repo, env=environment, verbose=verbose)
        _command(['docker', 'buildx', 'inspect', '--bootstrap', name], cwd=repo,
                 env=environment, verbose=verbose)
        details = json.loads(_command(['docker', 'inspect', 'buildx_buildkit_' + name + '0'],
                                      cwd=repo, env=environment, verbose=False))[0]
        actual_env = dict(item.split('=', 1) for item in details['Config']['Env'] if '=' in item)
        if (details['Config']['Image'] != BUILDKIT_IMAGE or details['HostConfig']['NetworkMode'] != network or
                any(actual_env.get(key, '') != environment.get(key, '') for key in PROXY_ENV)):
            raise BuildError('Existing Veritee builder has different image/network/proxy settings; '
                             'select a different VERITEE_BUILD_BUILDER')
    return name, network


@contextmanager
def registry_config(registry='', token=''):
    """Credentials are mounted at runtime, never put in build arguments/layers."""
    auths = {}
    if registry:
        if not token:
            raise BuildError('ACR authentication token is missing')
        auths[registry] = {'auth': base64.b64encode(('00000000-0000-0000-0000-000000000000:' + token).encode()).decode()}
    user, password = os.getenv('DOCKERHUB_USER', ''), os.getenv('DOCKERHUB_TOKEN', '')
    if bool(user) != bool(password):
        raise BuildError('Set both DOCKERHUB_USER and DOCKERHUB_TOKEN, or neither')
    if user:
        auths['https://index.docker.io/v1/'] = {'auth': base64.b64encode((user + ':' + password).encode()).decode()}
    with tempfile.TemporaryDirectory(prefix='veritee-registry-') as directory:
        target = Path(directory) / 'config.json'
        target.write_text(json.dumps({'auths': auths}))
        target.chmod(0o600)
        yield Path(directory)


def run(command, *, repo, verbose=False, registry='', token=''):
    """Run only the fixed recipes represented by CLI-generated commands."""
    import argparse
    parser = argparse.ArgumentParser(prog='veritee-build')
    parser.add_argument('action', choices=['azure-snp-base', 'app', 'extend'])
    parser.add_argument('--os-config', choices=['config-azure.yaml', 'config-azure.debug.yaml'], default='config-azure.yaml')
    parser.add_argument('--attestation-mode', choices=['maa', 'raw-sev-snp'], default='maa')
    parser.add_argument('--allow-unbound-attestation', choices=['true', 'false'], default='false')
    parser.add_argument('--app-dir')
    parser.add_argument('--image')
    parser.add_argument('--guest-image')
    parser.add_argument('--tls-mode', choices=['internal', 'azure_vault'])
    parser.add_argument('--persist-size', default='2G')
    if command[:3] != ['python3', '-m', 'veritee.build']:
        raise BuildError('Unsupported build command')
    args = parser.parse_args(command[3:])
    repo = Path(repo).resolve()
    check_inputs(repo, args.action, args.app_dir)
    if args.allow_unbound_attestation == 'true' and args.os_config != 'config-azure.debug.yaml':
        raise BuildError('Unbound attestation requires the debug profile')
    environment = dict(os.environ)
    # Warden's build proxy must not change the Warden/wallet process's own
    # transport. Apply its dedicated settings only to build subprocesses.
    if environment.get('VERITEE_BUILD_HTTPS_PROXY'):
        for key in ('HTTPS_PROXY', 'https_proxy'):
            environment[key] = environment['VERITEE_BUILD_HTTPS_PROXY']
        for key in ('HTTP_PROXY', 'http_proxy'):
            environment.pop(key, None)
    if 'VERITEE_BUILD_NO_PROXY' in environment:
        for key in ('NO_PROXY', 'no_proxy'):
            environment[key] = environment['VERITEE_BUILD_NO_PROXY']
    builder, network = ensure_builder(repo, environment, verbose)
    target = 'azure-snp-os-builder' if args.action == 'azure-snp-base' else 'app-disk-builder'
    # Names belong to this invocation. Concurrent callers cannot retag or
    # remove one another's builder images and runtime containers.
    identifier = uuid.uuid4().hex
    image = 'veritee-build:' + identifier
    container = 'veritee-build-' + identifier
    build_command = ['docker', 'buildx', 'build', '--builder', builder, '--load', '--progress', 'plain',
                     '--file', str(repo / 'build/Dockerfile'),
                     '--target', target, '--platform', 'linux/amd64', '--tag', image]
    for key in PROXY_ENV:
        if environment.get(key):
            build_command += ['--build-arg', key]
    if target == 'azure-snp-os-builder':
        build_command += ['--build-arg', 'ATTESTATION_MODE=' + args.attestation_mode,
                          '--build-arg', 'ALLOW_UNBOUND_ATTESTATION=' + args.allow_unbound_attestation]
    build_command += [str(repo)]
    output = repo / ('local' if args.action == 'app' else 'local-base-os' if args.action == 'azure-snp-base' else 'local-azure-snp')
    output.mkdir(parents=True, exist_ok=True)
    # Docker may run on Warden's host while the CLI runs inside its container.
    # Stage a complete job under shared storage and translate only that root.
    work_root = Path(environment.get('VERITEE_BUILD_WORK_ROOT', str(repo))).resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    host_root = Path(environment.get('VERITEE_BUILD_HOST_WORK_ROOT', str(work_root)))
    if not host_root.is_absolute():
        raise BuildError('VERITEE_BUILD_HOST_WORK_ROOT must be absolute')
    transcript = ''
    try:
        transcript += _command(build_command, cwd=repo, env=environment, verbose=verbose)
        with registry_config(registry, token) as credentials, \
                tempfile.TemporaryDirectory(prefix='.veritee-build-', dir=work_root) as directory:
            workspace = Path(directory)
            host_workspace = host_root / workspace.name
            (workspace / 'out').mkdir()
            run_command = ['docker', 'run', '--rm', '--privileged', '--name', container,
                           '--network', network,
                           '--mount', f'type=bind,source={host_workspace},target=/workdir',
                           '--env', 'OUTPUT_UID=' + str(os.getuid()), '--env', 'OUTPUT_GID=' + str(os.getgid())]
            for key in PROXY_ENV:
                if environment.get(key):
                    run_command += ['--env', key]
            if args.action == 'azure-snp-base':
                run_command += ['--env', 'OS_CONFIG=' + args.os_config,
                                '--env', 'ATTESTATION_MODE=' + args.attestation_mode,
                                '--env', 'ALLOW_UNBOUND_ATTESTATION=' + args.allow_unbound_attestation]
            else:
                app = Path(args.app_dir)
                app = (app if app.is_absolute() else repo / app).resolve()
                (workspace / 'inputs').mkdir()
                shutil.copytree(app, workspace / 'inputs/project', symlinks=True)
                shutil.copytree(credentials, workspace / 'docker-auth')
                run_command += ['--env', 'BUILD_ACTION=' + args.action, '--env', 'USER_DOCKER=' + args.image,
                                '--env', 'GUEST_ATTESTATION_IMAGE=' + args.guest_image,
                                '--env', 'VERITEE_TLS_MODE=' + args.tls_mode,
                                '--env', 'PERSIST_SIZE=' + args.persist_size]
                if args.action == 'extend':
                    _command(['cp', '--sparse=always', str(repo / 'local-base-os/disk.raw'),
                              str(workspace / 'inputs/os.raw')], cwd=repo, env=environment, verbose=False)
            run_command += [image]
            transcript += _command(run_command, cwd=repo, env=environment, verbose=verbose)
            for artifact in (workspace / 'out').iterdir():
                _command(['cp', '--sparse=always', str(artifact), str(output / artifact.name)],
                         cwd=repo, env=environment, verbose=False)
    finally:
        # Only this invocation's objects are eligible for cleanup. BuildKit's
        # shared cache remains available; no global image/cache pruning occurs.
        subprocess.run(['docker', 'rm', '--force', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return transcript


if __name__ == '__main__':
    import sys
    run(['python3', '-m', 'veritee.build', *sys.argv[1:]], repo=Path.cwd(), verbose=True)
