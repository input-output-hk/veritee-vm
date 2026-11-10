import glob
import http.client
import json
import os
import ssl
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from inspect import signature
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, FrozenSet, Iterator, List, Optional, Set, Annotated
from urllib.parse import urlencode, urljoin, urlparse
import base64
import binascii
import hashlib
import logging
from importlib.metadata import version

import requests
import typer


from veritee.outbound import (
    OutboundPolicyError,
    prepare_shipped_metadata,
    validate_compose_egress_boundary,
)
from veritee.proxy_policy import validate_proxy_allowed_paths
from veritee.http_helpers import ResolvedHttpsConnection

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

class IsoFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return (
            datetime.fromtimestamp(record.created)
            .astimezone()
            .replace(microsecond=0)
            .isoformat()
        )

def configure_logging() -> logging.Logger:
    handler = logging.StreamHandler()
    handler.setFormatter(
        IsoFormatter("veritee       | %(asctime)s %(levelname)-5s %(message)s")
    )

    logger = logging.getLogger("veritee")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if os.getenv("VERITEE_DEBUG") else logging.INFO)
    logger.propagate = False

    return logger

log = configure_logging()

COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[32m"
COLOR_GRAY = "\033[90m"
COLOR_YELLOW = "\033[33m"


CLI_VERSION = version("veritee")
DEFAULT_AZURE_VM_SIZE = "Standard_DC4ads_v5"


class AttestationMode(str, Enum):
    MAA = "maa"
    RAW_SEV_SNP = "raw-sev-snp"


def color_text(value: str, color: str) -> str:
    if os.getenv("NO_COLOR"):
        return value

    return f"{color}{value}{COLOR_RESET}"


class DeployerException(Exception):
    """Generic Deployer exception"""
    def __init__(self, message: str, *args: object) -> None:
        self.message = message
        super().__init__(self.message, *args)

class DeployerTfUnavailable(DeployerException):
    """Terraform is not available"""
    def __init__(self) -> None:
        err = "Terraform CLI was not found in PATH. Follow the instructions at [underline]https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli[/]."
        super().__init__(err)

class DeployerSubProcessException(DeployerException):
    """Subprocess failure (non zero return code)"""
    def __init__(self, command: str, retcode: int, stdout: str, stderr: str) -> None:
        self.__command = command
        self.__retcode = retcode
        self.__stdout = stdout
        self.__stderr = stderr
        err = f"Command `{self.__command}` terminated with non-zero return code: {self.__retcode}\nstdout: {self.__stdout}\nstderr: {self.__stderr}"
        super().__init__(err)

class Deployer:
    """Python API of the Deployer.
    
    This class contains methods that cover the main steps for launching Deployer runners.
    These methods rely on terraform to deploy runners.
    """

    __tf_available: Optional[bool] = None

    @classmethod
    def __assert_tf_available(cls) -> None:
        """Private method: check if terraform is installed"""
        if cls.__tf_available is None:
            # Check if the terraform binary is installed
            try:
                cls.__run_subprocess(["terraform", "--version"])
            except FileNotFoundError:
                raise DeployerTfUnavailable()
            except DeployerSubProcessException:
                raise DeployerTfUnavailable()

    @classmethod
    def assert_available(cls) -> None:
        """Check that the terraform binary is installed, without doing any work."""
        cls.__assert_tf_available()

    @classmethod
    def __tf_init(cls, work_dir: Path) -> None:
        """Private method: run terraform init as a subprocess

        Args:
            work_dir (Path): Working directory
        """
        cls.__assert_tf_available()

        #if not (work_dir / ".terraform").exists():
        cls.__run_subprocess(["terraform", "init"], cwd=work_dir)

    @classmethod
    def __tf_apply(cls, work_dir: Path, tf_vars: Optional[dict] = None) -> None:
        """Private method: run terraform apply as a subprocess

        Args:
            work_dir (Path): Working directory
            tf_vars (dict): Values for the terraform variables as a dict
        """
        cls.__assert_tf_available()

        args = ["terraform", "apply", "-auto-approve"]
        for k, v in (tf_vars or {}).items():
            args += ["--var", f"{k}={v}"]

        env = os.environ.copy()
        env["GODEBUG"] = "netdns=go+2"
        if os.getenv("VERITEE_DEBUG"):
            env["TF_LOG"] = "DEBUG"
            env["TF_LOG_PATH"] = str(work_dir / "terraform-debug.log")

        cls.__run_subprocess(args, cwd=work_dir, env=env)

    @classmethod
    def __run_subprocess(
        self,
        command: List[str],
        cwd: Optional[Path] = None,
        assert_returncode: bool = True,
        string_flag = True,
        env: Optional[dict] = None,
        stdin: Optional[int] = None,
    ) -> str:
        """Private method: run a command as a subprocess and return its stdout as a string
        
        Args:
            command (List[str]): Command to run in a subprocess
            cwd (Path, optional): Working directory of the subprocess
            text (bool, default = False): Text mode
            verbose (bool, default = False): Whether to print info about the subprocess
            assert_returncode (bool, default = True): Raise an error if the return code is non zero
        
        Returns:
            str
        """
        human_readable_command = " ".join(command)
        
        if cwd is None:
            cwd = Path.cwd()

        try:
            res = subprocess.run(
                command,
                cwd=str(cwd.absolute()),
                stdin=stdin,
                capture_output=True,
                text=string_flag,
                env=env,
            )
        except KeyboardInterrupt:
            exit(1)

        if assert_returncode and res.returncode != 0:
            raise DeployerSubProcessException(
                human_readable_command,
                res.returncode,
                res.stdout,
                res.stderr
            )

        return res.stdout

    @classmethod
    def init(cls, work_dir: Path, cloud: str) -> None:
        """Initailize the Deployer

        - Check dependencies
        - Create workding directory
        - Install runner code

        Args:
            work_dir (Path): Working directory
        """
        cls.__assert_tf_available()

        work_dir.mkdir(parents=True, exist_ok=True)

        deploy_folder = repo_root_from_cwd() / "cli" / cloud
        shutil.copytree(deploy_folder, work_dir, dirs_exist_ok=True)
        work_dir.chmod(0o700)

    @classmethod
    def launch_runner(cls, work_dir: Path, tf_vars: dict) -> dict:
        """Launch runner

        Take terraform configuration from working directory

        Args:
            work_dir (Path): Working directory
        """
        Deployer.__tf_init(work_dir)
        
        Deployer.__tf_apply(work_dir, tf_vars)

        output_result = subprocess.run(
            ["terraform", "output", "-json"],
            cwd=str(work_dir.absolute()),
            capture_output=True,
            text=True,
        )
        if output_result.returncode != 0:
            raise DeployerSubProcessException(
                "terraform output -json",
                output_result.returncode,
                output_result.stdout,
                output_result.stderr,
            )

        outputs = json.loads(output_result.stdout)
        return {
            name: output.get("value")
            for name, output in outputs.items()
            if isinstance(output, dict)
        }

def print_phase(title: str, current: int, total: int) -> None:
    rule = color_text("═" * 80, COLOR_YELLOW)
    print(rule)
    print(color_text(f"PHASE {current}/{total}: {title}", COLOR_YELLOW))
    print(rule)


def repo_root_from_cwd() -> Path:
    """Resolve the checkout root even when the CLI is run from a subdirectory."""
    cwd = Path.cwd().resolve()
    for candidate in (cwd, *cwd.parents):
        if (candidate / "cli" / "veritee" / "cli.py").is_file():
            return candidate

    return cwd


BANNER_DEFAULT_TAG = "TEE PACKAGER"
CLI_BANNER = r"""__     __ _____  ____   ___  _____  _____  _____
\ \   / /| ____||  _ \ |_ _||_   _|| ____|| ____|
 \ \ / / |  _|  | |_) | | |   | |  |  _|  |  _|
  \ V /  | |___ |  _ <  | |   | |  | |___ | |___
   \_/   |_____||_| \_\|___|  |_|  |_____||_____|"""
CLI_HELP_TEXT = "\b\n" + CLI_BANNER + f"""
Veritee VM  [ {BANNER_DEFAULT_TAG} ]

Build and deploy TEE VM images with your applications.
Allows you to register your application with the Warden attestation service and verify that your application is running in a trusted TEE environment."""


# show_locals would print unredacted secrets (tokens in command lists) on crash
app = typer.Typer(
    help=CLI_HELP_TEXT,
    rich_markup_mode="rich",
    pretty_exceptions_show_locals=False,
    no_args_is_help=True,
)

from veritee import os_release
from veritee import packaging_validation as pack_validation
app.add_typer(os_release.commands, name="os-release")

def warn_if_installed_cli_out_of_sync() -> None:
    """Warn when the running CLI differs from the checkout's source.

    A non-editable pip install snapshots the code at install time, so edits to
    cli/veritee/cli.py silently do not apply until reinstalled. Editable
    installs (pip install -e) run the checkout directly and never warn.
    """
    source = repo_root_from_cwd() / "cli" / "veritee" / "cli.py"
    if not source.is_file():
        return

    running = Path(__file__).resolve()
    try:
        if running.samefile(source):
            return
        if running.read_bytes() == source.read_bytes():
            return
    except OSError:
        return

    log.warning(
        "The running veritee CLI (%s) differs from the checkout source (%s). "
        "You may be executing stale code. Reinstall with "
        "`pip install -e ./cli` from the repository root to keep them in sync automatically.",
        running,
        source,
    )

COMMAND_PANEL_VERIFICATION = "Verification"
COMMAND_PANEL_REGISTRATION = "Registration"
COMMAND_PANEL_IMAGES = "Image Build & Packaging"
COMMAND_PANEL_DEPLOYMENT = "Deployment"

@app.callback()
def start(ctx: typer.Context) -> None:
    started_at = datetime.now().astimezone().replace(microsecond=0).isoformat()
    banner = CLI_BANNER + f"\nVeritee VM  [ {BANNER_DEFAULT_TAG} ]"
    print(color_text(banner, COLOR_GREEN))
    print(color_text(
        f"  version {CLI_VERSION} · network preprod · started {started_at}",
        COLOR_GRAY,
    ))
    warn_if_installed_cli_out_of_sync()

def load_json_file(path: Path) -> dict:
    if not path.exists():
        raise DeployerException(f"Required JSON file not found: {path}")

    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise DeployerException(f"Invalid JSON in {path}: {exc}") from exc

def parse_payload(payload: str):
    if payload.startswith("@"):
        path = Path(payload[1:])
        if not path.exists():
            raise DeployerException(f"Required payload file not found: {path}")

        value = path.read_text()
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return payload

def parse_json_argument(value: str, field_name: str):
    if value.startswith("@"):
        path = Path(value[1:])
        return load_json_file(path)

    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"{field_name} must be valid JSON or @path/to/file.json") from exc


def argument_source(value: str) -> str:
    if value.startswith("@"):
        return str(Path(value[1:]))

    return "inline value"


def parsed_value_kind(value) -> str:
    if isinstance(value, dict):
        return "JSON object"
    if isinstance(value, list):
        return "JSON array"
    if isinstance(value, str):
        return "text"
    if value is None:
        return "null"

    return type(value).__name__


def normalize_optional_nonce(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    nonce = value.strip()
    if not nonce:
        return None

    return nonce


def generate_attestation_nonce() -> str:
    return secrets.token_hex(32)


def log_verification_preflight(dapp_id: str, nonce: Optional[str], tee_attestation: str, parsed_attestation, payload: str, parsed_payload) -> None:
    log.info(color_text(f" ✓ Preflight: DApp identifier accepted: {dapp_id}.", COLOR_GREEN))
    if nonce:
        log.info(color_text(f" ✓ Preflight: nonce accepted: {nonce}.", COLOR_GREEN))
    log.info(
        color_text(
            f" ✓ Preflight: TEE attestation {parsed_value_kind(parsed_attestation)} loaded from {argument_source(tee_attestation)}.",
            COLOR_GREEN,
        )
    )
    log.info(
        color_text(
            f" ✓ Preflight: payload {parsed_value_kind(parsed_payload)} loaded from {argument_source(payload)}.",
            COLOR_GREEN,
        )
    )


WARDEN_REQUEST_TIMEOUT = (10, 120)
WARDEN_REGISTER_REQUEST_TIMEOUT = (10, 1800)
WARDEN_URL_ENV_VAR = "VERITEE_WARDEN_URL"
WARDEN_REGISTER_ROUTE = "dapps/register"
WARDEN_VERIFY_ATTESTATION_ROUTE = "dapps/verify_attestation"
WARDEN_JOB_POLL_SECS_ENV_VAR = "VERITEE_WARDEN_JOB_POLL_SECS"
DEFAULT_WARDEN_JOB_POLL_SECS = 5.0
WARDEN_JOB_HEARTBEAT_SECS_ENV_VAR = "VERITEE_WARDEN_JOB_HEARTBEAT_SECS"
DEFAULT_WARDEN_JOB_HEARTBEAT_SECS = 20.0


def warden_response_json(response: requests.Response, action: str) -> dict:
    if response.status_code >= 400:
        status = f"{response.status_code} {response.reason}".strip()
        body = response.text.strip()
        details = f"\n{body}" if body else ""
        raise DeployerException(f"Failed to {action}: Warden returned HTTP {status}{details}")

    try:
        return response.json()
    except ValueError as exc:
        raise DeployerException(f"Failed to {action}: Warden returned invalid JSON") from exc


def post_warden_json_response(
    endpoint: str,
    payload: dict,
    action: str,
    timeout=WARDEN_REQUEST_TIMEOUT,
) -> tuple[int, dict]:
    try:
        response = requests.post(
            endpoint,
            json=payload,
            headers={
                "Accept": "application/json",
            },
            timeout=timeout,
        )
        return response.status_code, warden_response_json(response, action)
    except requests.Timeout as exc:
        connect_timeout, read_timeout = timeout
        read_timeout_text = "none" if read_timeout is None else f"{read_timeout}s"
        raise DeployerException(
            f"Timed out while waiting for Warden to {action}. "
            f"Timeouts: connect={connect_timeout}s, read={read_timeout_text}."
        ) from exc
    except requests.RequestException as exc:
        raise DeployerException(f"Failed to {action}: {exc}") from exc


def post_warden_json(
    endpoint: str,
    payload: dict,
    action: str,
    timeout=WARDEN_REQUEST_TIMEOUT,
) -> dict:
    _, response_payload = post_warden_json_response(endpoint, payload, action, timeout=timeout)
    return response_payload


def get_warden_json(
    endpoint: str,
    action: str,
    timeout=WARDEN_REQUEST_TIMEOUT,
) -> dict:
    status_code, payload = get_warden_json_response(endpoint, action, timeout=timeout)
    if status_code >= 400:
        details = f"\n{payload}" if payload else ""
        raise DeployerException(
            f"Failed to {action}: Warden returned HTTP {status_code} for {endpoint}{details}"
        )

    if not isinstance(payload, dict):
        raise DeployerException(f"Failed to {action}: Warden returned invalid JSON")

    return payload


def get_warden_json_response(
    endpoint: str,
    action: str,
    timeout=WARDEN_REQUEST_TIMEOUT,
) -> tuple[int, object]:
    try:
        response = requests.get(
            endpoint,
            headers={
                "Accept": "application/json",
            },
            timeout=timeout,
        )
        if response.status_code >= 400:
            return response.status_code, response.text.strip()
        try:
            return response.status_code, response.json()
        except ValueError as exc:
            raise DeployerException(f"Failed to {action}: Warden returned invalid JSON") from exc
    except requests.Timeout as exc:
        connect_timeout, read_timeout = timeout
        read_timeout_text = "none" if read_timeout is None else f"{read_timeout}s"
        raise DeployerException(
            f"Timed out while waiting for Warden to {action}. "
            f"Timeouts: connect={connect_timeout}s, read={read_timeout_text}."
        ) from exc
    except requests.RequestException as exc:
        raise DeployerException(f"Failed to {action}: {exc}") from exc


def warden_job_poll_secs() -> float:
    return positive_float_env(
        WARDEN_JOB_POLL_SECS_ENV_VAR,
        DEFAULT_WARDEN_JOB_POLL_SECS,
    )


def warden_job_heartbeat_secs() -> float:
    return positive_float_env(
        WARDEN_JOB_HEARTBEAT_SECS_ENV_VAR,
        DEFAULT_WARDEN_JOB_HEARTBEAT_SECS,
    )


def positive_float_env(env_var: str, default: float) -> float:
    value = os.getenv(env_var, "").strip()
    if not value:
        return default

    try:
        parsed = float(value)
    except ValueError as exc:
        raise DeployerException(f"{env_var} must be a positive number of seconds") from exc

    if parsed <= 0:
        raise DeployerException(f"{env_var} must be a positive number of seconds")

    return parsed


def validate_warden_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise DeployerException("Warden URL must be an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise DeployerException("Warden URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise DeployerException("Warden URL must not contain a query string or fragment")

    return normalized


def resolve_warden_endpoint(endpoint: Optional[str], route: Optional[str] = None) -> str:
    if endpoint is not None:
        if not endpoint.strip():
            raise typer.BadParameter("Warden endpoint cannot be empty")
        return validate_warden_url(endpoint)

    base_url = os.getenv(WARDEN_URL_ENV_VAR, "").strip()
    if not base_url:
        raise DeployerException(
            f"{WARDEN_URL_ENV_VAR} must be set to the Warden base URL, or pass an explicit Warden endpoint."
        )

    base_url = validate_warden_url(base_url)
    if route is None:
        return base_url

    return f"{base_url}/{route.lstrip('/')}"


def resolve_warden_job_url(register_endpoint: str, status_url: str) -> str:
    parsed_status_url = urlparse(status_url)
    if parsed_status_url.scheme or parsed_status_url.netloc:
        return status_url

    normalized_status_url = status_url if status_url.startswith("/") else f"/{status_url}"
    return urljoin(register_endpoint, normalized_status_url)


def resolve_warden_job_endpoint(endpoint: Optional[str], status_url: str) -> str:
    if endpoint is not None:
        return resolve_warden_endpoint(endpoint)

    parsed_status_url = urlparse(status_url)
    if parsed_status_url.scheme and parsed_status_url.netloc:
        return validate_warden_url(status_url)

    return resolve_warden_endpoint(None)


def queued_payload_from_job_reference(job: str) -> dict:
    job_ref = job.strip()
    if not job_ref:
        raise typer.BadParameter("job cannot be empty")

    parsed_job_ref = urlparse(job_ref)
    if parsed_job_ref.scheme or parsed_job_ref.netloc or "/" in job_ref:
        path = parsed_job_ref.path if parsed_job_ref.scheme or parsed_job_ref.netloc else job_ref
        job_id = path.rstrip("/").rsplit("/", 1)[-1]
        if not job_id:
            raise typer.BadParameter("job reference must include a job id")
        return {
            "job_id": job_id,
            "status_url": job_ref,
        }

    return {
        "job_id": job_ref,
        "status_url": f"/jobs/{job_ref}",
    }


def queued_payload_from_warden_response(status_code: int, payload: dict, action: str) -> dict:
    if status_code != 202:
        raise DeployerException(f"Failed to {action}: Warden returned HTTP {status_code}, expected 202 Accepted")

    if not isinstance(payload, dict):
        raise DeployerException(f"Failed to {action}: Warden returned invalid queued job payload")

    job_id = payload.get("job_id")
    status_url = payload.get("status_url")
    if not isinstance(job_id, str) or not job_id.strip():
        raise DeployerException(f"Failed to {action}: Warden queued job response did not include job_id")
    if not isinstance(status_url, str) or not status_url.strip():
        raise DeployerException(f"Failed to {action}: Warden queued job response did not include status_url")

    return {
        "job_id": job_id,
        "status_url": status_url,
        "status": payload.get("status"),
    }


def queued_payload_from_nested_job(payload: dict, field_name: str, action: str) -> dict:
    nested_payload = payload.get(field_name)
    if not isinstance(nested_payload, dict):
        raise DeployerException(f"Failed to {action}: Warden response did not include {field_name}")

    job_id = nested_payload.get("job_id")
    status_url = nested_payload.get("status_url")
    if not isinstance(job_id, str) or not job_id.strip():
        raise DeployerException(f"Failed to {action}: {field_name} did not include job_id")
    if not isinstance(status_url, str) or not status_url.strip():
        raise DeployerException(f"Failed to {action}: {field_name} did not include status_url")

    return {
        "job_id": job_id,
        "status_url": status_url,
        "status": nested_payload.get("status"),
    }


def log_warden_job_summary(job: dict) -> None:
    job_id = job.get("job_id") or "unknown"
    status = job.get("status") or "unknown"
    phase = job.get("phase")

    message = f"Warden job {job_id}: status={status}"
    if phase:
        message += f", phase={phase}"
    log.info(message)


def warden_completed_phases(job: dict) -> List[str]:
    completed_phases = job.get("completed_phases")
    if not isinstance(completed_phases, list):
        return []

    return [phase for phase in completed_phases if isinstance(phase, str) and phase.strip()]


def log_new_warden_completed_phases(job: dict, logged_completed_phases: Set[str]) -> None:
    job_id = job.get("job_id") or "unknown"
    for phase in warden_completed_phases(job):
        if phase in logged_completed_phases:
            continue

        log.info(color_text(f" ✓ Warden job {job_id} completed phase: {phase}", COLOR_GREEN))
        logged_completed_phases.add(phase)


def warden_job_elapsed_secs(job: dict, fallback_started_at: float, now: float) -> int:
    started_at = job.get("started_at") or job.get("created_at")
    if isinstance(started_at, (int, float)) and started_at > 0:
        return max(0, int(time.time() - started_at))

    return max(0, int(now - fallback_started_at))


def poll_warden_job(register_endpoint: str, queued_payload: dict, job_description: str = "Warden job") -> dict:
    job_id = queued_payload.get("job_id")
    status_url = queued_payload.get("status_url")
    if not isinstance(job_id, str) or not job_id.strip():
        return queued_payload
    if not isinstance(status_url, str) or not status_url.strip():
        return queued_payload

    job_url = resolve_warden_job_url(register_endpoint, status_url)
    poll_secs = warden_job_poll_secs()
    heartbeat_secs = warden_job_heartbeat_secs()
    log.info(
        "%s %s accepted. Polling %s every %.1fs...",
        job_description,
        job_id,
        job_url,
        poll_secs,
    )

    last_status = None
    last_phase = None
    logged_completed_phases: Set[str] = set()
    last_heartbeat_at = time.monotonic()
    fallback_started_at = last_heartbeat_at
    while True:
        job = get_warden_json(job_url, f"poll {job_description}")
        status = job.get("status")
        phase = job.get("phase")
        now = time.monotonic()
        log_new_warden_completed_phases(job, logged_completed_phases)

        if status != last_status or phase != last_phase:
            log_warden_job_summary(job)
            last_status = status
            last_phase = phase
            last_heartbeat_at = now
        elif now - last_heartbeat_at >= heartbeat_secs:
            elapsed_secs = warden_job_elapsed_secs(job, fallback_started_at, now)
            message = f"Warden job {job_id} still {status}"
            if phase:
                message += f", phase={phase}"
            message += f", elapsed={elapsed_secs}s"
            log.info(message)
            last_heartbeat_at = now

        if status == "succeeded":
            result = job.get("result")
            if not isinstance(result, dict):
                raise DeployerException(
                    f"{job_description} {job_id} succeeded without a result"
                )
            return result

        if status == "failed":
            error = job.get("error") or "unknown error"
            raise DeployerException(f"{job_description} {job_id} failed: {error}")

        if status not in {"queued", "running"}:
            raise DeployerException(
                f"{job_description} {job_id} returned unknown status: {status}"
            )

        time.sleep(poll_secs)


def validate_attestation_domain_name(value: str) -> str:
    domain = value.strip()
    if not domain:
        raise typer.BadParameter("attestation_domain_name cannot be empty")

    parsed = urlparse(f"//{domain}")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise typer.BadParameter(
            "attestation_domain_name must be a domain name only, with no "
            "scheme, port, path, query, fragment, or credentials"
        ) from exc

    if (
        parsed.scheme
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or parsed_port is not None
        or (parsed.hostname or "").rstrip(".") != domain.lower().rstrip(".")
    ):
        raise typer.BadParameter(
            "attestation_domain_name must be a domain name only, with no "
            "scheme, port, path, query, fragment, or credentials"
        )

    if not re.fullmatch(r"[A-Za-z0-9.-]+", domain):
        raise typer.BadParameter("attestation_domain_name contains invalid characters")
    if len(domain) > 253:
        raise typer.BadParameter("attestation_domain_name is too long")
    labels = domain.rstrip(".").split(".")
    if len(labels) < 2:
        raise typer.BadParameter("attestation_domain_name must be a fully qualified domain name")
    for label in labels:
        if not label or len(label) > 63:
            raise typer.BadParameter("attestation_domain_name contains an invalid DNS label")
        if label.startswith("-") or label.endswith("-"):
            raise typer.BadParameter("attestation_domain_name contains an invalid DNS label")

    return domain.rstrip(".").lower()


def caddyfile_site_addresses(caddyfile: str) -> list[str]:
    sites = []
    depth = 0
    for raw_line in caddyfile.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if depth == 0 and line.endswith("{"):
            site_label = line[:-1].strip()
            if site_label:
                sites.extend(
                    address.strip().rstrip(",")
                    for address in re.split(r"[\s,]+", site_label)
                    if address.strip().rstrip(",")
                )

        depth += line.count("{")
        depth -= line.count("}")
        if depth < 0:
            depth = 0

    return sites


def caddy_site_host(site_address: str) -> Optional[str]:
    site_address = site_address.strip().strip(",")
    if not site_address or site_address == "{" or site_address.startswith(":"):
        return None

    parsed = urlparse(site_address if "://" in site_address else f"//{site_address}")
    host = parsed.hostname
    if not host:
        return None

    try:
        return validate_attestation_domain_name(host)
    except typer.BadParameter:
        return None


def caddyfile_site_hosts(caddyfile: str | Path) -> list[str]:
    if isinstance(caddyfile, Path):
        if not caddyfile.is_file():
            return []
        caddyfile = caddyfile.read_text()

    hosts = []
    for site_address in caddyfile_site_addresses(caddyfile):
        host = caddy_site_host(site_address)
        if host is not None:
            hosts.append(host)

    return hosts


def load_ecdsa_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(
        path.read_bytes(),
        password=None,
    )

    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise DeployerException(f"Expected ECDSA private key, got {type(key).__name__}")

    return key


def load_ecdsa_public_key(path: Path) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())

    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise DeployerException(f"Expected ECDSA public key, got {type(key).__name__}")

    return key


def sign_bytes_with_ecdsa(private_key_path: Path, payload: bytes) -> bytes:
    private_key = load_ecdsa_private_key(private_key_path)

    return private_key.sign(
        payload,
        ec.ECDSA(hashes.SHA256()),
    )


def verify_bytes_with_ecdsa(
    public_key_path: Path,
    payload: bytes,
    signature: bytes,
) -> None:
    public_key = load_ecdsa_public_key(public_key_path)

    try:
        public_key.verify(
            signature,
            payload,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise DeployerException("Invalid ECDSA signature") from exc
    

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(16 * 1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def copy_file_if_needed(source_path: Path, output_path: Path) -> Path:
    if not source_path.exists():
        raise DeployerException(f"Required file not found: {source_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if source_path.resolve() != output_path.resolve():
        shutil.copy2(source_path, output_path)

    return output_path


def write_tee_measurements(path: Path, payload: dict) -> None:
    ordered_payload = {}
    if "measurements" in payload:
        ordered_payload["measurements"] = payload["measurements"]
    if "application_root_hash" in payload:
        ordered_payload["application_root_hash"] = payload["application_root_hash"]

    for key, value in payload.items():
        if key not in ordered_payload:
            ordered_payload[key] = value

    path.write_text(json.dumps(ordered_payload, indent=4) + "\n")


SNP_ATTESTATION_REPORT_SIZE = 1184
SNP_POLICY_OFFSET = 0x08
SNP_FAMILY_ID_OFFSET = 0x10
SNP_IMAGE_ID_OFFSET = 0x20
SNP_PLATFORM_INFO_OFFSET = 0x40
SNP_MEASUREMENT_OFFSET = 0x90
SNP_REPORTED_TCB_OFFSET = 0x180
SNP_LAUNCH_TCB_OFFSET = 0x1F0
HCL_AKPUB_KEY_ID = "HCLAkPub"
TPM2_CHECKQUOTE_BIN_ENV = "TPM2_CHECKQUOTE_BIN"
QUOTE_DERIVED_PLATFORM_PCRS = ("0", "1", "2", "3")
TPM_ALG_SHA256 = 0x000B
TPM2_TOOLS_PCR_SELECTION_BANKS = 16
TPM2_TOOLS_PCR_SELECTION_ENTRY_SIZE = 8
TPM2_TOOLS_PCR_SELECT_MAX = 3
TPM2B_DIGEST_STRUCT_SIZE = 66
TPM2B_DIGEST_BUFFER_SIZE = 64
SHA256_DIGEST_SIZE = 32


def require_json_object(value: Any, description: str) -> dict:
    if not isinstance(value, dict):
        raise DeployerException(f"{description} must be a JSON object")

    return value


def decode_standard_base64(value: Any, description: str) -> bytes:
    if not isinstance(value, str):
        raise DeployerException(f"{description} must be a base64 string")

    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise DeployerException(f"{description} is not valid base64") from exc


def decode_base64url_json_segment(value: str, description: str) -> dict:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value + padding)
        return require_json_object(json.loads(decoded), description)
    except (ValueError, json.JSONDecodeError) as exc:
        raise DeployerException(f"{description} is not valid base64url JSON") from exc


def decode_base64url_bytes(value: Any, description: str) -> bytes:
    if not isinstance(value, str):
        raise DeployerException(f"{description} must be a base64url string")

    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, binascii.Error) as exc:
        raise DeployerException(f"{description} is not valid base64url") from exc


def read_u64_le(data: bytes, offset: int, description: str) -> int:
    end = offset + 8
    if len(data) < end:
        raise DeployerException(f"raw SEV-SNP report is too short for {description}")

    return int.from_bytes(data[offset:end], "little")


def read_hex(data: bytes, offset: int, length: int, description: str) -> str:
    end = offset + length
    if len(data) < end:
        raise DeployerException(f"raw SEV-SNP report is too short for {description}")

    return data[offset:end].hex()


def parse_snp_tcb(data: bytes, offset: int, description: str) -> dict:
    end = offset + 8
    if len(data) < end:
        raise DeployerException(f"raw SEV-SNP report is too short for {description}")

    value = data[offset:end]
    return {
        "bootloader": value[0],
        "tee": value[1],
        "snp": value[6],
        "microcode": value[7],
    }


def decode_maa_claims(evidence: dict) -> dict:
    token = require_json_object(evidence.get("token"), "MAA token")
    key_value = evidence.get("key")
    if not isinstance(key_value, list) or not all(isinstance(byte, int) for byte in key_value):
        raise DeployerException("MAA transport key must be a byte array")

    try:
        transport_key = bytes(key_value)
    except ValueError as exc:
        raise DeployerException("MAA transport key contains an invalid byte value") from exc

    encrypted_jwt = decode_standard_base64(token.get("Jwt"), "MAA encrypted JWT")
    auth_tag = decode_standard_base64(token.get("AuthenticationData"), "MAA authentication tag")
    encryption_params = require_json_object(
        token.get("EncryptionParams"),
        "MAA encryption parameters",
    )
    nonce = decode_standard_base64(encryption_params.get("Iv"), "MAA encryption nonce")

    try:
        jwt = AESGCM(transport_key).decrypt(
            nonce,
            encrypted_jwt + auth_tag,
            b"Transport Key",
        ).decode()
    except Exception as exc:
        raise DeployerException("failed to decrypt MAA JWT") from exc

    segments = jwt.split(".")
    if len(segments) != 3:
        raise DeployerException("decrypted MAA JWT must contain three segments")

    return decode_base64url_json_segment(segments[1], "MAA JWT claims")


def derive_maa_policy_fields(evidence: dict) -> dict:
    claims = decode_maa_claims(evidence)
    isolation = require_json_object(
        claims.get("x-ms-isolation-tee"),
        "MAA x-ms-isolation-tee claims",
    )

    return {
        "compliance-status": isolation.get("x-ms-compliance-status"),
        "attestation-type": isolation.get("x-ms-attestation-type"),
        "secureboot": claims.get("secureboot"),
        "imageId": isolation.get("x-ms-sevsnpvm-imageId"),
        "launch_measurement": isolation.get("x-ms-sevsnpvm-launchmeasurement"),
        "microcode-svn": isolation.get("x-ms-sevsnpvm-microcode-svn"),
        "snpfw-svn": isolation.get("x-ms-sevsnpvm-snpfw-svn"),
    }


def derive_raw_sev_snp_policy_fields(evidence: dict) -> dict:
    # Baseline capture only: this parses policy fields out of the raw SEV-SNP
    # report returned by the deployed VM. It intentionally does not verify the
    # AMD signature, VCEK chain, or runtime_data/report_data binding here. The
    # trust model is TOFU over a deployment the operator already controls; the
    # hydrated values become the expected policy that Warden verifies later.
    report = decode_standard_base64(evidence.get("report"), "raw SEV-SNP report")
    if len(report) != SNP_ATTESTATION_REPORT_SIZE:
        raise DeployerException(
            "raw SEV-SNP report has invalid size: "
            f"expected {SNP_ATTESTATION_REPORT_SIZE} bytes, got {len(report)}"
        )

    guest_policy = read_u64_le(report, SNP_POLICY_OFFSET, "guest policy")
    platform_info = read_u64_le(report, SNP_PLATFORM_INFO_OFFSET, "platform info")
    reported_tcb = parse_snp_tcb(report, SNP_REPORTED_TCB_OFFSET, "reported TCB")
    launch_tcb = parse_snp_tcb(report, SNP_LAUNCH_TCB_OFFSET, "launch TCB")

    return {
        "attestation-type": "sevsnpvm",
        "imageId": read_hex(report, SNP_IMAGE_ID_OFFSET, 16, "image ID"),
        "launch_measurement": read_hex(report, SNP_MEASUREMENT_OFFSET, 48, "launch measurement"),
        "microcode-svn": reported_tcb["microcode"],
        "snpfw-svn": reported_tcb["snp"],
        "sev-snp": {
            "family-id": read_hex(report, SNP_FAMILY_ID_OFFSET, 16, "family ID"),
            "migration-agent-allowed": bool(guest_policy & (1 << 18)),
            "ciphertext-hiding-enabled": bool(platform_info & (1 << 4)),
            "ecc-enabled": bool(platform_info & (1 << 2)),
            "minimum-reported-tcb": {
                "bootloader": reported_tcb["bootloader"],
                "tee": reported_tcb["tee"],
            },
            "minimum-launch-tcb": launch_tcb,
        },
    }


def derive_policy_fields_from_attestation(attestation: dict) -> dict:
    attestation = require_json_object(attestation, "attestation response")
    envelope = require_json_object(attestation.get("attestation"), "attestation envelope")
    mode = envelope.get("mode")
    evidence = require_json_object(envelope.get("evidence"), "attestation evidence")

    if mode == AttestationMode.MAA.value:
        return derive_maa_policy_fields(evidence)
    if mode == AttestationMode.RAW_SEV_SNP.value.replace("-", "_"):
        return derive_raw_sev_snp_policy_fields(evidence)

    raise DeployerException(f"unsupported attestation mode: {mode!r}")


def hcl_ak_pub_from_keys(keys: Any, description: str) -> dict:
    if not isinstance(keys, list):
        raise DeployerException(f"{description} keys must be a JSON array")

    for key in keys:
        if not isinstance(key, dict):
            continue
        if key.get("kid") != HCL_AKPUB_KEY_ID:
            continue
        if key.get("kty") != "RSA":
            raise DeployerException(f"{description} {HCL_AKPUB_KEY_ID} must be an RSA key")
        if not isinstance(key.get("n"), str) or not isinstance(key.get("e"), str):
            raise DeployerException(f"{description} {HCL_AKPUB_KEY_ID} must contain n and e")
        return key

    raise DeployerException(f"{description} does not contain {HCL_AKPUB_KEY_ID}")


def hcl_ak_pub_from_attestation(attestation: dict) -> dict:
    attestation = require_json_object(attestation, "attestation response")
    envelope = require_json_object(attestation.get("attestation"), "attestation envelope")
    mode = envelope.get("mode")
    evidence = require_json_object(envelope.get("evidence"), "attestation evidence")

    if mode == AttestationMode.MAA.value:
        claims = decode_maa_claims(evidence)
        isolation = require_json_object(
            claims.get("x-ms-isolation-tee"),
            "MAA x-ms-isolation-tee claims",
        )
        runtime = isolation.get("x-ms-runtime")
        if runtime is None:
            runtime = claims.get("x-ms-runtime")
        runtime = require_json_object(runtime, "MAA runtime claims")
        return hcl_ak_pub_from_keys(runtime.get("keys"), "MAA runtime claims")

    if mode == AttestationMode.RAW_SEV_SNP.value.replace("-", "_"):
        runtime_data = decode_standard_base64(
            evidence.get("runtime_data"),
            "raw SEV-SNP runtime_data",
        )
        try:
            runtime = require_json_object(
                json.loads(runtime_data),
                "raw SEV-SNP runtime_data",
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeployerException("raw SEV-SNP runtime_data is not valid JSON") from exc

        return hcl_ak_pub_from_keys(runtime.get("keys"), "raw SEV-SNP runtime_data")

    raise DeployerException(f"unsupported attestation mode for HCLAkPub extraction: {mode!r}")


def rsa_public_key_pem_from_jwk(key: dict) -> bytes:
    modulus = decode_base64url_bytes(key.get("n"), f"{HCL_AKPUB_KEY_ID}.n")
    exponent = decode_base64url_bytes(key.get("e"), f"{HCL_AKPUB_KEY_ID}.e")
    if not modulus or not exponent:
        raise DeployerException(f"{HCL_AKPUB_KEY_ID} contains an empty RSA component")

    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(exponent, "big"),
        int.from_bytes(modulus, "big"),
    ).public_key()

    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def parse_tpm2_checkquote_pcrs(stdout: str) -> dict[str, str]:
    pcr_map = {}
    in_sha256 = False
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.lower() == "sha256:":
            in_sha256 = True
            continue

        if not in_sha256:
            continue

        if line and not line.startswith((" ", "\t")):
            in_sha256 = False
            continue

        if ":" not in stripped:
            continue

        index, digest = stripped.split(":", 1)
        index = index.strip()
        if not index.isdigit():
            continue

        pcr_map[index] = digest.strip().removeprefix("0x").lower()

    if not pcr_map:
        raise DeployerException("tpm2_checkquote output contained no SHA-256 PCR digests")

    return pcr_map


def parse_tpm2_quote_pcr_selection_groups(pcr_data: bytes) -> list[list[str]]:
    if len(pcr_data) < 4:
        raise DeployerException("TPM quote PCR data is too short for a PCR selection list")

    count = int.from_bytes(pcr_data[0:4], "little")
    if count < 1 or count > TPM2_TOOLS_PCR_SELECTION_BANKS:
        raise DeployerException(f"TPM quote PCR selection count is invalid: {count}")

    selected_groups: list[list[str]] = []
    for selection_index in range(count):
        offset = 4 + selection_index * TPM2_TOOLS_PCR_SELECTION_ENTRY_SIZE
        end = offset + TPM2_TOOLS_PCR_SELECTION_ENTRY_SIZE
        if len(pcr_data) < end:
            raise DeployerException("TPM quote PCR data is too short for a PCR selection entry")

        hash_alg = int.from_bytes(pcr_data[offset:offset + 2], "little")
        sizeof_select = pcr_data[offset + 2]
        if sizeof_select > TPM2_TOOLS_PCR_SELECT_MAX:
            raise DeployerException(
                f"TPM quote PCR selection has invalid size: {sizeof_select}"
            )

        if hash_alg != TPM_ALG_SHA256:
            continue

        pcr_select = pcr_data[offset + 3:offset + 3 + sizeof_select]
        for byte_index, mask in enumerate(pcr_select):
            selected_pcrs = []
            for bit_index in range(8):
                if mask & (1 << bit_index):
                    selected_pcrs.append(str(byte_index * 8 + bit_index))
            if selected_pcrs:
                selected_groups.append(selected_pcrs)

    if not selected_groups:
        raise DeployerException("TPM quote PCR data does not contain a SHA-256 PCR selection")

    return selected_groups


def parse_tpm2_quote_pcr_selection(pcr_data: bytes) -> list[str]:
    selected_pcrs = []
    for group in parse_tpm2_quote_pcr_selection_groups(pcr_data):
        selected_pcrs.extend(group)

    return selected_pcrs


def parse_tpm2_quote_pcrs(pcr_data: bytes) -> dict[str, str]:
    selected_groups = parse_tpm2_quote_pcr_selection_groups(pcr_data)
    offset = 4 + TPM2_TOOLS_PCR_SELECTION_BANKS * TPM2_TOOLS_PCR_SELECTION_ENTRY_SIZE
    if len(pcr_data) < offset + 4:
        raise DeployerException("TPM quote PCR data is too short for digest groups")

    group_count = int.from_bytes(pcr_data[offset:offset + 4], "little")
    offset += 4
    if group_count != len(selected_groups):
        raise DeployerException(
            "TPM quote PCR digest group count does not match the SHA-256 PCR selection: "
            f"expected {len(selected_groups)}, got {group_count}"
        )

    pcr_map = {}
    for selected_pcrs in selected_groups:
        if len(pcr_data) < offset + 4:
            raise DeployerException("TPM quote PCR data is too short for a digest group")

        digest_count = int.from_bytes(pcr_data[offset:offset + 4], "little")
        offset += 4
        if digest_count != len(selected_pcrs):
            raise DeployerException(
                "TPM quote PCR digest count does not match the SHA-256 PCR selection: "
                f"expected {len(selected_pcrs)}, got {digest_count}"
            )

        for pcr_index in selected_pcrs:
            digest_end = offset + TPM2B_DIGEST_STRUCT_SIZE
            if len(pcr_data) < digest_end:
                raise DeployerException(f"TPM quote PCR {pcr_index} digest is truncated")

            digest_size = int.from_bytes(pcr_data[offset:offset + 2], "little")
            if digest_size != SHA256_DIGEST_SIZE:
                raise DeployerException(
                    f"TPM quote PCR {pcr_index} has invalid SHA-256 digest size: {digest_size}"
                )

            digest_start = offset + 2
            digest_end = digest_start + SHA256_DIGEST_SIZE
            pcr_map[pcr_index] = pcr_data[digest_start:digest_end].hex()
            offset += 2 + TPM2B_DIGEST_BUFFER_SIZE

    return pcr_map


def quote_pcrs_from_attestation_with_tpm2_checkquote(attestation: dict) -> dict[str, str]:
    msg = decode_standard_base64(attestation.get("msg"), "TPM quote message")
    sig = decode_standard_base64(attestation.get("sig"), "TPM quote signature")
    pcr = decode_standard_base64(attestation.get("pcr"), "TPM quote PCR selection")
    ak_pub_pem = rsa_public_key_pem_from_jwk(hcl_ak_pub_from_attestation(attestation))

    tpm2_checkquote_bin = os.getenv(TPM2_CHECKQUOTE_BIN_ENV, "tpm2_checkquote")
    with (
        tempfile.NamedTemporaryFile() as msg_file,
        tempfile.NamedTemporaryFile() as sig_file,
        tempfile.NamedTemporaryFile() as pcr_file,
        tempfile.NamedTemporaryFile() as ak_pub_file,
    ):
        msg_file.write(msg)
        msg_file.flush()
        sig_file.write(sig)
        sig_file.flush()
        pcr_file.write(pcr)
        pcr_file.flush()
        ak_pub_file.write(ak_pub_pem)
        ak_pub_file.flush()

        command = [
            tpm2_checkquote_bin,
            "--public",
            ak_pub_file.name,
            "--message",
            msg_file.name,
            "--pcr",
            pcr_file.name,
            "--signature",
            sig_file.name,
        ]
        result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        raise DeployerSubProcessException(
            " ".join(command),
            result.returncode,
            result.stdout,
            result.stderr,
        )

    return parse_tpm2_checkquote_pcrs(result.stdout)


def quote_pcrs_from_attestation(
    attestation: dict,
    *,
    use_tpm2_checkquote: bool = False,
) -> dict[str, str]:
    # Baseline capture only: by default this parses PCR values from the TPM PCR
    # blob without verifying the quote signature or HCLAkPub binding. Warden is
    # responsible for those checks later; this CLI only hydrates PCR0-3 from a VM
    # the operator has chosen as the known-good first deployment.
    if use_tpm2_checkquote:
        return quote_pcrs_from_attestation_with_tpm2_checkquote(attestation)

    pcr = decode_standard_base64(attestation.get("pcr"), "TPM quote PCR selection")
    return parse_tpm2_quote_pcrs(pcr)


def write_quote_derived_platform_pcrs(
    attestation: dict,
    pcrs_output: Path,
    *,
    use_tpm2_checkquote: bool = False,
) -> dict[str, str]:
    quote_pcrs = quote_pcrs_from_attestation(
        attestation,
        use_tpm2_checkquote=use_tpm2_checkquote,
    )
    pcrs_payload = load_json_file(pcrs_output) if pcrs_output.exists() else {}
    measurements = pcrs_payload.setdefault("measurements", {})
    if not isinstance(measurements, dict):
        raise DeployerException(f"{pcrs_output} measurements must be a JSON object")

    extracted = {}
    for index in QUOTE_DERIVED_PLATFORM_PCRS:
        digest = quote_pcrs.get(index)
        if digest is None:
            raise DeployerException(f"TPM quote is missing PCR {index}")
        extracted[index] = digest
        measurements[index] = digest

    pcrs_output.parent.mkdir(parents=True, exist_ok=True)
    write_tee_measurements(pcrs_output, pcrs_payload)

    return extracted


def hydrate_policy_template_from_attestation(template: dict, attestation: dict) -> dict:
    policy = json.loads(json.dumps(template))
    derived = derive_policy_fields_from_attestation(attestation)

    # These are identifiers / measurements / minimum TCB floors that should come
    # from the deployed VM evidence.
    for key in (
        "attestation-type",
        "imageId",
        "launch_measurement",
        "microcode-svn",
        "snpfw-svn",
    ):
        if derived.get(key) is not None:
            policy[key] = derived[key]

    # These keep the old behaviour when present in the template, but can be
    # filled in for a minimal policy template.
    for key in ("compliance-status", "secureboot"):
        if key not in policy and derived.get(key) is not None:
            policy[key] = derived[key]

    if "sev-snp" in derived:
        sev_policy = policy.setdefault("sev-snp", {})
        if not isinstance(sev_policy, dict):
            raise DeployerException("policy sev-snp field must be a JSON object")

        raw_fields = derived["sev-snp"]
        for key in ("family-id", "minimum-reported-tcb", "minimum-launch-tcb"):
            sev_policy[key] = raw_fields[key]

        # Preserve security intent if the template already says what is allowed.
        # In particular, never derive debug-allowed from the VM.
        for key in (
            "migration-agent-allowed",
            "ciphertext-hiding-enabled",
            "ecc-enabled",
        ):
            if key not in sev_policy and key in raw_fields:
                sev_policy[key] = raw_fields[key]

        sev_policy.setdefault("debug-allowed", False)

    return policy


def normalize_attestation_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise typer.BadParameter("attestation-url cannot be empty")

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise typer.BadParameter(
            "attestation-url must be a full HTTP(S) URL; use the deployed VM's "
            "https://<attestation-domain>/tee_attestation endpoint"
        )

    return value


def normalize_public_attestation_url(value: str) -> str:
    url = normalize_attestation_url(value)
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.path.rstrip("/") != "/tee_attestation":
        raise typer.BadParameter(
            "pull-attestation requires the public HTTPS /tee_attestation URL"
        )
    return url


def fetch_resolved_https_json(
    url: str,
    resolved_host: str,
    *,
    params: dict,
    timeout_seconds: int,
    context: Optional[ssl.SSLContext] = None,
) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise DeployerException("resolved attestation fetch requires an HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise DeployerException("attestation URL must not contain credentials")
    if not resolved_host.strip():
        raise DeployerException("resolved attestation host cannot be empty")

    connection = ResolvedHttpsConnection(
        parsed.hostname,
        resolved_host.strip(),
        port=parsed.port or 443,
        timeout=timeout_seconds,
        context=context or ssl.create_default_context(),
    )
    request_path = parsed.path or "/"
    query = parsed.query
    encoded_params = urlencode(params)
    if encoded_params:
        query = f"{query}&{encoded_params}" if query else encoded_params
    if query:
        request_path = f"{request_path}?{query}"

    try:
        connection.request(
            "GET",
            request_path,
            headers={"Accept": "application/json", "Host": parsed.netloc},
        )
        response = connection.getresponse()
        body = response.read().decode("utf-8")
    except (OSError, http.client.HTTPException, UnicodeDecodeError) as exc:
        raise DeployerException(
            f"Failed to fetch attestation from {url} via {resolved_host}: {exc}"
        ) from exc
    finally:
        connection.close()

    if response.status < 200 or response.status >= 300:
        raise DeployerException(
            f"Attestation endpoint {url} returned HTTP {response.status} {response.reason}:\n{body}"
        )

    try:
        return require_json_object(json.loads(body), "attestation response")
    except json.JSONDecodeError as exc:
        raise DeployerException(f"Attestation endpoint {url} did not return JSON") from exc


def internal_tls_root_ca(attestation_document: dict) -> str:
    root_ca = attestation_document.get("webserver_rootca")
    tls_evidence = attestation_document.get("webserver_tls")
    if not isinstance(root_ca, str) or not root_ca.strip():
        raise DeployerException(
            "internal TLS attestation document is missing webserver_rootca"
        )
    if not isinstance(tls_evidence, dict) or tls_evidence.get("mode") != "internal_ca":
        raise DeployerException(
            "internal TLS attestation document has invalid webserver_tls evidence"
        )

    expected_hash = tls_evidence.get("root_ca_sha256")
    actual_hash = hashlib.sha256(root_ca.encode("utf-8")).hexdigest()
    if not isinstance(expected_hash, str) or not secrets.compare_digest(
        expected_hash.lower(),
        actual_hash,
    ):
        raise DeployerException(
            "internal TLS root CA does not match webserver_tls.root_ca_sha256"
        )

    return root_ca


def fetch_internal_tls_attestation_json(
    url: str,
    *,
    params: dict,
    timeout_seconds: int,
    resolved_host: Optional[str] = None,
) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise DeployerException("internal TLS attestation fetch requires an HTTPS URL")

    destination = resolved_host or parsed.hostname
    static_document_url = urljoin(url, "/attestation.json")

    # The CA is authenticated by the attestation and PCR15 checks performed
    # after bootstrap. It is not trusted merely because this first fetch returned it.
    bootstrap_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    bootstrap_context.check_hostname = False
    bootstrap_context.verify_mode = ssl.CERT_NONE
    static_document = fetch_resolved_https_json(
        static_document_url,
        destination,
        params={},
        timeout_seconds=timeout_seconds,
        context=bootstrap_context,
    )
    root_ca = internal_tls_root_ca(static_document)

    # Trust only this root. Adding it to create_default_context() would retain
    # the host WebPKI roots and allow a public certificate to satisfy the retry.
    trusted_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        trusted_context.load_verify_locations(cadata=root_ca)
    except ssl.SSLError as exc:
        raise DeployerException(
            "internal TLS attestation document contains an invalid root CA"
        ) from exc

    return fetch_resolved_https_json(
        url,
        destination,
        params=params,
        timeout_seconds=timeout_seconds,
        context=trusted_context,
    )


def fetch_attestation_json(
    attestation_url: str,
    *,
    timeout_seconds: int = 30,
    nonce: Optional[str] = None,
    payload: Optional[str] = None,
    resolved_host: Optional[str] = None,
    tls_mode: str = "azure_vault",
) -> dict:
    url = normalize_attestation_url(attestation_url)
    resolved_tls_mode = validate_tls_mode(tls_mode)
    parsed_url = urlparse(url)
    params = {}
    normalized_nonce = normalize_optional_nonce(nonce)
    if normalized_nonce is not None:
        params["nonce"] = normalized_nonce
    if payload is not None and payload.strip():
        params["payload"] = payload

    if resolved_tls_mode == "internal" and parsed_url.scheme == "https":
        return fetch_internal_tls_attestation_json(
            url,
            params=params,
            timeout_seconds=timeout_seconds,
            resolved_host=resolved_host,
        )

    if resolved_host is not None:
        return fetch_resolved_https_json(
            url,
            resolved_host,
            params=params,
            timeout_seconds=timeout_seconds,
        )

    try:
        response = requests.get(
            url,
            params=params,
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        return require_json_object(response.json(), "attestation response")
    except requests.RequestException as exc:
        body = exc.response.text if exc.response is not None else ""
        raise DeployerException(f"Failed to fetch attestation from {url}: {exc}\n{body}") from exc
    except json.JSONDecodeError as exc:
        raise DeployerException(f"Attestation endpoint {url} did not return JSON") from exc


def write_hydrated_policy_from_attestation(
    attestation: dict,
    *,
    template_policy: Path,
    output: Path,
    pcrs_output: Optional[Path] = None,
    use_tpm2_checkquote: bool = False,
) -> dict:
    template = load_json_file(template_policy)
    policy = hydrate_policy_template_from_attestation(template, attestation)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_tee_measurements(output, policy)

    if pcrs_output is not None:
        extracted_pcrs = write_quote_derived_platform_pcrs(
            attestation,
            pcrs_output,
            use_tpm2_checkquote=use_tpm2_checkquote,
        )
        log.info(
            "Extracted quote-derived platform PCRs to %s: %s",
            pcrs_output,
            ", ".join(f"PCR{index}={digest}" for index, digest in extracted_pcrs.items()),
        )

    return policy


def hydrate_policy_from_online_attestation(
    attestation_url: str,
    *,
    template_policy: Path,
    output: Path,
    pcrs_output: Optional[Path] = None,
    timeout_seconds: int = 30,
    use_tpm2_checkquote: bool = False,
    attestation_nonce: Optional[str] = None,
    unbound_attestation: bool = False,
    resolved_host: Optional[str] = None,
    tls_mode: str = "azure_vault",
) -> dict:
    if unbound_attestation and normalize_optional_nonce(attestation_nonce) is not None:
        raise typer.BadParameter("--attestation-nonce cannot be used with --unbound-attestation")

    nonce = None if unbound_attestation else normalize_optional_nonce(attestation_nonce) or generate_attestation_nonce()
    if nonce is None:
        log.warning("Fetching unbound attestation response from %s", normalize_attestation_url(attestation_url))
    else:
        log.info("Fetching nonce-bound attestation response from %s with nonce %s", normalize_attestation_url(attestation_url), nonce)

    attestation = fetch_attestation_json(
        attestation_url,
        timeout_seconds=timeout_seconds,
        nonce=nonce,
        resolved_host=resolved_host,
        tls_mode=tls_mode,
    )
    return write_hydrated_policy_from_attestation(
        attestation,
        template_policy=template_policy,
        output=output,
        pcrs_output=pcrs_output,
        use_tpm2_checkquote=use_tpm2_checkquote,
    )


def resolve_policy_template(repo_root: Path, output: Optional[Path] = None) -> Path:
    candidates = []
    if output is not None:
        candidates.append(output)
    candidates.extend([
        repo_root / POLICY_TEMPLATE_FILE,
        repo_root / POLICY_FILE,
    ])

    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise DeployerException(
        "Could not find a policy template to hydrate. Expected one of: "
        + ", ".join(str(candidate) for candidate in candidates)
    )


def resolve_policy_template_for_hydration(repo_root: Path, output: Path) -> Path:
    return resolve_policy_template(repo_root, output)


def hydrate_policy_after_create_vm(
    attestation_url: str,
    *,
    repo_root: Path,
    output: Path,
    pcrs_output: Optional[Path] = None,
    attempts: int = 12,
    delay_seconds: int = 10,
    use_tpm2_checkquote: bool = False,
    unbound_attestation: bool = False,
    resolved_host: Optional[str] = None,
    tls_mode: str = "azure_vault",
) -> dict:
    template_policy = resolve_policy_template_for_hydration(repo_root, output)
    last_error = None

    for attempt in range(1, attempts + 1):
        try:
            return hydrate_policy_from_online_attestation(
                attestation_url,
                template_policy=template_policy,
                output=output,
                pcrs_output=pcrs_output,
                timeout_seconds=10,
                use_tpm2_checkquote=use_tpm2_checkquote,
                unbound_attestation=unbound_attestation,
                resolved_host=resolved_host,
                tls_mode=tls_mode,
            )
        except DeployerException as exc:
            last_error = exc
            if attempt == attempts:
                break

            log.info(
                "Attestation endpoint not ready yet (%s/%s); retrying in %ss: %s",
                attempt,
                attempts,
                delay_seconds,
                exc,
            )
            time.sleep(delay_seconds)

    raise DeployerException(
        f"Failed to hydrate policy after {attempts} attempt(s): {last_error}"
    )


def iter_roothash_entries(value):
    if isinstance(value, dict):
        roothash = value.get("roothash")
        if isinstance(roothash, str):
            yield value

        for child in value.values():
            yield from iter_roothash_entries(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_roothash_entries(child)


def has_app_label(entry: dict) -> bool:
    for key in ("label", "partition_label", "partlabel", "name"):
        value = entry.get(key)
        if isinstance(value, str) and value == "app":
            return True

    return False


def extract_application_root_hash(path: Path, *, require_app_label: bool = False) -> str:
    manifest = load_json_file(path)
    entries = list(iter_roothash_entries(manifest))
    if not entries:
        raise DeployerException(f"Could not find roothash in {path}")

    app_entries = [entry for entry in entries if has_app_label(entry)]
    if len(app_entries) == 1:
        return app_entries[0]["roothash"]

    if len(app_entries) > 1:
        raise DeployerException(f"Found multiple app roothashes in {path}")

    if require_app_label:
        raise DeployerException(f"Could not find app roothash in {path}")

    if len(entries) == 1:
        return entries[0]["roothash"]

    if isinstance(manifest, list) and manifest and isinstance(manifest[0], dict):
        roothash = manifest[0].get("roothash")
        if isinstance(roothash, str):
            return roothash

    raise DeployerException(f"Found multiple roothashes in {path}, but none labeled app")


def write_application_root_hash(
    source_path: Path,
    output_path: Path,
    *,
    require_app_label: bool = False,
) -> str:
    application_root_hash = extract_application_root_hash(
        source_path,
        require_app_label=require_app_label,
    )
    payload = load_json_file(output_path) if output_path.exists() else {}
    payload["application_root_hash"] = application_root_hash
    write_tee_measurements(output_path, payload)

    return application_root_hash


def write_pcr_measurements(disk_path: Path, output_path: Path, target: str) -> None:
    if not disk_path.exists():
        raise DeployerException(f"Base Veritee OS image artifact not found: {disk_path}")

    repo_root = Path.cwd()
    script_path = repo_root / "scripts" / "compute_expected_pcr4.py"
    if not script_path.is_file():
        raise DeployerException(
            f"PCR measurement script not found at {script_path}. "
            "Run this command from the veritee repository root."
        )
    measurement_output_path = output_path.with_suffix(".measurements.json")
    command = [
        sys.executable,
        str(script_path),
        "--disk",
        str(disk_path),
        "--target",
        target,
        "--output",
        str(measurement_output_path),
    ]
    res = subprocess.run(
        command,
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise DeployerSubProcessException(
            " ".join(command),
            res.returncode,
            res.stdout,
            res.stderr,
        )

    try:
        output_payload = load_json_file(output_path) if output_path.exists() else {}
        measurement_payload = load_json_file(measurement_output_path)
        output_payload["measurements"] = measurement_payload["measurements"]
        write_tee_measurements(output_path, output_payload)
    finally:
        measurement_output_path.unlink(missing_ok=True)


def load_tee_measurements(path: Path) -> dict:
    measurements = load_json_file(path)
    if "measurements" not in measurements:
        raise DeployerException(f"Missing measurements in {path}")
    if "application_root_hash" not in measurements:
        raise DeployerException(f"Missing application_root_hash in {path}")

    return measurements


APP_METADATA_FILE = "metadata.json"
APP_METADATA_FIELDS = (
    "name",
    "description",
    "app_container_image",
    "base_os_image",
)
APP_METADATA_REQUIRED_FIELDS = (
    "name",
    "app_container_image",
    "base_os_image",
)
DEFAULT_PERSIST_SIZE = "2G"
APP_KEY_FILE = "temenos_app_key"
APP_KEY_ENV_VAR = "VERITEE_APP_KEY"
ACR_NAME_ENV_VAR = "VERITEE_ACR_NAME"
GUEST_ATTESTATION_IMAGE_ENV_VAR = "VERITEE_GUEST_ATTESTATION_IMAGE"
DEFAULT_GUEST_ATTESTATION_IMAGE = "temenostest.azurecr.io/veritee/guest-attestation@sha256:9426ac1dce1c3501c70252ab37d9d591ebfaca252f853e31da747acf541d6b1a"
DEFAULT_ATTESTATION_DOMAIN_NAME = "attestation-endpoint.api.mydapp.midnight.io"
DAPP_CADDYFILE_TEMPLATE = Path("run.d/Caddyfile.template")
DAPP_DOCKER_COMPOSE = Path("run.d/docker-compose.yml")
APP_REGISTER_FILE_FIELDS = (
    ("caddyfile", DAPP_CADDYFILE_TEMPLATE),
    ("docker_compose", DAPP_DOCKER_COMPOSE),
)
APP_SOURCE_ROOT = Path("examples")
TLS_MODE_FILE = "tls_mode"
TLS_MODE_CHOICES = ("internal", "azure_vault")
TLS_MODE_DESCRIPTIONS = (
    ("internal", "Caddy tls internal; attestation includes the local root CA."),
    ("azure_vault", "Runtime-mounted Azure Vault certificates"),
)
TLS_FULLCHAIN_SECRET_NAME = "temenos-tls-fullchain-pem"
TLS_PRIVKEY_SECRET_NAME = "temenos-tls-privkey-pem"
PCRS_FILE = "pcrs.json"
POLICY_FILE = "policy.json"
POLICY_TEMPLATE_FILE = "policy.template.json"
DEFAULT_APP_DIR = Path("examples/dapp")
DAPP_OUTPUT_DIR = Path("local-azure-snp")
ACR_OS_ARTIFACT_PREFIX = "/temenos"
TERRAFORM_WORK_ROOT = Path(".temenos")
INVENTORY_STORAGE_ACCOUNT_ENV_VAR = "VERITEE_INVENTORY_STORAGE_ACCOUNT"
INVENTORY_CONTAINER_ENV_VAR = "VERITEE_INVENTORY_CONTAINER"
DEFAULT_INVENTORY_CONTAINER = "temenos-inventory"
DEFAULT_INVENTORY_RESOURCE_GROUP = "temenos-inventory-rg"
DEFAULT_INVENTORY_LOCATION = "eastus"
INVENTORY_COMPONENT_TAG = "temenos_component"
INVENTORY_COMPONENT_TAG_VALUE = "deployment-inventory"
INVENTORY_BLOB_DATA_ROLE = "Storage Blob Data Contributor"
VERITEE_MANAGED_TAG = "temenos_managed"
VERITEE_DEPLOYMENT_ID_TAG = "temenos_deployment_id"
AZURE_RESOURCE_GROUP_MAX_LENGTH = 90
AZURE_TAG_VALUE_MAX_LENGTH = 256


def write_app_metadata(output_dir: Path, metadata: dict) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / APP_METADATA_FILE
    output_path.write_text(json.dumps(metadata, indent=4, sort_keys=True) + "\n")
    return output_path


def resolve_app_source_dir(app_dir: Optional[Path] = None) -> Path:
    """Resolve caller paths before entering the checkout build context."""
    repository = repo_root_from_cwd().resolve()
    source = (Path(app_dir) if app_dir is not None else repository / DEFAULT_APP_DIR).resolve()
    if not source.is_dir():
        raise DeployerException(f"DApp source directory not found: {source}")
    staging_parent = repository / ".temenos" / "app-build"
    if repository.is_relative_to(source) or staging_parent.is_relative_to(source):
        raise DeployerException("App source must not contain the Veritee checkout or its build work directory")
    return source


@contextmanager
def app_build_context(app_dir: Optional[Path]) -> Iterator[Path]:
    source = resolve_app_source_dir(app_dir)
    repository = repo_root_from_cwd().resolve()
    previous_directory = Path.cwd()
    try:
        os.chdir(repository)
        yield source
    finally:
        os.chdir(previous_directory)


def build_from_checkout(command):
    """Keep Earthly, relative artifacts and output paths in one checkout context."""
    @wraps(command)
    def run(*args, **kwargs):
        arguments = signature(command).bind(*args, **kwargs)
        app_dir = arguments.arguments.get("app_dir")
        with app_build_context(Path(app_dir) if app_dir else None) as source:
            arguments.arguments["app_dir"] = source
            return command(*arguments.args, **arguments.kwargs)
    return run


@contextmanager
def prepared_app_build_source(
    app_dir: Path,
    *,
    tls_mode: str,
    tls_keyvault_name: Optional[str],
    app_container_image: Optional[str] = None,
    allow_warden_egress_profile: bool = False,
) -> Iterator[tuple[str, dict]]:
    """Stage an app source tree with its normalized, measured egress policy."""
    source_dir = resolve_app_source_dir(app_dir)
    if not source_dir.is_dir():
        raise DeployerException(f"DApp source directory not found: {app_dir}")

    metadata_path = source_dir / APP_METADATA_FILE
    source_metadata = load_json_file(metadata_path)
    load_app_metadata(metadata_path)
    if app_container_image is not None:
        source_metadata["app_container_image"] = app_container_image

    try:
        shipped_metadata = prepare_shipped_metadata(
            source_metadata,
            tls_mode=tls_mode,
            tls_keyvault_name=tls_keyvault_name,
            allow_warden_profile=allow_warden_egress_profile,
        )
    except OutboundPolicyError as exc:
        raise DeployerException(f"Invalid outbound policy in {metadata_path}: {exc}") from exc

    try:
        validate_compose_egress_boundary(
            source_dir / DAPP_DOCKER_COMPOSE,
            allow_warden_host_access=(
                shipped_metadata.get("egress_profile") == "warden"
            ),
        )
    except OutboundPolicyError as exc:
        raise DeployerException(
            f"Unsafe DApp Compose configuration in {source_dir / DAPP_DOCKER_COMPOSE}: {exc}"
        ) from exc

    repository = repo_root_from_cwd().resolve()
    staging_parent = repository / ".temenos" / "app-build"
    staging_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="source-", dir=staging_parent) as temporary_dir:
        staging_root = Path(temporary_dir)
        staged_dir = staging_root / "app"
        def exclude_unmeasured_paths(directory, names):
            parent = Path(directory).relative_to(source_dir)
            return {name for name in names if pack_validation.excluded_path((parent / name).as_posix())}

        shutil.copytree(
            source_dir, staged_dir, symlinks=True, ignore=exclude_unmeasured_paths
        )
        staged_metadata_path = write_app_metadata(staged_dir, shipped_metadata)
        os.utime(staged_metadata_path, (0, 0))
        yield str(staged_dir.relative_to(repository)), shipped_metadata


def validate_tls_mode(value: str) -> str:
    tls_mode = value.strip().lower().replace("-", "_")
    if tls_mode not in TLS_MODE_CHOICES:
        choices = ", ".join(TLS_MODE_CHOICES)
        raise typer.BadParameter(f"TLS mode must be one of: {choices}")

    return tls_mode


def prompt_tls_mode(value: Optional[str]) -> str:
    if value is not None:
        return validate_tls_mode(value)

    typer.echo("TLS modes:")
    for mode, description in TLS_MODE_DESCRIPTIONS:
        typer.echo(f"  {mode:<11} {description}")

    while True:
        try:
            return validate_tls_mode(typer.prompt("Select TLS mode", default="internal"))
        except typer.BadParameter as exc:
            typer.echo(str(exc), err=True)


def write_tls_mode(output_dir: Path, tls_mode: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / TLS_MODE_FILE
    output_path.write_text(f"{validate_tls_mode(tls_mode)}\n")

    return output_path


def read_tls_mode_file(path: Path) -> str:
    if not path.is_file():
        raise DeployerException(f"TLS mode file not found: {path}")

    return validate_tls_mode(path.read_text())


def resolve_attestation_tls_mode(
    value: Optional[str],
    artifact_dir: Path = DAPP_OUTPUT_DIR,
) -> str:
    if value is not None:
        return validate_tls_mode(value)

    mode_path = artifact_dir / TLS_MODE_FILE
    if not mode_path.is_file():
        raise DeployerException(
            f"Could not determine the deployed TLS mode: {mode_path} was not found. "
            "Pass --tls-mode internal or --tls-mode azure_vault."
        )

    tls_mode = read_tls_mode_file(mode_path)
    log.info("Using TLS mode from %s: %s", mode_path, tls_mode)
    return tls_mode


def default_tls_keyvault_name(app_name: str) -> str:
    slug = slugify_dapp_name(app_name)
    candidate = f"temenos-{slug}-tls"
    if len(candidate) <= 24:
        return candidate

    digest = hashlib.sha256(app_name.encode("utf-8")).hexdigest()[:6]
    prefix_len = 24 - len("temenos-") - len("-") - len(digest)
    short_slug = slug[:prefix_len].strip("-")
    if not short_slug:
        short_slug = "app"

    return f"temenos-{short_slug}-{digest}"


def default_tls_keyvault_resource_group(app_name: str) -> str:
    return f"temenos-{slugify_dapp_name(app_name)}-tls-rg"


def validate_tls_keyvault_name(value: str) -> str:
    name = value.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,22}[a-z0-9]", name):
        raise typer.BadParameter(
            "Azure Key Vault name must be 3-24 characters, start with a letter, "
            "end with a letter or digit, and contain only letters, digits, and hyphens"
        )
    if "--" in name:
        raise typer.BadParameter("Azure Key Vault name must not contain consecutive hyphens")

    return name


def resolve_tls_keyvault_name(
    *,
    tls_mode: str,
    app_name: str,
    value: Optional[str],
    prompt: bool,
) -> Optional[str]:
    if tls_mode != "azure_vault":
        if value is not None and value.strip():
            raise typer.BadParameter("--tls-keyvault-name can only be used with --tls-mode azure_vault")
        return None

    default_name = default_tls_keyvault_name(app_name)
    if value is None:
        if prompt:
            value = typer.prompt("Enter Azure Key Vault name", default=default_name)
        else:
            value = default_name

    return validate_tls_keyvault_name(value)


def resolve_packaging_tls_keyvault_name(
    *,
    tls_mode: str,
    app_dir: Path,
    app_name: str,
    value: Optional[str],
) -> Optional[str]:
    metadata_value = load_json_file(app_dir / APP_METADATA_FILE).get(
        "tls_keyvault_name"
    )
    if metadata_value is not None and not isinstance(metadata_value, str):
        raise DeployerException("metadata tls_keyvault_name must be a string")
    if value is None:
        value = metadata_value
    return resolve_tls_keyvault_name(
        tls_mode=tls_mode,
        app_name=app_name,
        value=value,
        prompt=False,
    )


def local_registration_profile() -> dict:
    return pack_validation.local_profile(repo_root_from_cwd(), DEFAULT_GUEST_ATTESTATION_IMAGE)


def validate_dapp_packaging(
    app_dir: Path, metadata: dict, *, tls_mode: str, tls_keyvault_name: Optional[str],
    guest_image: str, registration_preflight: bool = True, allow_warden: bool = False,
    profile: Optional[dict] = None, selected_os: Optional[dict] = None,
) -> dict:
    """Pure input validation. No image pull, build, key creation or Azure write."""
    profile = profile or local_registration_profile()
    try:
        pack_validation.require_pinned_image(metadata["app_container_image"], "app_container_image")
        pack_validation.require_pinned_image(metadata["base_os_image"], "base_os_image")
        pack_validation.require_pinned_image(guest_image, "guest_attestation_image")
        for field in ("name", "app_container_image", "base_os_image"):
            if len(metadata[field].strip()) > AZURE_TAG_VALUE_MAX_LENGTH:
                raise ValueError(f"Azure deployment tag derived from {field} exceeds {AZURE_TAG_VALUE_MAX_LENGTH} characters")
        shipped = prepare_shipped_metadata(
            load_json_file(app_dir / APP_METADATA_FILE), tls_mode=tls_mode,
            tls_keyvault_name=tls_keyvault_name, allow_warden_profile=allow_warden,
        )
        validate_compose_egress_boundary(
            app_dir / DAPP_DOCKER_COMPOSE,
            allow_warden_host_access=shipped.get("egress_profile") == "warden",
        )
        source = pack_validation.source_tree(app_dir)
        if registration_preflight:
            pack_validation.validate_rebuild(
                app_dir, repo_root_from_cwd() / "veritee-os/app-disk", profile, guest_image,
                shipped.get("egress_profile") == "warden",
                repo_root_from_cwd(),
            )
            caddyfile = read_required_text_file(app_dir / DAPP_CADDYFILE_TEMPLATE, "Caddyfile template")
            guest_sites = pack_validation.guest_site_addresses(caddyfile)
            if len(guest_sites) < 2:
                raise ValueError("The guest launcher requires two separate Caddy site blocks: attestation first, API second (LF site headers)")
            guest_hosts = [validate_attestation_domain_name(host) for host in guest_sites[:2]]
            if caddyfile_site_hosts(caddyfile)[:2] != guest_hosts:
                raise ValueError("CLI and guest disagree on Caddy site hosts; use one bare domain per site header")
            address = f"https://{guest_hosts[1]}" if tls_mode != "internal" else "http://255.255.255.255"
            version = selected_os["entry"]["release_version"] if selected_os else metadata.get("base_os_version", "")
            if selected_os and metadata.get("base_os_version", version) != version:
                raise ValueError("metadata.base_os_version disagrees with the selected OS release")
            projected = pack_validation.projection(
                metadata, address, guest_hosts[0], tls_mode, version=version,
                os_key=selected_os["os_key"] if selected_os else "0" * 64,
            )
            pack_validation.validate_projection(projected, profile)
        return {"profile": profile, "source": source, "shipped_metadata": shipped}
    except (ValueError, UnicodeError, OSError, OutboundPolicyError) as error:
        raise DeployerException(f"DApp packaging validation failed: {error}") from error


@app.command("validate-dapp", rich_help_panel=COMMAND_PANEL_IMAGES)
def validate_dapp(
    app_dir: Annotated[Optional[Path], typer.Option(help="Application directory to validate; defaults to examples/dapp in the checkout")] = None,
    tls_mode: Annotated[str, typer.Option(help="TLS mode used for packaging")] = "internal",
    tls_keyvault_name: Annotated[Optional[str], typer.Option(help="Runtime TLS vault name, when using azure_vault")] = None,
    guest_attestation_image: Annotated[Optional[str], typer.Option(help="Guest attestation image used for packaging")] = None,
    allow_warden_egress_profile: Annotated[bool, typer.Option(help="Validate an operator Warden image's explicit egress profile")] = False,
    registration_preflight: Annotated[bool, typer.Option("--registration-preflight/--no-registration-preflight", help="Check compatibility with Warden's fixed app-disk rebuild recipe")] = True,
):
    """Validate package inputs without downloading images or building a disk."""
    app_dir = resolve_app_source_dir(app_dir)
    metadata = load_app_source_metadata(app_dir)
    mode = validate_tls_mode(tls_mode)
    vault = resolve_packaging_tls_keyvault_name(
        tls_mode=mode, app_dir=app_dir, app_name=metadata["name"], value=tls_keyvault_name
    )
    helper_image = resolve_guest_attestation_image(guest_attestation_image)
    profile = local_registration_profile()
    validate_dapp_packaging(
        app_dir, metadata, tls_mode=mode, tls_keyvault_name=vault, guest_image=helper_image,
        registration_preflight=registration_preflight, allow_warden=allow_warden_egress_profile,
        profile=profile,
    )
    typer.echo(json.dumps({
        "valid": True, "registration_preflight": registration_preflight,
        "scope": "local_inputs", "os_registry_checked": False,
        "azure_vault_availability_checked": False,
    }, indent=2))


def resolve_app_metadata_path(path: Optional[Path]) -> Path:
    if path is not None:
        return path

    default_path = repo_root_from_cwd() / DAPP_OUTPUT_DIR / APP_METADATA_FILE
    if not default_path.exists():
        raise DeployerException(
            f"DApp metadata not found. Add {DEFAULT_APP_DIR / APP_METADATA_FILE} "
            "or run package-dapp-deployable-vm-image first."
        )

    return default_path


def load_app_metadata(path: Path) -> dict:
    metadata = load_json_file(path)

    invalid_fields = [
        field
        for field in APP_METADATA_FIELDS
        if not isinstance(metadata.get(field), str)
    ]
    if invalid_fields:
        raise DeployerException(
            f"Missing or invalid field(s) in {path}: {', '.join(invalid_fields)}"
        )

    missing_fields = [
        field
        for field in APP_METADATA_REQUIRED_FIELDS
        if not metadata[field].strip()
    ]
    if missing_fields:
        raise DeployerException(
            f"Missing required field(s) in {path}: {', '.join(missing_fields)}"
        )

    result = {field: metadata[field] for field in APP_METADATA_FIELDS}

    if "proxy_allowed_paths" in metadata:
        try:
            result["proxy_allowed_paths"] = validate_proxy_allowed_paths(metadata)
        except ValueError as error:
            raise DeployerException(f"Invalid proxy_allowed_paths in {path}: {error}") from error

    deployable_vm_image = metadata.get("deployable_vm_image")
    if isinstance(deployable_vm_image, str) and deployable_vm_image.strip():
        result["deployable_vm_image"] = deployable_vm_image

    base_os_version = metadata.get("base_os_version")
    if base_os_version is not None:
        if not isinstance(base_os_version, str) or not base_os_version.strip():
            raise DeployerException(f"Invalid optional field in {path}: base_os_version")
        result["base_os_version"] = base_os_version.strip()

    persist_size = metadata.get("persist_size")
    if persist_size is not None:
        if not isinstance(persist_size, str) or not re.fullmatch(
            r"[1-9][0-9]*[KMGT]?", persist_size
        ):
            raise DeployerException(
                f"Invalid optional field in {path}: persist_size must look like "
                "2G, 4096M, or 1048576K"
            )
        result["persist_size"] = persist_size

    return result


def resolve_persist_size(value: Optional[str], metadata: dict) -> str:
    resolved = value if value is not None else metadata.get("persist_size")
    if resolved is None:
        resolved = DEFAULT_PERSIST_SIZE
    if not isinstance(resolved, str) or not re.fullmatch(
        r"[1-9][0-9]*[KMGT]?", resolved
    ):
        raise typer.BadParameter(
            "--persist-size must look like 2G, 4096M, or 1048576K"
        )
    return resolved


def load_app_source_metadata(app_dir: Path) -> dict:
    metadata_path = app_dir / APP_METADATA_FILE
    if not metadata_path.exists():
        raise DeployerException(
            f"Missing DApp metadata at {metadata_path}. "
            "Set name, description, app_container_image, and base_os_image in that file."
        )

    return load_app_metadata(metadata_path)


def load_tls_vault_metadata(app_dir: Path) -> tuple[Path, dict]:
    metadata_path = app_dir / APP_METADATA_FILE
    if not metadata_path.is_file():
        raise DeployerException(f"DApp metadata not found: {metadata_path}")

    return metadata_path, load_app_metadata(metadata_path)


def read_required_text_file(path: Path, description: str) -> str:
    if not path.is_file():
        raise DeployerException(f"Required {description} not found: {path}")

    return pack_validation.exact_text(path)


def load_register_app_disk_files(app_dir: Path) -> dict:
    return {
        "caddyfile": read_required_text_file(
            app_dir / DAPP_CADDYFILE_TEMPLATE,
            "DApp Caddyfile template",
        ),
        "docker_compose": read_required_text_file(
            app_dir / DAPP_DOCKER_COMPOSE,
            "DApp docker-compose.yml",
        ),
    }


def has_register_app_files(app_dir: Path) -> bool:
    return all((app_dir / relative_path).is_file() for _, relative_path in APP_REGISTER_FILE_FIELDS)


def find_app_dirs_matching_metadata(metadata_file: Path) -> list[Path]:
    source_root = repo_root_from_cwd() / APP_SOURCE_ROOT
    if not source_root.is_dir():
        return []

    expected_metadata = load_app_metadata(metadata_file)
    matches = []
    for candidate_dir in sorted(source_root.iterdir()):
        candidate_metadata_path = candidate_dir / APP_METADATA_FILE
        if not candidate_dir.is_dir() or not candidate_metadata_path.is_file():
            continue

        try:
            candidate_metadata = load_app_metadata(candidate_metadata_path)
        except DeployerException:
            continue

        if candidate_metadata == expected_metadata:
            matches.append(candidate_dir)

    return matches


def resolve_register_app_source_dir(metadata_file: Path, app_dir: Optional[Path]) -> Path:
    if app_dir is not None:
        return resolve_app_source_dir(app_dir)

    if has_register_app_files(metadata_file.parent):
        return metadata_file.parent

    matching_app_dirs = [
        candidate_dir
        for candidate_dir in find_app_dirs_matching_metadata(metadata_file)
        if has_register_app_files(candidate_dir)
    ]

    if len(matching_app_dirs) == 1:
        return matching_app_dirs[0]

    if len(matching_app_dirs) > 1:
        matches = ", ".join(str(path) for path in matching_app_dirs)
        raise DeployerException(
            f"Found multiple DApp source directories matching {metadata_file}: {matches}. "
            "Pass --app-dir with the DApp source directory used for packaging."
        )

    raise DeployerException(
        f"Could not resolve DApp source directory for {metadata_file}. "
        "Pass --app-dir with the DApp source directory used for packaging."
    )


def add_register_app_file_fields(payload: dict, app_source_dir: Path) -> list[Path]:
    included_files = []
    for field_name, relative_path in APP_REGISTER_FILE_FIELDS:
        source_path = app_source_dir / relative_path
        if not source_path.is_file():
            raise DeployerException(f"Required DApp app-disk file not found: {source_path}")

        payload[field_name] = read_required_text_file(source_path, relative_path.as_posix())
        included_files.append(source_path)

    return included_files


def read_register_app_metadata_json(metadata_file: Path, app_source_dir: Path) -> str:
    source_metadata_path = app_source_dir / APP_METADATA_FILE
    if not source_metadata_path.is_file():
        raise DeployerException(f"Required DApp metadata file not found: {source_metadata_path}")

    packaged_metadata = load_app_metadata(metadata_file)
    source_metadata = load_app_metadata(source_metadata_path)
    if source_metadata != packaged_metadata:
        raise DeployerException(
            f"DApp source metadata at {source_metadata_path} does not match {metadata_file}. "
            "Pass the app source directory used to build the selected deployable VM image."
        )

    # Registration must replay the exact policy measured into the app disk,
    # including normalized application and generated platform destinations.
    return pack_validation.exact_text(metadata_file)


def resolve_register_tls_mode(
    metadata_file: Path,
    app_source_dir: Path,
    tls_mode: Optional[str],
) -> str:
    if tls_mode is not None:
        resolved_tls_mode = validate_tls_mode(tls_mode)
    else:
        packaged_tls_mode_path = metadata_file.parent / TLS_MODE_FILE
        if packaged_tls_mode_path.is_file():
            resolved_tls_mode = read_tls_mode_file(packaged_tls_mode_path)
        else:
            resolved_tls_mode = prompt_tls_mode(None)

    source_tls_mode_path = app_source_dir / "run.d/.temenos-tls-mode"
    if source_tls_mode_path.is_file():
        source_tls_mode = read_tls_mode_file(source_tls_mode_path)
        if source_tls_mode != resolved_tls_mode:
            raise DeployerException(
                f"TLS mode mismatch: {source_tls_mode_path} is {source_tls_mode}, "
                f"but registration is using {resolved_tls_mode}."
            )

    return resolved_tls_mode


def register_caddyfile_hosts(app_source_dir: Path) -> list[str]:
    return caddyfile_site_hosts(app_source_dir / DAPP_CADDYFILE_TEMPLATE)


def resolve_deployment_attestation_domain(
    metadata_file: Path,
    attestation_domain_name: Optional[str],
) -> str:
    if attestation_domain_name is not None:
        return validate_attestation_domain_name(attestation_domain_name)

    app_source_dir = resolve_register_app_source_dir(metadata_file, None)
    hosts = register_caddyfile_hosts(app_source_dir)
    if not hosts:
        raise DeployerException(
            "Could not derive the attestation endpoint domain from the DApp Caddyfile. "
            "Pass --attestation-domain-name or use --no-hydrate-policy."
        )

    return validate_attestation_domain_name(hosts[0])


def resolve_optional_deployment_attestation_domain(
    metadata_file: Path,
    attestation_domain_name: Optional[str],
) -> Optional[str]:
    if attestation_domain_name is not None:
        return validate_attestation_domain_name(attestation_domain_name)

    try:
        return resolve_deployment_attestation_domain(metadata_file, None)
    except DeployerException as exc:
        log.warning(
            "Could not infer the attestation endpoint domain from the packaged DApp; "
            "skipping automatic policy hydration. Pass --attestation-domain-name to enable it."
        )
        log.debug("Attestation domain inference failed: %s", exc)
        return None


def default_attestation_domain_from_caddyfile(caddyfile: str) -> Optional[str]:
    hosts = caddyfile_site_hosts(caddyfile)
    if not hosts:
        return None

    return hosts[0]


def default_register_address(tls_mode: str, app_source_dir: Path) -> Optional[str]:
    if tls_mode == "internal":
        return None

    hosts = register_caddyfile_hosts(app_source_dir)
    if len(hosts) >= 2:
        return f"https://{hosts[1]}"
    if hosts:
        return f"https://{hosts[0]}"

    return None


def default_register_attestation_domain(tls_mode: str, app_source_dir: Path) -> Optional[str]:
    if tls_mode != "internal":
        hosts = register_caddyfile_hosts(app_source_dir)
        if hosts:
            return hosts[0]
        return None

    return DEFAULT_ATTESTATION_DOMAIN_NAME


def resolve_register_address(
    tls_mode: str,
    app_source_dir: Path,
    address: Optional[str],
) -> str:
    if tls_mode == "internal":
        return prompt_required_value(
            "Enter DApp VM IP address or base URL",
            address,
            "DApp address",
        )

    if address is not None:
        return prompt_required_value(
            "Enter DApp API endpoint URL",
            address,
            "DApp address",
        )

    derived_address = default_register_address(tls_mode, app_source_dir)
    if derived_address is None:
        raise DeployerException(
            "Could not derive DApp API endpoint URL from run.d/Caddyfile.template. "
            "Expected at least one Caddy site. For two-site configurations, the first "
            "is the attestation host and the second is the API host; a single site "
            "serves both. Pass --address=https://<api-domain> to override."
        )

    log.info("Using DApp API endpoint from Caddyfile: %s", derived_address)
    return derived_address


def resolve_register_attestation_domain(
    tls_mode: str,
    app_source_dir: Path,
    attestation_domain_name: Optional[str],
) -> str:
    if attestation_domain_name is not None:
        return validate_attestation_domain_name(attestation_domain_name)

    default_domain = default_register_attestation_domain(tls_mode, app_source_dir)
    if tls_mode == "internal":
        return validate_attestation_domain_name(
            typer.prompt(
                "Enter attestation endpoint domain name",
                default=default_domain,
            )
        )

    if default_domain is None:
        raise DeployerException(
            "Could not derive attestation endpoint domain from run.d/Caddyfile.template. "
            "Expected the first Caddy site to be the attestation host. "
            "Pass --attestation-domain-name=<domain> to override."
        )

    log.info("Using attestation endpoint domain from Caddyfile: %s", default_domain)
    return validate_attestation_domain_name(default_domain)


def prompt_required_value(
    prompt: str,
    value: Optional[str],
    field_name: str,
    default: Optional[str] = None,
) -> str:
    if value is None:
        value = typer.prompt(prompt, default=default) if default else typer.prompt(prompt)

    value = value.strip()
    if not value:
        raise typer.BadParameter(f"{field_name} cannot be empty")

    return value


def prompt_existing_file(prompt: str, value: Optional[Path], default: Path, field_name: str) -> Path:
    path = value
    while path is None or not path.is_file():
        if path is not None and not path.is_file():
            typer.echo(f"{field_name} file not found: {path}", err=True)
        path = Path(typer.prompt(prompt, default=str(default)))

    return path


def validate_app_key(value: str, source: str) -> str:
    value = value.strip()
    if not value:
        raise typer.BadParameter(f"Veritee app key from {source} cannot be empty")

    return value


def resolve_app_key(metadata_file: Path, value: Optional[str]) -> str:
    if value is not None:
        return validate_app_key(value, "--app-key")

    env_value = os.getenv(APP_KEY_ENV_VAR)
    if env_value is not None:
        return validate_app_key(env_value, APP_KEY_ENV_VAR)

    key_path = metadata_file.parent / APP_KEY_FILE
    if key_path.exists():
        return validate_app_key(key_path.read_text(), str(key_path))

    key = secrets.token_hex(32)
    key_path.write_text(key + "\n")
    os.chmod(key_path, 0o600)
    log.info("Generated Veritee app key at %s", key_path)

    return key


def load_available_app_name(*metadata_dirs: Path) -> Optional[str]:
    seen = set()
    for metadata_dir in metadata_dirs:
        metadata_path = metadata_dir / APP_METADATA_FILE
        if metadata_path in seen:
            continue
        seen.add(metadata_path)

        if not metadata_path.exists():
            continue

        try:
            name = load_app_metadata(metadata_path)["name"]
        except DeployerException:
            continue

        if name:
            return name

    return None


def load_optional_metadata(metadata_dir: Path) -> dict:
    metadata_path = metadata_dir / APP_METADATA_FILE
    if not metadata_path.exists():
        return {}

    try:
        load_app_metadata(metadata_path)
        return load_json_file(metadata_path)
    except DeployerException as exc:
        log.debug("Ignoring invalid deployment metadata at %s: %s", metadata_path, exc)
        return {}


def write_os_security_files(
    output_dir: Path,
    pcrs_path: Path,
    policy_template_path: Optional[Path] = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    copied_pcrs_path = copy_file_if_needed(pcrs_path, output_dir / PCRS_FILE)
    if policy_template_path is not None:
        copy_file_if_needed(policy_template_path, output_dir / POLICY_FILE)
    return copied_pcrs_path


def resolve_security_files(metadata_file: Path) -> tuple[Path, Path]:
    for candidate_dir in (
        metadata_file.parent,
        DEFAULT_OS_DISK_DIR,
    ):
        pcrs_path = candidate_dir / PCRS_FILE
        policy_path = candidate_dir / POLICY_FILE
        if pcrs_path.exists() and policy_path.exists():
            return pcrs_path, policy_path

    raise DeployerException(
        f"Could not find colocated {PCRS_FILE} and {POLICY_FILE}. "
        "Run package-dapp-deployable-vm-image first, then hydrate the policy "
        "from a deployed VM if required."
    )


DEFAULT_OS_DISK_VERSION = "0.1.0"
DEFAULT_OS_DISK_DIR = Path("local-base-os")


def require_acr_name() -> str:
    acr_name = os.getenv(ACR_NAME_ENV_VAR, "").strip()
    if not acr_name:
        raise DeployerException(
            f"{ACR_NAME_ENV_VAR} must be set to your Azure Container Registry name."
        )

    return acr_name


def require_azure_subscription_id() -> str:
    subscription_id = os.getenv("ARM_SUBSCRIPTION_ID", "").strip()
    if not subscription_id:
        raise DeployerException(
            "ARM_SUBSCRIPTION_ID environment variable is not set. "
            "Set it to your Azure subscription ID and try again."
        )

    return subscription_id


def validate_inventory_storage_account(value: str) -> str:
    account = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9]{3,24}", account):
        raise DeployerException(
            f"{INVENTORY_STORAGE_ACCOUNT_ENV_VAR} must be a 3-24 character "
            "lowercase Azure Storage account name."
        )

    return account


def validate_inventory_container(value: str) -> str:
    container = value.strip().lower()
    if (
        not 3 <= len(container) <= 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?", container)
        or "--" in container
    ):
        raise DeployerException(
            f"{INVENTORY_CONTAINER_ENV_VAR} must be a valid 3-63 character "
            "lowercase Azure Blob container name."
        )

    return container


def require_inventory_storage(subscription_id: str) -> tuple[str, str]:
    account = os.getenv(INVENTORY_STORAGE_ACCOUNT_ENV_VAR, "").strip()
    if not account:
        accounts = query_inventory_storage_accounts(subscription_id)
        if not accounts:
            raise DeployerException(
                "No Veritee inventory Storage account was found. "
                "Run `veritee init-inventory` once, or set "
                f"{INVENTORY_STORAGE_ACCOUNT_ENV_VAR} to an existing account."
            )
        if len(accounts) > 1:
            names = ", ".join(sorted(str(item["name"]) for item in accounts))
            raise DeployerException(
                "Multiple Veritee inventory Storage accounts were found "
                f"({names}). Set {INVENTORY_STORAGE_ACCOUNT_ENV_VAR} explicitly."
            )
        account = str(accounts[0]["name"])

    container = os.getenv(
        INVENTORY_CONTAINER_ENV_VAR,
        DEFAULT_INVENTORY_CONTAINER,
    )
    return (
        validate_inventory_storage_account(account),
        validate_inventory_container(container),
    )


def default_inventory_storage_account(subscription_id: str) -> str:
    suffix = hashlib.sha256(subscription_id.encode("utf-8")).hexdigest()[:14]
    return f"temenosinv{suffix}"


def acr_registry(acr_name: str) -> str:
    return f"{acr_name}.azurecr.io"


def slugify_dapp_name(name: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    if not slug:
        raise DeployerException("DApp name must contain at least one alphanumeric character")

    return slug


def utc_timestamp(value: Optional[datetime] = None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return (
        current.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def generate_deployment_id(
    app_name: str,
    *,
    created_at: Optional[datetime] = None,
    random_suffix: Optional[str] = None,
) -> str:
    current = created_at or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    timestamp = current.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ").lower()
    suffix = random_suffix or secrets.token_hex(4)
    if not re.fullmatch(r"[a-z0-9]{4,16}", suffix):
        raise ValueError("deployment id suffix must contain 4-16 lowercase letters or digits")

    app_slug = truncate_resource_name(azure_resource_slug(app_name), 44)
    return f"{app_slug}-{timestamp}-{suffix}"


def default_deployment_resource_group(deployment_id: str) -> str:
    return f"{truncate_resource_name(deployment_id, AZURE_RESOURCE_GROUP_MAX_LENGTH - 3)}-rg"


def image_ref_digest(image_ref: object) -> Optional[str]:
    if not isinstance(image_ref, str):
        return None

    match = re.search(r"@(?P<algorithm>sha256):(?P<digest>[0-9a-fA-F]{64})$", image_ref.strip())
    if match is None:
        return None

    return f"{match.group('algorithm')}:{match.group('digest').lower()}"


def validate_sha256_hex(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()):
        raise DeployerException(f"{field_name} must be a 64-character SHA-256 digest")

    return value.strip().lower()


def current_git_sha(repo_root: Path) -> str:
    result = run_checked(["git", "rev-parse", "HEAD"], cwd=repo_root)
    sha = result.stdout.strip().lower()
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", sha):
        raise DeployerException("Could not determine the checkout's git commit")

    return sha


def build_deployment_tags(
    *,
    metadata: dict,
    application_root_hash: str,
    deployment_id: str,
    vm_name: str,
    created_at: str,
    git_sha: str,
    tls_mode: str,
    tls_keyvault_name: Optional[str],
) -> dict[str, str]:
    tags = {
        VERITEE_MANAGED_TAG: "true",
        VERITEE_DEPLOYMENT_ID_TAG: deployment_id,
        "temenos_app_name": metadata["name"].strip(),
        "temenos_app_image": str(metadata.get("app_container_image") or "").strip(),
        "temenos_base_os_image": str(metadata.get("base_os_image") or "").strip(),
        "temenos_vm_name": vm_name,
        "temenos_created_at": created_at,
        "temenos_app_root_hash": validate_sha256_hex(
            application_root_hash,
            "application_root_hash",
        ),
        "temenos_git_sha": git_sha,
        "temenos_tls_mode": validate_tls_mode(tls_mode),
    }

    app_digest = image_ref_digest(metadata.get("app_container_image"))
    if app_digest is not None:
        tags["temenos_app_image_digest"] = app_digest

    os_digest = image_ref_digest(metadata.get("base_os_image"))
    if os_digest is not None:
        tags["temenos_os_image_digest"] = os_digest

    if tls_keyvault_name:
        tags["temenos_tls_keyvault_name"] = tls_keyvault_name

    for key, value in tags.items():
        if not value:
            raise DeployerException(f"Azure deployment tag {key} cannot be empty")
        if len(value) > AZURE_TAG_VALUE_MAX_LENGTH:
            raise DeployerException(
                f"Azure deployment tag {key} exceeds {AZURE_TAG_VALUE_MAX_LENGTH} characters"
            )

    return tags


def resolve_deployment_option(
    value: Optional[str],
    *,
    option_name: str,
    prompt: str,
    default: str,
) -> str:
    if value is None:
        if not sys.stdin.isatty():
            raise typer.BadParameter(
                f"{option_name} is required when stdin is not a TTY"
            )
        value = typer.prompt(prompt, default=default)

    resolved = value.strip()
    if not resolved:
        raise typer.BadParameter(f"{option_name} cannot be empty")

    return resolved


def resolve_vm_size(value: Optional[str]) -> str:
    if value is None:
        if sys.stdin.isatty():
            value = typer.prompt(
                "Enter Azure VM size",
                default=DEFAULT_AZURE_VM_SIZE,
            )
        else:
            value = DEFAULT_AZURE_VM_SIZE

    resolved = value.strip()
    if not resolved:
        raise typer.BadParameter("--vm-size cannot be empty")

    return resolved


def truncate_resource_name(value: str, max_length: int, separator: str = "-") -> str:
    truncated = value[:max_length].rstrip(separator)
    return truncated or "app"


def azure_resource_slug(app_name: str) -> str:
    return re.sub(r"-+", "-", slugify_dapp_name(app_name)).strip("-")


def default_vm_name_for_app(app_name: str) -> str:
    slug = azure_resource_slug(app_name)
    return f"temenos-{truncate_resource_name(slug, 53)}-vm"


def default_gallery_name_for_app(app_name: str) -> str:
    slug = azure_resource_slug(app_name).replace("-", "_")
    return f"temenos_{truncate_resource_name(slug, 48, '_')}_gallery"


def resolve_deployable_vm_image(metadata: dict, acr_name: str) -> str:
    if "deployable_vm_image" in metadata:
        return metadata["deployable_vm_image"]

    registry = acr_registry(acr_name)
    slug = slugify_dapp_name(metadata["name"])
    return f"{registry}/deployable-vm/{slug}:{DEFAULT_OS_DISK_VERSION}"


def resolve_base_os_image(acr_name: str, version: str) -> str:
    return f"{acr_registry(acr_name)}/temenos/base-os:{version}"


def resolve_guest_attestation_image(
    value: Optional[str],
) -> str:
    if value is not None:
        value = value.strip()
        if not value:
            raise typer.BadParameter("guest-attestation-image cannot be empty")
        return value

    env_value = os.getenv(GUEST_ATTESTATION_IMAGE_ENV_VAR, "").strip()
    if env_value:
        return env_value

    return DEFAULT_GUEST_ATTESTATION_IMAGE


def infer_acr_name_from_image_ref(image_ref: str) -> Optional[str]:
    match = re.match(r"^([^./]+)\.azurecr\.io/", image_ref.strip())
    if match is None:
        return None

    return match.group(1)


def resolve_acr_name_for_packaging(metadata: dict, *, required: bool = True) -> str:
    acr_name = os.getenv(ACR_NAME_ENV_VAR, "").strip()
    if acr_name:
        return acr_name

    for image_ref in (
        metadata.get("deployable_vm_image"),
        metadata.get("base_os_image"),
        metadata.get("app_container_image"),
    ):
        if not isinstance(image_ref, str):
            continue
        inferred = infer_acr_name_from_image_ref(image_ref)
        if inferred is not None:
            return inferred

    if required:
        raise DeployerException(
            f"{ACR_NAME_ENV_VAR} must be set to your Azure Container Registry name."
        )

    return "<acr-name>"


def deployable_vm_push_artifacts() -> List[str]:
    artifacts = [
        "disk.raw",
        "disk.img.vhd",
        "disk.img.vhd.source-raw.sha256",
        "disk.img.vhd.sha256",
        "disk.manifest",
        PCRS_FILE,
        APP_METADATA_FILE,
        TLS_MODE_FILE,
    ]
    if (DAPP_OUTPUT_DIR / pack_validation.SNAPSHOT_FILE).is_file():
        artifacts.append(pack_validation.SNAPSHOT_FILE)
    return artifacts


def base_os_push_artifacts() -> List[str]:
    return [
        "disk.raw",
        PCRS_FILE,
    ]


def build_earthly_base_os_command(
    *,
    os_config: str,
    attestation_mode: AttestationMode,
    allow_unbound_attestation: bool,
) -> List[str]:
    return [
        "earthly",
        "--no-cache",
        "-P",
        "+veritee-os-azure-snp",
        f"--OS_CONFIG={os_config}",
        f"--ATTESTATION_MODE={attestation_mode.value}",
        f"--ALLOW_UNBOUND_ATTESTATION={str(allow_unbound_attestation).lower()}",
    ]


def validate_unbound_attestation_build(
    *, debug: bool, allow_unbound_attestation: bool
) -> None:
    if allow_unbound_attestation and not debug:
        raise typer.BadParameter(
            "--allow-unbound-attestation requires --debug; release images always require nonce-bound evidence"
        )


GIB = 1024**3
PUBLISH_SPACE_SAFETY_BYTES = 2 * GIB


def format_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{num_bytes} B"
        value /= 1024

    return f"{num_bytes} B"


def artifact_payload_size(artifact_dir: Path, artifact_files: List[str]) -> int:
    total = 0
    for name in artifact_files:
        source_path = artifact_dir / name
        if not source_path.exists():
            raise DeployerException(f"Missing artifact for ACR push: {source_path}")
        total += source_path.stat().st_size

    return total


def ensure_publish_disk_space(artifact_dir: Path, artifact_files: List[str]) -> None:
    """Fail early when Docker cannot reasonably ingest the publish payload.

    The publish step builds a scratch image containing all deployable artifacts.
    BuildKit commonly stores both a local source snapshot and image layers, so
    a 12 GiB payload can need roughly twice that amount before push cleanup.
    """
    payload_size = artifact_payload_size(artifact_dir, artifact_files)
    required_bytes = (payload_size * 2) + PUBLISH_SPACE_SAFETY_BYTES

    check_path = Path("/var/lib/docker")
    if not check_path.exists():
        check_path = artifact_dir

    free_bytes = shutil.disk_usage(check_path).free
    if free_bytes >= required_bytes:
        return

    raise DeployerException(
        "Not enough free disk space for the ACR publish step. "
        f"Artifacts to package: {format_size(payload_size)}; estimated free "
        f"space needed by Docker/BuildKit: {format_size(required_bytes)}; "
        f"available on {check_path}: {format_size(free_bytes)}. "
        "Free Docker/build cache space or run with --no-push after packaging."
    )


EARTHLY_EXTEND_OS_TARGET = "veritee-os-azure-snp-extend-os"
EARTHLY_APP_DISK_TARGET = "dapp-appdisk"
# Secret names the deployer supplies to Earthly via --secret flags. Docker Hub
# values are empty when credentials are omitted, which lets pulls proceed
# anonymously without weakening the required ACR authentication path.
EARTHLY_CLI_SECRET_NAMES: FrozenSet[str] = frozenset(
    {"acr_token", "dockerhub_user", "dockerhub_token"}
)
# Names documented in the top-level README's environment-variable table.
DOCKERHUB_USER_ENV_VAR = "DOCKERHUB_USER"
DOCKERHUB_TOKEN_ENV_VAR = "DOCKERHUB_TOKEN"


def dockerhub_env_secrets() -> Dict[str, str]:
    """Read optional Docker Hub credentials from the environment.

    Returns Earthly secret name → value, empty when the env vars are unset.
    The token should be a read-only Docker Hub personal access token, not the
    account password.
    """
    user = os.getenv(DOCKERHUB_USER_ENV_VAR, "").strip()
    token = os.getenv(DOCKERHUB_TOKEN_ENV_VAR, "").strip()
    if bool(user) != bool(token):
        raise DeployerException(
            f"Set both {DOCKERHUB_USER_ENV_VAR} and {DOCKERHUB_TOKEN_ENV_VAR}, "
            "or neither."
        )
    if not user:
        return {}
    return {"dockerhub_user": user, "dockerhub_token": token}


def cli_secret_names() -> FrozenSet[str]:
    """All Earthly secret names the deployer can supply in this environment."""
    dockerhub_env_secrets()
    return EARTHLY_CLI_SECRET_NAMES


def earthly_dockerhub_secrets() -> Dict[str, str]:
    """Return both Earthly secrets, using empty values for anonymous pulls."""
    return dockerhub_env_secrets() or {
        "dockerhub_user": "",
        "dockerhub_token": "",
    }


def warn_if_anonymous_dockerhub_pull() -> None:
    if not dockerhub_env_secrets():
        log.warning(
            "%s/%s are not set; Docker Hub pulls will be anonymous and may "
            "be rate-limited.",
            DOCKERHUB_USER_ENV_VAR,
            DOCKERHUB_TOKEN_ENV_VAR,
        )


def secret_flags(secret_values: Dict[str, str]) -> List[str]:
    flags: List[str] = []
    for name, value in secret_values.items():
        flags.extend(["--secret", f"{name}={value}"])
    return flags

_EARTHFILE_TARGET_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*):\s*(?:#.*)?$")
_EARTHFILE_SECRET_RE = re.compile(
    r"--secret[= ]+(?:[A-Za-z_][A-Za-z0-9_]*=)?([A-Za-z0-9._/+-]+)"
)


def _earthfile_target_lines(target: str, earthfile: Path) -> List[str]:
    """Return the logical lines of one Earthfile target's body.

    Backslash continuations are joined into single lines. Scans only the named
    target's own body, not targets it builds FROM or functions it calls with
    DO.
    """
    if not earthfile.is_file():
        raise DeployerException(
            f"Earthfile not found at {earthfile}. "
            "Run this command from the veritee repository root."
        )

    lines: List[str] = []
    in_target = False
    pending = ""
    for line in earthfile.read_text().splitlines():
        target_match = _EARTHFILE_TARGET_RE.match(line)
        if target_match:
            in_target = target_match.group(1) == target
            pending = ""
            continue
        if not in_target:
            continue
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        lines.append(pending + line)
        pending = ""

    return lines


def earthfile_target_secrets(target: str, earthfile: Path) -> Set[str]:
    """Return the secret names referenced by one Earthfile target."""
    secret_names: Set[str] = set()
    for line in _earthfile_target_lines(target, earthfile):
        for secret_match in _EARTHFILE_SECRET_RE.finditer(line):
            secret_names.add(secret_match.group(1).removeprefix("+secrets/"))

    return secret_names


_EARTHFILE_COPY_RE = re.compile(r"^\s*COPY\s+(.+)$")


def earthfile_target_copy_sources(target: str, earthfile: Path) -> List[str]:
    """Return the COPY source tokens of one Earthfile target.

    Flag tokens (--dir, --chmod=..., ...) are dropped; the final token of each
    COPY is its destination, everything before it is a source.
    """
    sources: List[str] = []
    for line in _earthfile_target_lines(target, earthfile):
        copy_match = _EARTHFILE_COPY_RE.match(line)
        if not copy_match:
            continue
        tokens = [t for t in copy_match.group(1).split() if not t.startswith("--")]
        if len(tokens) >= 2:
            sources.extend(tokens[:-1])
    return sources


def preflight_check_earthly_copy_sources(
    target: str,
    arg_values: Dict[str, str],
    earthfile: Optional[Path] = None,
) -> None:
    """Fail fast if the Earthly target COPYs context paths that do not exist.

    Substitutes known ARG values into the COPY sources and checks each against
    the build context (the Earthfile's directory). Artifact references
    (+target/...) and sources with unresolved variables are skipped, since
    they cannot be verified on the host.
    """
    if earthfile is None:
        earthfile = Path.cwd() / "Earthfile"
    context_root = earthfile.parent

    missing: List[str] = []
    for source in earthfile_target_copy_sources(target, earthfile):
        resolved = source
        for name in sorted(arg_values, key=len, reverse=True):
            resolved = resolved.replace(f"${{{name}}}", arg_values[name])
            resolved = resolved.replace(f"${name}", arg_values[name])
        if "+" in resolved or "$" in resolved:
            continue
        pattern = resolved.rstrip("/")
        if any(char in pattern for char in "*?["):
            if not glob.glob(str(context_root / pattern)):
                missing.append(f"{source} (no match for {pattern})")
        elif not (context_root / pattern).exists():
            missing.append(f"{source} ({pattern})")

    if missing:
        raise DeployerException(
            f"Earthly target +{target} COPYs sources missing from the build "
            f"context at {context_root}: {'; '.join(missing)}. The build "
            "would only fail once the COPY step executes, so aborting before "
            "building."
        )


def preflight_check_earthly_secrets(
    target: str,
    provided_secret_names: Optional[FrozenSet[str]] = None,
    earthfile: Optional[Path] = None,
) -> None:
    """Fail fast if the Earthly target needs secrets this CLI does not pass.

    Earthly only resolves secrets when the referencing RUN executes, which can
    be a long time into a build. Checking up front turns an hours-late
    "unable to lookup secret" failure into an immediate, explicit error.
    """
    if provided_secret_names is None:
        provided_secret_names = cli_secret_names()
    if earthfile is None:
        earthfile = Path.cwd() / "Earthfile"

    required = earthfile_target_secrets(target, earthfile)
    missing = sorted(required - set(provided_secret_names))
    if missing:
        supplied = ", ".join(sorted(provided_secret_names)) or "none"
        hint = (
            f" Docker Hub credentials can be supplied via the "
            f"{DOCKERHUB_USER_ENV_VAR} and {DOCKERHUB_TOKEN_ENV_VAR} "
            "environment variables (use a read-only access token)."
            if {"dockerhub_user", "dockerhub_token"} & set(missing)
            else ""
        )
        raise DeployerException(
            f"Earthly target +{target} references secrets this CLI does not "
            f"supply: {', '.join(missing)} (supplied: {supplied}). The build "
            "would only fail once the referencing RUN step executes, so "
            f"aborting before building.{hint}"
        )


def build_earthly_extend_os_command(
    *,
    app_dir: str,
    persist_size: str,
    app_container_image: str,
    guest_attestation_image: str,
    registry: str,
    acr_token: str,
    tls_mode: str,
) -> List[str]:
    if not app_dir or not app_dir.strip():
        raise DeployerException("APP_DIR must be provided explicitly for an application disk build")
    return [
        "earthly",
        "--no-cache",
        "--secret",
        f"acr_token={acr_token}",
        *secret_flags(earthly_dockerhub_secrets()),
        "-P",
        f"+{EARTHLY_EXTEND_OS_TARGET}",
        f"--PERSIST_SIZE={persist_size}",
        f"--OS_RAW={DEFAULT_OS_DISK_DIR / 'disk.raw'}",
        f"--USER_DOCKER={app_container_image}",
        f"--GUEST_ATTESTATION_IMAGE={guest_attestation_image}",
        f"--APP_DIR={app_dir}",
        f"--ACR_REGISTRY={registry}",
        f"--VERITEE_TLS_MODE={tls_mode}",
    ]


def build_earthly_app_disk_command(
    *,
    app_dir: str,
    app_container_image: str,
    guest_attestation_image: str,
    registry: str,
    acr_token: str,
    tls_mode: str,
) -> List[str]:
    if not app_dir or not app_dir.strip():
        raise DeployerException("APP_DIR must be provided explicitly for an application disk build")
    command = [
        "earthly",
        "--no-cache",
        "--secret",
        f"acr_token={acr_token}",
        *secret_flags(earthly_dockerhub_secrets()),
        "-P",
        f"+{EARTHLY_APP_DISK_TARGET}",
        f"--USER_DOCKER={app_container_image}",
        f"--GUEST_ATTESTATION_IMAGE={guest_attestation_image}",
        f"--ACR_REGISTRY={registry}",
        f"--VERITEE_TLS_MODE={tls_mode}",
        f"--APP_DIR={app_dir}",
    ]

    return command


def redact_earthly_command(command: List[str]) -> List[str]:
    display_command = command.copy()
    for index, value in enumerate(display_command):
        if index > 0 and display_command[index - 1] == "--secret" and "=" in value:
            name = value.split("=", 1)[0]
            display_command[index] = f"{name}=<redacted>"

    return display_command



def run_checked(
    command: List[str],
    *,
    cwd: Optional[Path] = None,
    input_text: Optional[str] = None,
    stdin: Optional[int] = None,
    capture_output: bool = True,
    display_command: Optional[List[str]] = None,
    log_stdout: bool = True,
    env: Optional[dict] = None,
    redact_values: Optional[List[str]] = None,
) -> subprocess.CompletedProcess:
    if input_text is not None and stdin is not None:
        raise ValueError("input_text and stdin cannot both be set")

    try:
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd is not None else None,
            input=input_text,
            stdin=stdin,
            capture_output=capture_output,
            text=True,
            check=False,
            env=env,
        )
    except KeyboardInterrupt:
        exit(1)

    command_text = " ".join(display_command or command)
    safe_stdout = result.stdout or ""
    safe_stderr = result.stderr or ""
    for value in redact_values or []:
        if value:
            safe_stdout = safe_stdout.replace(value, "<redacted>")
            safe_stderr = safe_stderr.replace(value, "<redacted>")

    if safe_stdout and log_stdout:
        log.debug("stdout from `%s`:\n%s", command_text, safe_stdout.rstrip())
    if safe_stderr:
        log.debug("stderr from `%s`:\n%s", command_text, safe_stderr.rstrip())

    if result.returncode != 0:
        raise DeployerSubProcessException(
            command_text,
            result.returncode,
            safe_stdout,
            safe_stderr,
        )

    return result


def run_streamable_command(
    command: List[str],
    *,
    verbose: bool,
    cwd: Optional[Path] = None,
    display_command: Optional[List[str]] = None,
) -> str:
    result = run_checked(
        command,
        cwd=cwd,
        stdin=sys.stdin,
        capture_output=not verbose,
        display_command=display_command,
    )

    if not verbose and result.stdout:
        for line in result.stdout.rstrip().splitlines():
            log.info(line)

    return result.stdout or ""


def run_checked_with_retries(
    command: List[str],
    *,
    attempts: int,
    delay_seconds: int,
    display_command: Optional[List[str]] = None,
) -> subprocess.CompletedProcess:
    last_error: Optional[DeployerSubProcessException] = None
    for attempt in range(1, attempts + 1):
        try:
            return run_checked(command, display_command=display_command)
        except DeployerSubProcessException as exc:
            last_error = exc
            if attempt == attempts:
                break

            log.info("Azure command failed; retrying in %ss (%s/%s)...", delay_seconds, attempt, attempts)
            time.sleep(delay_seconds)

    assert last_error is not None
    raise last_error


def run_probe(command: List[str]) -> subprocess.CompletedProcess:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    command_text = " ".join(command)
    if result.stdout:
        log.debug("stdout from `%s`:\n%s", command_text, result.stdout.rstrip())
    if result.stderr:
        log.debug("stderr from `%s`:\n%s", command_text, result.stderr.rstrip())

    return result


def parse_azure_json(result: subprocess.CompletedProcess, description: str):
    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise DeployerException(
            f"Azure returned invalid JSON while {description}"
        ) from exc


def query_azure_storage_accounts(subscription_id: str) -> list[dict]:
    result = run_checked(
        [
            "az",
            "storage",
            "account",
            "list",
            "--subscription",
            subscription_id,
            "--output",
            "json",
        ]
    )
    payload = parse_azure_json(result, "listing Azure Storage accounts")
    if not isinstance(payload, list):
        raise DeployerException("Azure Storage account list must be a JSON array")

    return [item for item in payload if isinstance(item, dict)]


def query_inventory_storage_accounts(subscription_id: str) -> list[dict]:
    return [
        account
        for account in query_azure_storage_accounts(subscription_id)
        if isinstance(account.get("tags"), dict)
        and str(account["tags"].get(INVENTORY_COMPONENT_TAG, "")).lower()
        == INVENTORY_COMPONENT_TAG_VALUE
    ]


def wait_for_inventory_storage_account(
    storage_account: str,
    subscription_id: str,
    *,
    attempts: int = 24,
    delay_seconds: int = 5,
) -> None:
    for attempt in range(1, attempts + 1):
        result = run_checked(
            [
                "az",
                "storage",
                "account",
                "show",
                "--name",
                storage_account,
                "--subscription",
                subscription_id,
                "--query",
                "provisioningState",
                "--output",
                "tsv",
            ]
        )
        state = result.stdout.strip()
        if state == "Succeeded":
            return
        if state in {"Failed", "Canceled"}:
            raise DeployerException(
                f"Inventory Storage account {storage_account} entered state {state}"
            )
        if attempt < attempts:
            log.info(
                "Inventory Storage account is %s; waiting %ss (%s/%s)...",
                state or "not ready",
                delay_seconds,
                attempt,
                attempts,
            )
            time.sleep(delay_seconds)

    raise DeployerException(
        f"Inventory Storage account {storage_account} did not become ready"
    )


def azure_operator_principal(subscription_id: str) -> tuple[str, str]:
    operator = azure_operator(subscription_id)
    operator_type = operator["type"].lower()
    if operator_type == "user":
        result = run_checked(
            ["az", "ad", "signed-in-user", "show", "--query", "id", "--output", "tsv"]
        )
        principal_type = "User"
    else:
        result = run_checked(
            [
                "az",
                "ad",
                "sp",
                "show",
                "--id",
                operator["name"],
                "--query",
                "id",
                "--output",
                "tsv",
            ]
        )
        principal_type = "ServicePrincipal"

    principal_id = result.stdout.strip()
    if not principal_id:
        raise DeployerException("Could not resolve the current Azure principal id")
    return principal_id, principal_type


def ensure_inventory_blob_access(
    storage_account: str,
    subscription_id: str,
) -> None:
    account_result = run_checked(
        [
            "az",
            "storage",
            "account",
            "show",
            "--name",
            storage_account,
            "--subscription",
            subscription_id,
            "--query",
            "id",
            "--output",
            "tsv",
        ]
    )
    scope = account_result.stdout.strip()
    if not scope:
        raise DeployerException(
            f"Could not resolve Azure resource id for Storage account {storage_account}"
        )

    principal_id, principal_type = azure_operator_principal(subscription_id)
    assignments_result = run_checked(
        [
            "az",
            "role",
            "assignment",
            "list",
            "--assignee",
            principal_id,
            "--scope",
            scope,
            "--include-inherited",
            "--subscription",
            subscription_id,
            "--output",
            "json",
        ]
    )
    assignments = parse_azure_json(
        assignments_result,
        "checking inventory Storage account access",
    )
    if not isinstance(assignments, list):
        raise DeployerException("Azure role-assignment list must be a JSON array")
    data_roles = {
        str(assignment.get("roleDefinitionName", ""))
        for assignment in assignments
        if isinstance(assignment, dict)
    }
    if data_roles.intersection({INVENTORY_BLOB_DATA_ROLE, "Storage Blob Data Owner"}):
        return

    run_checked(
        [
            "az",
            "role",
            "assignment",
            "create",
            "--assignee-object-id",
            principal_id,
            "--assignee-principal-type",
            principal_type,
            "--role",
            INVENTORY_BLOB_DATA_ROLE,
            "--scope",
            scope,
            "--subscription",
            subscription_id,
            "--output",
            "none",
        ]
    )


def ensure_inventory_container(
    storage_account: str,
    container: str,
    subscription_id: str,
) -> None:
    run_checked_with_retries(
        [
            "az",
            "storage",
            "container",
            "create",
            "--account-name",
            storage_account,
            "--name",
            container,
            "--auth-mode",
            "login",
            "--public-access",
            "off",
            "--subscription",
            subscription_id,
            "--output",
            "none",
        ],
        attempts=12,
        delay_seconds=5,
    )


def inventory_storage_resource_group(
    storage_account: str,
    subscription_id: str,
) -> str:
    result = run_checked(
        [
            "az",
            "storage",
            "account",
            "show",
            "--name",
            storage_account,
            "--subscription",
            subscription_id,
            "--query",
            "resourceGroup",
            "--output",
            "tsv",
        ]
    )
    resource_group = result.stdout.strip()
    if not resource_group:
        raise DeployerException(
            f"Could not resolve resource group for inventory Storage account {storage_account}"
        )
    return resource_group


def ensure_inventory_storage_is_external(
    storage_account: str,
    deployment_resource_group: str,
    subscription_id: str,
) -> None:
    inventory_resource_group = inventory_storage_resource_group(
        storage_account,
        subscription_id,
    )
    if inventory_resource_group.lower() == deployment_resource_group.lower():
        raise DeployerException(
            "Inventory storage must be outside the immutable deployment resource group"
        )


def inventory_blob_name(deployment_id: str, event: str, recorded_at: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]+", deployment_id):
        raise DeployerException("Invalid deployment id for inventory record")
    if not re.fullmatch(r"[a-z][a-z0-9_]+", event):
        raise DeployerException("Invalid inventory event name")

    compact_timestamp = re.sub(r"[^0-9A-Za-z]", "", recorded_at)
    return (
        f"records/{deployment_id}/{compact_timestamp}-{event}-"
        f"{secrets.token_hex(4)}.json"
    )


def append_inventory_record(
    *,
    storage_account: str,
    container: str,
    subscription_id: str,
    deployment_id: str,
    event: str,
    record: dict,
) -> str:
    recorded_at = utc_timestamp()
    blob_name = inventory_blob_name(deployment_id, event, recorded_at)
    payload = {
        **record,
        "schema_version": 1,
        "event": event,
        "recorded_at": recorded_at,
        "subscription_id": subscription_id,
        "deployment_id": deployment_id,
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        record_path = Path(tmpdir) / "record.json"
        record_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        run_checked(
            [
                "az",
                "storage",
                "blob",
                "upload",
                "--account-name",
                storage_account,
                "--container-name",
                container,
                "--name",
                blob_name,
                "--file",
                str(record_path),
                "--auth-mode",
                "login",
                "--overwrite",
                "false",
                "--subscription",
                subscription_id,
                "--output",
                "none",
            ]
        )

    log.info(
        "Appended deployment audit record: %s/%s/%s",
        storage_account,
        container,
        blob_name,
    )
    return blob_name


def list_inventory_record_blobs(
    *,
    storage_account: str,
    container: str,
    subscription_id: str,
    deployment_id: Optional[str] = None,
) -> list[str]:
    prefix = "records/"
    if deployment_id is not None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]+", deployment_id):
            raise DeployerException("Invalid deployment id for inventory history")
        prefix = f"records/{deployment_id}/"

    result = run_checked(
        [
            "az",
            "storage",
            "blob",
            "list",
            "--account-name",
            storage_account,
            "--container-name",
            container,
            "--prefix",
            prefix,
            "--auth-mode",
            "login",
            "--subscription",
            subscription_id,
            "--query",
            "[].name",
            "--output",
            "json",
        ]
    )
    payload = parse_azure_json(result, "listing deployment inventory records")
    if not isinstance(payload, list) or not all(
        isinstance(item, str) for item in payload
    ):
        raise DeployerException("Deployment inventory record list must be a JSON array")

    return sorted(name for name in payload if name.endswith(".json"))


def load_inventory_records(
    *,
    storage_account: str,
    container: str,
    subscription_id: str,
    deployment_id: Optional[str] = None,
) -> list[dict]:
    blob_names = list_inventory_record_blobs(
        storage_account=storage_account,
        container=container,
        subscription_id=subscription_id,
        deployment_id=deployment_id,
    )
    if blob_names:
        log.info(
            "Downloading %s deployment audit record%s...",
            len(blob_names),
            "" if len(blob_names) == 1 else "s",
        )
    records = []
    with tempfile.TemporaryDirectory() as tmpdir:
        for index, blob_name in enumerate(blob_names):
            record_path = Path(tmpdir) / f"record-{index}.json"
            run_checked(
                [
                    "az",
                    "storage",
                    "blob",
                    "download",
                    "--account-name",
                    storage_account,
                    "--container-name",
                    container,
                    "--name",
                    blob_name,
                    "--file",
                    str(record_path),
                    "--auth-mode",
                    "login",
                    "--overwrite",
                    "true",
                    "--subscription",
                    subscription_id,
                    "--output",
                    "none",
                ]
            )
            record = load_json_file(record_path)
            if not isinstance(record, dict):
                raise DeployerException(
                    f"Deployment inventory record {blob_name} must be a JSON object"
                )
            record["blob_name"] = blob_name
            records.append(record)

    return sorted(
        records,
        key=lambda item: (
            str(item.get("recorded_at") or ""),
            str(item.get("blob_name") or ""),
        ),
    )


def azure_resource_group_exists(resource_group: str, subscription_id: str) -> bool:
    result = run_checked(
        [
            "az",
            "group",
            "exists",
            "--name",
            resource_group,
            "--subscription",
            subscription_id,
            "--output",
            "tsv",
        ]
    )
    value = result.stdout.strip().lower()
    if value not in {"true", "false"}:
        raise DeployerException(
            f"Azure returned an invalid existence result for resource group {resource_group}"
        )
    return value == "true"


def ensure_resource_group_is_new(resource_group: str, subscription_id: str) -> None:
    if azure_resource_group_exists(resource_group, subscription_id):
        raise DeployerException(
            f"Azure resource group {resource_group} already exists. "
            "Each immutable Veritee deployment requires a new resource group."
        )


def validate_incomplete_deployment_resume(
    work_dir: Path, resource_group: str, subscription_id: str,
    deployment_id: str, app_name: str,
) -> dict:
    state_path = work_dir / "terraform.tfstate"
    if not state_path.is_file():
        raise DeployerException("Resuming requires the original local Terraform state")
    state = load_json_file(state_path)
    resources = state.get("resources", [])
    if not isinstance(resources, list):
        raise DeployerException("Invalid Terraform resources in resume state")
    expected_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}".lower()
    groups = [instance.get("attributes", {}).get("id", "").lower()
              for resource in resources if resource.get("type") == "azurerm_resource_group"
              for instance in resource.get("instances", [])]
    if groups != [expected_id]:
        raise DeployerException("Resume state does not match the requested subscription/resource group")
    if any(resource.get("type") in {"azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine",
                                   "azurerm_virtual_machine"} and resource.get("instances")
           for resource in resources):
        raise DeployerException("Cannot resume an immutable deployment whose VM already entered Terraform state")
    group = query_resource_group(resource_group, subscription_id)
    tags = resource_group_tags(group)
    if (not is_managed_resource_group(group)
            or tags.get(VERITEE_DEPLOYMENT_ID_TAG) != deployment_id
            or tags.get("temenos_app_name") != app_name):
        raise DeployerException("Azure resource group does not belong to this Veritee deployment/application")
    result = run_checked(["az", "vm", "list", "--resource-group", resource_group,
                          "--subscription", subscription_id, "--output", "json"])
    vms = parse_azure_json(result, "checking incomplete deployment for existing VMs")
    if not isinstance(vms, list) or vms:
        raise DeployerException("Cannot resume provisioning in a resource group containing a VM")
    return group


def delete_resource_group_and_wait(
    resource_group: str,
    subscription_id: str,
    *,
    poll_seconds: int = 5,
    heartbeat_seconds: int = 30,
    timeout_seconds: int = 1800,
) -> None:
    run_checked(
        [
            "az",
            "group",
            "delete",
            "--name",
            resource_group,
            "--subscription",
            subscription_id,
            "--yes",
            "--no-wait",
            "--output",
            "none",
        ]
    )
    log.info("Azure accepted the deletion request. Waiting for completion...")

    started_at = time.monotonic()
    next_heartbeat = heartbeat_seconds
    while azure_resource_group_exists(resource_group, subscription_id):
        elapsed = int(time.monotonic() - started_at)
        if elapsed >= timeout_seconds:
            raise DeployerException(
                f"Timed out waiting for Azure resource group {resource_group} "
                "to be deleted"
            )
        if elapsed >= next_heartbeat:
            log.info(
                "Azure resource group %s is still deleting (elapsed=%ss)...",
                resource_group,
                elapsed,
            )
            next_heartbeat += heartbeat_seconds
        time.sleep(poll_seconds)


def merge_resource_group_tags(
    resource_group: str,
    tags: dict[str, str],
    subscription_id: str,
) -> None:
    if not tags:
        return

    assignments = [f"tags.{key}={value}" for key, value in sorted(tags.items())]
    run_checked(
        [
            "az",
            "group",
            "update",
            "--name",
            resource_group,
            "--subscription",
            subscription_id,
            "--set",
            *assignments,
            "--output",
            "none",
        ]
    )


def resource_group_tags(resource_group: dict) -> dict[str, str]:
    tags = resource_group.get("tags")
    if not isinstance(tags, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in tags.items()
        if value is not None
    }


def is_managed_resource_group(resource_group: dict) -> bool:
    return resource_group_tags(resource_group).get(VERITEE_MANAGED_TAG, "").lower() == "true"


def query_managed_resource_groups(subscription_id: str) -> list[dict]:
    result = run_checked(
        [
            "az",
            "group",
            "list",
            "--subscription",
            subscription_id,
            "--tag",
            f"{VERITEE_MANAGED_TAG}=true",
            "--output",
            "json",
        ]
    )
    payload = parse_azure_json(result, "listing Veritee deployments")
    if not isinstance(payload, list):
        raise DeployerException("Azure resource-group list must be a JSON array")

    return [
        group
        for group in payload
        if isinstance(group, dict) and is_managed_resource_group(group)
    ]


def query_resource_group(resource_group: str, subscription_id: str) -> dict:
    result = run_checked(
        [
            "az",
            "group",
            "show",
            "--name",
            resource_group,
            "--subscription",
            subscription_id,
            "--output",
            "json",
        ]
    )
    payload = parse_azure_json(result, f"looking up resource group {resource_group}")
    if not isinstance(payload, dict):
        raise DeployerException("Azure resource-group response must be a JSON object")
    return payload


def select_managed_resource_group(
    resource_groups: list[dict],
    *,
    deployment_id: Optional[str],
    resource_group: Optional[str],
) -> dict:
    deployment_id = deployment_id.strip() if deployment_id is not None else None
    resource_group = resource_group.strip() if resource_group is not None else None
    if bool(deployment_id) == bool(resource_group):
        raise typer.BadParameter(
            "Pass exactly one of --deployment-id or --resource-group"
        )

    if resource_group is not None:
        matches = [
            group
            for group in resource_groups
            if str(group.get("name", "")).lower() == resource_group.strip().lower()
        ]
    else:
        expected_id = deployment_id or ""
        if not expected_id:
            raise typer.BadParameter("--deployment-id cannot be empty")
        matches = [
            group
            for group in resource_groups
            if resource_group_tags(group).get(VERITEE_DEPLOYMENT_ID_TAG) == expected_id
        ]

    if len(matches) != 1:
        selector = resource_group or deployment_id
        raise DeployerException(
            f"Expected exactly one Veritee-managed resource group for {selector!r}; "
            f"found {len(matches)}"
        )

    selected = matches[0]
    if not is_managed_resource_group(selected):
        raise DeployerException(
            f"Refusing to delete untagged resource group {selected.get('name', 'unknown')}"
        )

    return selected


def resolve_managed_resource_group(
    *,
    subscription_id: str,
    deployment_id: Optional[str],
    resource_group: Optional[str],
) -> dict:
    deployment_id = deployment_id.strip() if deployment_id is not None else None
    resource_group = resource_group.strip() if resource_group is not None else None
    if bool(deployment_id) == bool(resource_group):
        raise typer.BadParameter(
            "Pass exactly one of --deployment-id or --resource-group"
        )

    if resource_group is not None:
        groups = [query_resource_group(resource_group, subscription_id)]
    else:
        groups = query_managed_resource_groups(subscription_id)

    return select_managed_resource_group(
        groups,
        deployment_id=deployment_id,
        resource_group=resource_group,
    )


def azure_operator(subscription_id: str) -> dict[str, str]:
    result = run_checked(
        [
            "az",
            "account",
            "show",
            "--subscription",
            subscription_id,
            "--query",
            "user",
            "--output",
            "json",
        ]
    )
    payload = parse_azure_json(result, "resolving the Azure operator")
    if not isinstance(payload, dict):
        return {"name": "unknown", "type": "unknown"}
    return {
        "name": str(payload.get("name") or "unknown"),
        "type": str(payload.get("type") or "unknown"),
    }


def remove_external_keyvault_role_assignment(
    resource_group: dict,
    subscription_id: str,
) -> None:
    tags = resource_group_tags(resource_group)
    if tags.get("temenos_tls_mode") != "azure_vault":
        return

    vault_name = tags.get("temenos_tls_keyvault_name", "").strip()
    vm_name = tags.get("temenos_vm_name", "").strip()
    resource_group_name = str(resource_group.get("name", "")).strip()
    if not vault_name or not vm_name or not resource_group_name:
        raise DeployerException(
            "Azure Vault deployment tags are incomplete; refusing teardown before "
            "the external Key Vault role assignment can be removed"
        )

    principal_id = tags.get("temenos_vm_principal_id", "").strip()
    if not principal_id:
        principal_result = run_checked(
            [
                "az",
                "vm",
                "show",
                "--resource-group",
                resource_group_name,
                "--name",
                vm_name,
                "--subscription",
                subscription_id,
                "--query",
                "identity.principalId",
                "--output",
                "tsv",
            ]
        )
        principal_id = principal_result.stdout.strip()
    if not principal_id:
        raise DeployerException("Could not resolve the VM managed-identity principal id")

    vault_result = run_checked(
        [
            "az",
            "keyvault",
            "show",
            "--name",
            vault_name,
            "--subscription",
            subscription_id,
            "--query",
            "id",
            "--output",
            "tsv",
        ]
    )
    vault_id = vault_result.stdout.strip()
    if not vault_id:
        raise DeployerException(f"Could not resolve Azure Key Vault {vault_name}")

    run_checked(
        [
            "az",
            "role",
            "assignment",
            "delete",
            "--assignee",
            principal_id,
            "--role",
            "Key Vault Secrets User",
            "--scope",
            vault_id,
            "--subscription",
            subscription_id,
            "--output",
            "none",
        ]
    )
    log.info("Removed VM identity access from external Key Vault %s", vault_name)


def preserve_deployment_vhd(
    *,
    resource_group: dict,
    inventory_storage_account: str,
    inventory_container: str,
    subscription_id: str,
    poll_attempts: int = 360,
    poll_delay_seconds: int = 5,
) -> str:
    tags = resource_group_tags(resource_group)
    deployment_id = tags.get(VERITEE_DEPLOYMENT_ID_TAG, "").strip()
    source_account = tags.get("temenos_storage_account", "").strip()
    source_container = tags.get("temenos_storage_container", "").strip()
    source_resource_group = str(resource_group.get("name") or "").strip()
    if not deployment_id or not source_account or not source_container:
        raise DeployerException(
            "Deployment storage tags are incomplete; cannot retain the VHD"
        )

    expiry = (
        datetime.now(timezone.utc) + timedelta(hours=1)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    account_key_result = run_checked(
        [
            "az",
            "storage",
            "account",
            "keys",
            "list",
            "--resource-group",
            source_resource_group,
            "--account-name",
            source_account,
            "--subscription",
            subscription_id,
            "--query",
            "[0].value",
            "--output",
            "tsv",
        ],
        log_stdout=False,
    )
    source_account_key = account_key_result.stdout.strip()
    if not source_account_key:
        raise DeployerException("Azure did not return the source storage account key")

    sas_command = [
        "az",
        "storage",
        "blob",
        "generate-sas",
        "--account-name",
        source_account,
        "--container-name",
        source_container,
        "--name",
        "temen-os.vhd",
        "--permissions",
        "r",
        "--expiry",
        expiry,
        "--https-only",
        "--full-uri",
        "--subscription",
        subscription_id,
        "--output",
        "tsv",
    ]
    sas_env = os.environ.copy()
    sas_env["AZURE_STORAGE_KEY"] = source_account_key
    sas_result = run_checked(
        sas_command,
        log_stdout=False,
        env=sas_env,
    )
    source_uri = sas_result.stdout.strip()
    if not source_uri:
        raise DeployerException("Azure did not return a source URI for VHD retention")

    destination_blob = (
        f"retained-images/{deployment_id}/{secrets.token_hex(4)}-temen-os.vhd"
    )
    copy_command = [
        "az",
        "storage",
        "blob",
        "copy",
        "start",
        "--account-name",
        inventory_storage_account,
        "--destination-container",
        inventory_container,
        "--destination-blob",
        destination_blob,
        "--source-uri",
        source_uri,
        "--auth-mode",
        "login",
        "--subscription",
        subscription_id,
        "--output",
        "none",
    ]
    display_command = copy_command.copy()
    display_command[display_command.index("--source-uri") + 1] = "<redacted-sas-uri>"
    run_checked(
        copy_command,
        display_command=display_command,
        redact_values=[source_uri],
    )

    for _ in range(poll_attempts):
        status_result = run_checked(
            [
                "az",
                "storage",
                "blob",
                "show",
                "--account-name",
                inventory_storage_account,
                "--container-name",
                inventory_container,
                "--name",
                destination_blob,
                "--auth-mode",
                "login",
                "--subscription",
                subscription_id,
                "--query",
                "properties.copy.status",
                "--output",
                "tsv",
            ]
        )
        status = status_result.stdout.strip().lower()
        if status == "success":
            return destination_blob
        if status in {"aborted", "failed"}:
            raise DeployerException(f"Azure VHD copy ended with status {status}")
        time.sleep(poll_delay_seconds)

    raise DeployerException("Timed out waiting for the retained VHD copy to complete")


def ensure_current_user_can_write_keyvault_secrets(vault_id: str, subscription_id: str) -> None:
    principal = run_probe(
        [
            "az",
            "ad",
            "signed-in-user",
            "show",
            "--query",
            "id",
            "--output",
            "tsv",
        ]
    )
    principal_id = principal.stdout.strip()
    if principal.returncode != 0 or not principal_id:
        log.info("Could not resolve signed-in Azure user; skipping local Key Vault secret-writer role assignment.")
        return

    role_assignment = run_probe(
        [
            "az",
            "role",
            "assignment",
            "create",
            "--assignee-object-id",
            principal_id,
            "--assignee-principal-type",
            "User",
            "--role",
            "Key Vault Secrets Officer",
            "--scope",
            vault_id,
            "--subscription",
            subscription_id,
            "--output",
            "none",
        ]
    )
    if role_assignment.returncode == 0:
        log.info("Granted current Azure user Key Vault Secrets Officer on %s", vault_id)
    elif "RoleAssignmentExists" in role_assignment.stderr:
        log.info("Current Azure user already has Key Vault Secrets Officer on %s", vault_id)
    else:
        log.info("Could not grant current Azure user Key Vault secret-writer access; continuing with existing permissions.")


def ensure_tls_keyvault(
    *,
    vault_name: str,
    resource_group: str,
    location: str,
    subscription_id: str,
) -> str:
    existing = run_probe(
        [
            "az",
            "keyvault",
            "show",
            "--name",
            vault_name,
            "--subscription",
            subscription_id,
            "--query",
            "{id:id,rbac:properties.enableRbacAuthorization}",
            "--output",
            "json",
        ]
    )
    if existing.returncode == 0 and existing.stdout.strip():
        vault = json.loads(existing.stdout)
        vault_id = vault.get("id", "").strip()
        if not vault_id:
            raise DeployerException(f"Azure Key Vault lookup did not return a vault id: {vault_name}")
        if not vault.get("rbac", False):
            raise DeployerException(
                f"Azure Key Vault {vault_name} exists but does not use Azure RBAC authorization. "
                "Use a vault with RBAC enabled so the VM managed identity can read TLS secrets."
            )

        log.info("Key Vault exists: %s", vault_id)
        ensure_current_user_can_write_keyvault_secrets(vault_id, subscription_id)
        return vault_id

    log.info("Key Vault not found; creating it.")
    run_checked(
        [
            "az",
            "group",
            "create",
            "--name",
            resource_group,
            "--location",
            location,
            "--subscription",
            subscription_id,
            "--output",
            "none",
        ]
    )
    created = run_checked(
        [
            "az",
            "keyvault",
            "create",
            "--name",
            vault_name,
            "--resource-group",
            resource_group,
            "--location",
            location,
            "--enable-rbac-authorization",
            "true",
            "--subscription",
            subscription_id,
            "--query",
            "id",
            "--output",
            "tsv",
        ]
    )
    vault_id = created.stdout.strip()
    if not vault_id:
        raise DeployerException(f"Azure Key Vault creation did not return a vault id: {vault_name}")

    ensure_current_user_can_write_keyvault_secrets(vault_id, subscription_id)
    return vault_id


def get_acr_access_token(acr_name: str) -> str:
    result = run_checked(
        [
            "az",
            "acr",
            "login",
            "--name",
            acr_name,
            "--expose-token",
            "--output",
            "tsv",
            "--query",
            "accessToken",
        ]
    )
    token = result.stdout.strip()
    if not token:
        raise DeployerException(f"Failed to obtain ACR access token for {acr_name}")

    return token


def acr_login(acr_name: str) -> None:
    run_checked(["az", "acr", "login", "--name", acr_name])


def push_scratch_artifact_image(
    acr_name: str,
    image_ref: str,
    artifact_dir: Path,
    artifact_files: List[str],
) -> None:
    import tempfile

    # Stage the build context inside the working directory rather than /tmp:
    # a snap-confined docker client has a private /tmp and cannot read it.
    with tempfile.TemporaryDirectory(
        prefix=".temenos-dapp-push-", dir=Path.cwd()
    ) as tmp:
        tmp_path = Path(tmp)
        dockerfile_lines = ["FROM scratch"]
        for name in artifact_files:
            source_path = artifact_dir / name
            if not source_path.exists():
                raise DeployerException(f"Missing artifact for ACR push: {source_path}")

            try:
                # Hardlink instead of copying: the artifacts are multiple GB
                # and the staging dir lives on the same filesystem.
                os.link(source_path, tmp_path / name)
            except OSError:
                shutil.copy2(source_path, tmp_path / name)
            dockerfile_lines.append(
                f"COPY {name} {ACR_OS_ARTIFACT_PREFIX}/{name}"
            )

        (tmp_path / "Dockerfile").write_text("\n".join(dockerfile_lines) + "\n")
        acr_login(acr_name)
        run_checked(["docker", "build", "-t", image_ref, str(tmp_path)])
        run_checked(["docker", "push", image_ref])


def print_tee_step(message: str) -> None:
    log.info(f"[TEE] {message}")


def print_quiet_earthly_hint() -> None:
    log.info(
        "Earthly output is hidden by default. Pass --verbose to inspect the "
        "standard container build steps."
    )


def load_pcr4_measurement(path: Path) -> str:
    measurements = load_json_file(path)
    pcr4 = measurements.get("measurements", {}).get("4")
    if not isinstance(pcr4, str) or not pcr4.strip():
        raise DeployerException(f"Missing PCR4 measurement in {path}")

    return pcr4.strip()


def read_manifest_content(path: Path):
    if not path.exists():
        raise DeployerException(f"Manifest input not found: {path}")

    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return path.read_text()


def generate_simple_manifest(
    *,
    vhd_path: Path,
    image_version: str,
    output_path: Path,
    disk_manifest_path: Optional[Path] = None,
    initrd_manifest_path: Optional[Path] = None,
) -> Path:
    if not vhd_path.exists():
        raise DeployerException(f"VHD not found: {vhd_path}")

    manifest = {
        "version": image_version,
        "vhd": {
            "path": vhd_path.name,
            "sha256": sha256_file(vhd_path),
            "size_bytes": vhd_path.stat().st_size,
        },
    }

    embedded_manifests = {}

    if disk_manifest_path is not None:
        embedded_manifests["disk"] = {
            "path": disk_manifest_path.name,
            "sha256": sha256_file(disk_manifest_path),
            "content": read_manifest_content(disk_manifest_path),
        }

    if initrd_manifest_path is not None:
        embedded_manifests["initrd"] = {
            "path": initrd_manifest_path.name,
            "sha256": sha256_file(initrd_manifest_path),
            "content": read_manifest_content(initrd_manifest_path),
        }

    if embedded_manifests:
        manifest["embedded_manifests"] = embedded_manifests

    write_json(output_path, manifest)
    return output_path

@app.command("job-status", rich_help_panel=COMMAND_PANEL_VERIFICATION)
def job_status(
    job: Annotated[Optional[str], typer.Argument(help="Warden job id, status URL, or /jobs/{job_id}")] = None,
    endpoint: Annotated[Optional[str], typer.Option(help="Warden base URL used to resolve relative job URLs. Uses VERITEE_WARDEN_URL when omitted.")] = None,
    poll: Annotated[Optional[bool], typer.Option("--poll/--no-poll", help="Poll until the job reaches a terminal state")] = None,
):
    """Enquire a scheduled job status from the Warden (DAPP registration, on-chain push of attestation verification). If the job is still queued, you can optionally poll until it completes."""
    show_options_phase = job is None or poll is None
    total_phases = 3 if show_options_phase else 2
    current_phase = 1

    if show_options_phase:
        print_phase("JOB STATUS OPTIONS", current_phase, total_phases)
        current_phase += 1

    if job is None:
        job = typer.prompt("Enter Warden job id or status URL")

    if poll is None:
        poll = typer.confirm("Poll job until completion?", default=False)

    queued_payload = queued_payload_from_job_reference(job)
    endpoint = resolve_warden_job_endpoint(endpoint, queued_payload["status_url"])

    if poll:
        print_phase("POLL JOB", current_phase, total_phases)
        current_phase += 1
        log.info("Using Warden endpoint: %s", endpoint)
        result = poll_warden_job(endpoint, queued_payload)
        print_phase("JOB RESPONSE", current_phase, total_phases)
        typer.echo(json.dumps(result, indent=4))
        return

    print_phase("FETCH JOB", current_phase, total_phases)
    current_phase += 1
    job_url = resolve_warden_job_url(endpoint, queued_payload["status_url"])
    log.info("Using Warden job endpoint: %s", job_url)
    job_payload = get_warden_json(job_url, "fetch job status")
    print_phase("JOB RESPONSE", current_phase, total_phases)
    typer.echo(json.dumps(job_payload, indent=4))


@app.command("pull-attestation", rich_help_panel=COMMAND_PANEL_VERIFICATION)
def pull_attestation(
    target: Annotated[str, typer.Argument(help="Full public HTTPS attestation URL, for example https://<attestation-domain>/tee_attestation")],
    nonce: Annotated[Optional[str], typer.Option(help="Client payload nonce. Defaults to a generated nonce unless --unbound-attestation is used. Reuse this value with verify-attestation --nonce when freshness is required.")] = None,
    payload: Annotated[Optional[str], typer.Option(help="Optional MAA client payload string.")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Write attestation JSON to this file instead of stdout")] = None,
    resolve_host: Annotated[Optional[str], typer.Option("--resolve", help="Connect to this IP while preserving the HTTPS hostname for TLS and HTTP routing")] = None,
    tls_mode: Annotated[Optional[str], typer.Option("--tls-mode", help="Override the TLS mode recorded in local-azure-snp/tls_mode")] = None,
    unbound_attestation: Annotated[bool, typer.Option("--unbound-attestation/--nonce-bound-attestation", help="Fetch attestation without a nonce. Servers must explicitly allow this for dev/testing.")] = False,
):
    """Pull a DApp TEE attestation from a Veritee VM"""
    print_phase("REQUEST DAPP ATTESTATION", 1, 2)
    endpoint = normalize_public_attestation_url(target)
    normalized_nonce = normalize_optional_nonce(nonce)
    if unbound_attestation:
        if normalized_nonce is not None:
            raise typer.BadParameter("--nonce cannot be used with --unbound-attestation")
        if payload is not None and payload.strip():
            raise typer.BadParameter("--payload requires a nonce and cannot be used with --unbound-attestation")
        log.warning(color_text(" ! fetching unbound attestation; evidence will be replayable.", COLOR_YELLOW))
    elif normalized_nonce is None:
        normalized_nonce = generate_attestation_nonce()
        log.info("Generated attestation nonce: %s", normalized_nonce)

    tls_mode = resolve_attestation_tls_mode(tls_mode)
    if tls_mode == "internal":
        log.warning(
            "Bootstrapping the Caddy internal root CA from the static attestation "
            "document; trust it only after the attestation and PCR15 are verified"
        )

    log.info("Requesting DApp attestation from %s...", endpoint)
    attestation = fetch_attestation_json(
        endpoint,
        nonce=normalized_nonce,
        payload=payload,
        resolved_host=resolve_host,
        tls_mode=tls_mode,
    )

    print_phase("DAPP ATTESTATION RESPONSE", 2, 2)
    rendered = json.dumps(attestation, indent=4)
    if output is not None:
        output.write_text(rendered + "\n")
        log.info(color_text(f" ✓ Wrote DApp attestation to {output}.", COLOR_GREEN))
        return

    typer.echo(rendered)


@app.command(rich_help_panel=COMMAND_PANEL_VERIFICATION)
def verify_attestation(
    dapp_id: Annotated[str, typer.Option(help="Warden registration entry_id or registration_id")],
    tee_attestation: Annotated[
        str,
        typer.Option(
            help="TEE attestation JSON to verify. Pass inline JSON or @path/to/file.json for large payloads."
        ),
    ],
    payload: Annotated[str, typer.Option(help="Payload to sign after attestation verification. JSON is accepted; non-JSON is sent as text.")],
    nonce: Annotated[Optional[str], typer.Option(help="MAA client payload nonce to check against the attestation.")] = None,
    endpoint: Annotated[Optional[str], typer.Option(help="Warden attestation verification endpoint. Derived from VERITEE_WARDEN_URL when omitted.")] = None,
    poll: Annotated[bool, typer.Option("--poll/--no-poll", help="Poll the queued verification recording job until completion")] = False,
    expected_application_id: Annotated[Optional[str], typer.Option(help="Trusted application ID the selected registration must belong to.")] = None,
):
    """Verify a DApp's TEE attestation"""
    endpoint = resolve_warden_endpoint(endpoint, WARDEN_VERIFY_ATTESTATION_ROUTE)
    print_phase("VALIDATE ATTESTATION VERIFICATION REQUEST", 1, 3)
    if not dapp_id.strip():
        raise typer.BadParameter("DApp ID cannot be empty")
    if not payload:
        raise typer.BadParameter("Payload cannot be empty")

    normalized_nonce = normalize_optional_nonce(nonce)
    if normalized_nonce is None:
        raise typer.BadParameter("--nonce is required for attestation freshness")
    parsed_attestation = parse_json_argument(tee_attestation, "TEE attestation")
    parsed_payload = parse_payload(payload)
    log_verification_preflight(
        dapp_id.strip(),
        normalized_nonce,
        tee_attestation,
        parsed_attestation,
        payload,
        parsed_payload,
    )

    request_payload = {
        "dapp_id": dapp_id.strip(),
        "tee_attestation": parsed_attestation,
        "payload": parsed_payload,
        "nonce": normalized_nonce,
    }

    if expected_application_id is not None:
        request_payload["expected_application_id"] = expected_application_id

    if poll:
        log.info("Verification recording polling: enabled")

    print_phase("REQUEST ATTESTATION VERIFICATION", 2, 3)
    log.info(
        "Requesting Warden attestation verification for DApp %s...",
        dapp_id.strip(),
    )
    log.info("Using Warden endpoint: %s", endpoint)
    response_status, response_payload = post_warden_json_response(
        endpoint,
        request_payload,
        "verify attestation",
        timeout=WARDEN_REQUEST_TIMEOUT,
    )
    if response_status not in {200, 202}:
        raise DeployerException(
            f"Failed to verify attestation: Warden returned HTTP {response_status}, expected 200 OK or 202 Accepted"
        )
    if not isinstance(response_payload, dict):
        raise DeployerException("Failed to verify attestation: Warden returned invalid verification response")

    if poll:
        queued_payload = queued_payload_from_nested_job(
            response_payload,
            "verification_recording",
            "verify attestation",
        )
        print_phase("POLL RECORDING JOB AND RESPONSE", 3, 3)
        response_payload["verification_recording_result"] = poll_warden_job(
            endpoint,
            queued_payload,
            "Warden verification recording job",
        )
    else:
        print_phase("ATTESTATION VERIFICATION RESPONSE", 3, 3)
    typer.echo(json.dumps(response_payload, indent=4))

@app.command(rich_help_panel=COMMAND_PANEL_VERIFICATION)
def attested_prove(
    dapp_id: Annotated[str, typer.Option(help="Warden-issued DApp ID")],
    payload: Annotated[str, typer.Option(help="Request payload to send through the attested channel (sent as UTF-8 bytes).")],
    server: Annotated[str, typer.Option(help="Attestation server base URL")] = "http://localhost:8000",
    path: Annotated[str, typer.Option(help="Upstream DApp path inside the encrypted request")] = "/prove",
    method: Annotated[str, typer.Option(help="Upstream HTTP method inside the encrypted request")] = "POST",
    content_type: Annotated[str, typer.Option(help="Content-Type forwarded to the DApp")] = "application/json",
    warden_endpoint: Annotated[Optional[str], typer.Option(help="Warden attestation verification endpoint. Derived from VERITEE_WARDEN_URL when omitted.")] = None,
    skip_warden: Annotated[bool, typer.Option(help="Skip Warden attestation verification (INSECURE; local testing only)")] = False,
    expected_application_id: Annotated[Optional[str], typer.Option(help="Trusted application ID the selected registration must belong to.")] = None,
):
    """Establish an attested channel and tunnel one request through it.

    Fetches the attested epoch key, delegates attestation verification to Warden,
    runs the session handshake, then tunnels an HTTP request over `POST /proxy`
    and prints the decrypted DApp response.
    """
    from .attested_channel import (
        AttestedChannelClient,
        HttpTransport,
        ProtocolError,
        UpstreamHttpError,
        make_warden_verifier,
    )

    if not dapp_id.strip():
        raise typer.BadParameter("DApp ID cannot be empty")
    if not payload:
        raise typer.BadParameter("Payload cannot be empty")

    if not path.startswith("/"):
        raise typer.BadParameter("Path must start with /")

    verifier = None
    if not skip_warden:
        warden_endpoint = resolve_warden_endpoint(
            warden_endpoint,
            WARDEN_VERIFY_ATTESTATION_ROUTE,
        )
        verifier = make_warden_verifier(
            warden_endpoint, dapp_id.strip(), parse_payload(payload),
            expected_application_id=expected_application_id,
        )

    client = AttestedChannelClient(HttpTransport(server), verifier=verifier)

    print_phase("ESTABLISH ATTESTED CHANNEL", 1, 2)
    log.info("Creating attested session with %s...", server)
    try:
        session = client.create_session()
        response = client.request(
            session, method, path, payload.encode("utf-8"),
            headers={"content-type": content_type} if content_type else None,
        )
        response.raise_for_status()
    except UpstreamHttpError as exc:
        raise DeployerException(str(exc)) from exc
    except (ProtocolError, requests.RequestException) as exc:
        raise DeployerException(f"Attested channel failed: {exc}") from exc

    print_phase("ATTESTED RESPONSE", 2, 2)
    log.info("DApp response status: %s", response.status)
    try:
        typer.echo(response.body.decode("utf-8"))
    except UnicodeDecodeError:
        typer.echo(base64.b64encode(response.body).decode("ascii"))

@app.command(rich_help_panel=COMMAND_PANEL_REGISTRATION)
def register_app(
    endpoint: Annotated[Optional[str], typer.Option(help="Warden DApp registration endpoint. Derived from VERITEE_WARDEN_URL when omitted.")] = None,
    metadata_path: Annotated[Optional[Path], typer.Option(help="Path to DApp metadata.json from package-dapp-deployable-vm-image")] = None,
    app_dir: Annotated[Optional[Path], typer.Option(help="Required application source directory used for packaging")] = None,
    base_os_version: Annotated[Optional[str], typer.Option("--base-os-version", help="Optional consistency check against the OS version resolved by Warden.")] = None,
    tls_mode: Annotated[Optional[str], typer.Option("--tls-mode", help="TLS mode used to build the DApp disk: internal or azure_vault")] = None,
    address: Annotated[Optional[str], typer.Option(help="DApp base endpoint URL or VM IP address to register on Warden")] = None,
    attestation_domain_name: Annotated[Optional[str], typer.Option(help="Attestation endpoint domain name to register on Warden. Defaults from the Caddyfile for public TLS modes.")] = None,
    app_key: Annotated[Optional[str], typer.Option("--app-key", help="High-entropy app key. Defaults to VERITEE_APP_KEY or a generated local key file.")] = None,
    poll: Annotated[Optional[bool], typer.Option("--poll/--no-poll", help="Poll queued registration jobs until completion")] = None,
):
    """Register your DApp on the Warden for attestation verification and signing."""
    if app_dir is None:
        raise DeployerException("Pass --app-dir with the application source directory used for packaging")
    endpoint = resolve_warden_endpoint(endpoint, WARDEN_REGISTER_ROUTE)
    metadata_file = resolve_app_metadata_path(metadata_path)
    metadata = load_app_metadata(metadata_file)
    app_source_dir = resolve_register_app_source_dir(metadata_file, app_dir)
    metadata_json = read_register_app_metadata_json(metadata_file, app_source_dir)
    print_phase("PROVIDE DAPP INFORMATIONS", 1, 4)
    log.info("Using DApp metadata from %s", metadata_file)
    log.info("Using DApp app-disk files from %s", app_source_dir)
    tls_mode = resolve_register_tls_mode(metadata_file, app_source_dir, tls_mode)
    try:
        input_snapshot = pack_validation.verify_snapshot(metadata_file, app_source_dir, tls_mode)
    except (ValueError, KeyError, UnicodeError, OSError) as error:
        raise DeployerException(f"Registration input drift: {error}") from error
    address = resolve_register_address(tls_mode, app_source_dir, address)
    attestation_domain_name = resolve_register_attestation_domain(
        tls_mode,
        app_source_dir,
        attestation_domain_name,
    )
    if input_snapshot is not None:
        if input_snapshot.get("registration_preflight") is False:
            raise DeployerException("This operator image skipped registration preflight; repackage with --registration-preflight before registering it")
        try:
            version = input_snapshot["os_release_version"]
            if base_os_version is not None and base_os_version.strip() != version:
                raise ValueError("--base-os-version disagrees with the packaged OS release")
            pack_validation.validate_projection(pack_validation.projection(
                metadata, address, attestation_domain_name, tls_mode,
                version=version, os_key=input_snapshot["os_key"],
            ), local_registration_profile())
        except (ValueError, KeyError, UnicodeError) as error:
            raise DeployerException(f"Registration preflight failed: {error}") from error
    app_key = resolve_app_key(metadata_file, app_key)
    pcrs_path, policy_path = resolve_security_files(metadata_file)
    payload = {
        "address": address,
        "attestation_domain_name": attestation_domain_name,
        "temenos_app_key": app_key,
        "metadata_json": metadata_json,
        "tls_mode": tls_mode,
        "tee_measurements": [
            load_tee_measurements(pcrs_path),
            load_json_file(policy_path),
        ],
    }
    if base_os_version is not None:
        if not base_os_version.strip():
            raise typer.BadParameter("base-os-version cannot be empty")
        payload["base_os_version"] = base_os_version.strip()
    included_app_files = add_register_app_file_fields(payload, app_source_dir)
    print_phase("POLLING OPTIONS", 2, 4)
    if poll is None:
        poll = typer.confirm("Poll queued registration job until completion?", default=True)
    else:
        log.info("Queued registration polling: %s", "enabled" if poll else "disabled")

    print_phase("REGISTER DAPP ON WARDEN", 3, 4)
    log.info(f"Registering {metadata['name']} on Warden...")
    log.info("Using Warden endpoint: %s", endpoint)
    log.info(
        "Including DApp app-disk file(s): %s",
        ", ".join(str(path) for path in included_app_files),
    )
    log.info("Base Veritee OS image: %s (resolved by Warden)", metadata["base_os_image"])
    log.info("TLS mode: %s", tls_mode)
    response_status, response_payload = post_warden_json_response(
        endpoint,
        payload,
        "register DApp",
        timeout=WARDEN_REGISTER_REQUEST_TIMEOUT,
    )
    queued_payload = queued_payload_from_warden_response(
        response_status,
        response_payload,
        "register DApp",
    )
    if poll:
        print_phase("POLL JOB AND RESPONSE", 4, 4)
        response_payload = poll_warden_job(endpoint, queued_payload, "Warden registration job")
    else:
        response_payload = queued_payload
        print_phase("DAPP REGISTRATION RESPONSE & COMPLETE", 4, 4)
    typer.echo(json.dumps(response_payload, indent=4))

@app.command("pull-base-os-image", rich_help_panel=COMMAND_PANEL_IMAGES)
def pull_base_os_image(
    base_os_image: Annotated[Optional[str], typer.Option(help="ACR reference for the base Veritee OS image")] = None,
    version: Annotated[Optional[str], typer.Option(help="Base Veritee OS image version label to record in local metadata")] = None,
    output_dir: Annotated[Path, typer.Option(help="Directory where the base Veritee OS image artifacts are stored locally")] = DEFAULT_OS_DISK_DIR,
    os_release_key: Annotated[Optional[str], typer.Option(help="Advanced override: accepted OS manifest SHA-256. Otherwise resolve the chosen OS image automatically.")] = None,
):
    resolved_version = version.strip() if version is not None else DEFAULT_OS_DISK_VERSION
    if not resolved_version:
        raise typer.BadParameter("version cannot be empty")

    if base_os_image is None:
        metadata_path = DEFAULT_APP_DIR / APP_METADATA_FILE
        if metadata_path.exists():
            base_os_image = load_app_source_metadata(DEFAULT_APP_DIR)["base_os_image"]
        else:
            raise DeployerException(
                "Pass --base-os-image or add base_os_image to "
                f"{metadata_path} before pulling the base Veritee OS image."
            )

    selected_os = os_release.resolve_selection(os_release_key, base_os_image=base_os_image)
    selected_manifest = json.loads(selected_os["manifest"])
    if base_os_image != selected_manifest["publication"]["reference"]:
        raise DeployerException("Base OS reference disagrees with selected accepted manifest")
    if version is not None and version != selected_os["entry"]["release_version"]:
        raise DeployerException("--version disagrees with selected accepted release")
    resolved_version = selected_os["entry"]["release_version"]
    print_phase("PULL BASE VERITEE OS IMAGE", 1, 2)
    print_tee_step(f"Pulling base Veritee OS image from ACR ({base_os_image})...")
    os_release.pull_selected(selected_os, output_dir)

    print_phase("WRITE BASE OS METADATA AND COMPLETE", 2, 2)
    os_image_metadata = {
        "version": selected_os["entry"]["release_version"],
        "base_os_image": base_os_image,
        "pcr4": load_pcr4_measurement(output_dir / PCRS_FILE),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "base_os_image_download.json", os_image_metadata)
    log.info(
        color_text(
            f" ✓ Base Veritee OS image v{resolved_version} pulled to {output_dir}.",
            COLOR_GREEN,
        )
    )


@app.command("push-base-os-image", rich_help_panel=COMMAND_PANEL_IMAGES)
def push_base_os_image(
    base_os_image: Annotated[Optional[str], typer.Option(help="ACR reference to publish the base Veritee OS image to")] = None,
    version: Annotated[Optional[str], typer.Option(help="Base Veritee OS image version tag")] = None,
    input_dir: Annotated[Path, typer.Option(help="Directory containing disk.raw and pcrs.json")] = DEFAULT_OS_DISK_DIR,
):
    print_phase("PUSH OS IMAGE TO ACR", 1, 1)

    resolved_version = version.strip() if version is not None else DEFAULT_OS_DISK_VERSION
    if not resolved_version:
        raise typer.BadParameter("version cannot be empty")

    acr_name = require_acr_name()
    if base_os_image is None:
        base_os_image = resolve_base_os_image(acr_name, resolved_version)

    print_tee_step(f"Pushing base Veritee OS image artifacts to ACR ({base_os_image})...")
    push_scratch_artifact_image(
        acr_name,
        base_os_image,
        input_dir,
        base_os_push_artifacts(),
    )
    log.info(color_text(f" ✓ Published base Veritee OS image: {base_os_image}", COLOR_GREEN))


@app.command("build-base-os-image", rich_help_panel=COMMAND_PANEL_IMAGES)
def build_base_os_image(
    azure_snp: Annotated[bool, typer.Option("--azuresnp")] = False,
    attestation_mode: Annotated[
        AttestationMode,
        typer.Option(
            help="Attestation evidence compiled into the base OS image: MAA-backed or raw Azure SEV-SNP"
        ),
    ] = AttestationMode.MAA,
    debug: Annotated[bool, typer.Option()] = False,
    verbose: Annotated[bool, typer.Option()] = False,
    allow_unbound_attestation: Annotated[
        bool,
        typer.Option(
            "--allow-unbound-attestation/--require-bound-attestation",
            help="Allow a debug image to serve no-nonce evidence. Requires --debug; release images always require nonce-bound evidence.",
        ),
    ] = False,
):
    """Build the base Veritee OS image. Use package-dapp-deployable-vm-image to package a DApp."""
    if not azure_snp:
        raise typer.BadParameter("pass --azuresnp to select the Azure SEV-SNP build")
    validate_unbound_attestation_build(
        debug=debug,
        allow_unbound_attestation=allow_unbound_attestation,
    )

    print_phase("BUILD BASE VERITEE OS IMAGE", 1, 2)

    log.info("Attestation mode: %s", attestation_mode.value)
    if allow_unbound_attestation:
        log.warning(
            "Unbound attestation evidence enabled in this image; no-nonce responses are replayable and should be used only for dev/testing."
        )

    if debug:
        log.info("IMPORTANT: Debug images are NOT deterministic due to the use of RootPassword in both the initrd and rootfs!")
        log.info("Building debug base Veritee OS image")
    else:
        log.info("Building release base Veritee OS image...")

    if not verbose:
        print_quiet_earthly_hint()

    os_config = f"config-azure.{'debug.' if debug else ''}yaml"
    command = build_earthly_base_os_command(
        os_config=os_config,
        attestation_mode=attestation_mode,
        allow_unbound_attestation=allow_unbound_attestation,
    )

    build_source = os_release.source_identity(Path.cwd()) if not debug else None
    stdout = run_streamable_command(command, verbose=verbose, cwd=Path.cwd())

    disk_output_dir = Path.cwd() / DEFAULT_OS_DISK_DIR
    disk_pcrs_path = disk_output_dir / PCRS_FILE

    print_phase("GENERATING MEASUREMENTS", 2, 2)

    log.info("Generating Azure SNP TEE measurements for the base Veritee OS image...")
    write_pcr_measurements(
        disk_output_dir / "disk.raw",
        disk_pcrs_path,
        "azure-snp",
    )
    write_os_security_files(
        disk_output_dir,
        disk_pcrs_path,
    )
    if build_source is not None:
        os_release.record_build(Path.cwd(), disk_output_dir, build_source, command, attestation_mode.value)
    log.info(f"Wrote base Veritee OS image TEE measurements to {disk_output_dir}")

    return stdout


@app.command("hydrate-policy-from-attestation", rich_help_panel=COMMAND_PANEL_IMAGES)
def hydrate_policy_from_attestation(
    attestation_url: Annotated[
        Optional[str],
        typer.Option(
            help=(
                "Full URL of the attestation endpoint. Use the public HTTPS Caddy "
                "endpoint for a deployed VM; local debug servers require an explicit "
                "http://localhost:8000/ URL."
            )
        ),
    ] = None,
    attestation_file: Annotated[
        Optional[Path],
        typer.Option(help="Read a saved attestation response JSON instead of fetching online."),
    ] = None,
    template_policy: Annotated[
        Optional[Path],
        typer.Option(
            help=(
                "Existing policy template whose security intent should be preserved. "
                "Defaults to the output policy if present, then policy.template.json, "
                "then legacy policy.json."
            )
        ),
    ] = None,
    output: Annotated[
        Path,
        typer.Option(help="Policy file to write."),
    ] = DAPP_OUTPUT_DIR / POLICY_FILE,
    pcrs_output: Annotated[
        Optional[Path],
        typer.Option(
            help=(
                "PCR measurements file to update with quote-derived PCR0-3. "
                "Defaults to pcrs.json next to the hydrated policy."
            )
        ),
    ] = None,
    use_tpm2_checkquote: Annotated[
        bool,
        typer.Option(
            "--use-tpm2-checkquote/--parse-tpm2-pcrs-only",
            help=(
                "Use tpm2_checkquote to verify the TPM quote while hydrating PCR0-3. "
                "By default the CLI only parses the PCR blob; Warden performs verification."
            ),
        ),
    ] = False,
    attestation_nonce: Annotated[
        Optional[str],
        typer.Option(
            "--attestation-nonce",
            help="Nonce to send when fetching online attestation. Defaults to a generated nonce.",
        ),
    ] = None,
    resolve_host: Annotated[
        Optional[str],
        typer.Option(
            "--resolve",
            help="Connect to this IP while preserving the HTTPS hostname for TLS and HTTP routing.",
        ),
    ] = None,
    tls_mode: Annotated[
        Optional[str],
        typer.Option(
            "--tls-mode",
            help="Override the TLS mode recorded next to the output policy.",
        ),
    ] = None,
    unbound_attestation: Annotated[
        bool,
        typer.Option(
            "--unbound-attestation/--nonce-bound-attestation",
            help="Fetch online attestation without a nonce. Servers must explicitly allow this for dev/testing.",
        ),
    ] = False,
):
    """Hydrate platform policy fields and quote-derived PCR0-3 from attestation evidence."""
    if (attestation_url is None) == (attestation_file is None):
        raise typer.BadParameter("pass exactly one of --attestation-url or --attestation-file")
    if attestation_file is not None and (
        attestation_nonce is not None
        or resolve_host is not None
        or tls_mode is not None
        or unbound_attestation
    ):
        raise typer.BadParameter(
            "--attestation-nonce, --resolve, --tls-mode internal, and "
            "--unbound-attestation can only be used with --attestation-url"
        )
    if unbound_attestation and normalize_optional_nonce(attestation_nonce) is not None:
        raise typer.BadParameter("--attestation-nonce cannot be used with --unbound-attestation")

    print_phase("HYDRATE TEE POLICY FROM ATTESTATION", 1, 1)
    resolved_pcrs_output = pcrs_output if pcrs_output is not None else output.parent / PCRS_FILE
    resolved_template_policy = (
        template_policy
        if template_policy is not None
        else resolve_policy_template(Path.cwd(), output)
    )

    if attestation_file is not None:
        attestation = load_json_file(attestation_file)
        log.info("Loaded attestation response from %s", attestation_file)
        policy = write_hydrated_policy_from_attestation(
            attestation,
            template_policy=resolved_template_policy,
            output=output,
            pcrs_output=resolved_pcrs_output,
            use_tpm2_checkquote=use_tpm2_checkquote,
        )
    else:
        assert attestation_url is not None
        tls_mode = resolve_attestation_tls_mode(tls_mode, output.parent)
        if tls_mode == "internal":
            log.warning(
                "Bootstrapping the Caddy internal root CA from the static attestation "
                "document; registration must verify the attestation and PCR15 before "
                "the CA is trusted"
            )
        policy = hydrate_policy_from_online_attestation(
            attestation_url,
            template_policy=resolved_template_policy,
            output=output,
            pcrs_output=resolved_pcrs_output,
            use_tpm2_checkquote=use_tpm2_checkquote,
            attestation_nonce=attestation_nonce,
            unbound_attestation=unbound_attestation,
            resolved_host=resolve_host,
            tls_mode=tls_mode,
        )

    mode = policy.get("attestation-type", "unknown")
    log.info(color_text(f" ✓ Wrote {mode} policy to {output}", COLOR_GREEN))
    log.info(color_text(f" ✓ Wrote quote-derived PCR0-3 to {resolved_pcrs_output}", COLOR_GREEN))


@app.command("build-app-disk", rich_help_panel=COMMAND_PANEL_IMAGES)
@build_from_checkout
def build_app_disk(
    image: Annotated[str, typer.Option(help="ACR image to embed in the application disk")],
    app_dir: Annotated[str, typer.Option(help="Path to the application directory. Must contain the application disk run/setup files")] = "",
    tls_mode: Annotated[Optional[str], typer.Option("--tls-mode", help="TLS mode to embed in the DApp disk: internal or azure_vault")] = None,
    tls_keyvault_name: Annotated[Optional[str], typer.Option("--tls-keyvault-name", help="Azure Key Vault name to include in the measured egress policy")] = None,
    allow_warden_egress_profile: Annotated[bool, typer.Option("--allow-warden-egress-profile", help="Permit the broad, measured Warden egress profile")] = False,
    guest_attestation_image: Annotated[Optional[str], typer.Option(help=f"Guest attestation helper image. Defaults to VERITEE_GUEST_ATTESTATION_IMAGE or {DEFAULT_GUEST_ATTESTATION_IMAGE}")] = None,
    verbose: Annotated[bool, typer.Option(help="Show full Earthly build logs")] = False,
):
    """Build the standalone application disk."""
    print_phase("BUILD APPLICATION DISK", 1, 1)

    app_container_image = image.strip()
    if not app_container_image:
        raise typer.BadParameter("image cannot be empty")

    tls_mode = prompt_tls_mode(tls_mode)
    source_app_dir = Path(app_dir)
    source_metadata = load_app_source_metadata(source_app_dir)
    tls_keyvault_name = resolve_packaging_tls_keyvault_name(
        tls_mode=tls_mode,
        app_dir=source_app_dir,
        app_name=source_metadata["name"],
        value=tls_keyvault_name,
    )
    guest_attestation_image = resolve_guest_attestation_image(guest_attestation_image)
    warn_if_anonymous_dockerhub_pull()
    preflight_check_earthly_secrets(EARTHLY_APP_DISK_TARGET)
    acr_name = require_acr_name()
    registry = acr_registry(acr_name)
    acr_token = get_acr_access_token(acr_name)

    if not verbose:
        print_quiet_earthly_hint()

    with prepared_app_build_source(
        source_app_dir,
        tls_mode=tls_mode,
        tls_keyvault_name=tls_keyvault_name,
        app_container_image=app_container_image,
        allow_warden_egress_profile=allow_warden_egress_profile,
    ) as (build_app_dir, _):
        preflight_check_earthly_copy_sources(
            EARTHLY_APP_DISK_TARGET,
            {"APP_DIR": build_app_dir},
        )
        command = build_earthly_app_disk_command(
            app_dir=build_app_dir,
            app_container_image=app_container_image,
            guest_attestation_image=guest_attestation_image,
            registry=registry,
            acr_token=acr_token,
            tls_mode=tls_mode,
        )
        display_command = redact_earthly_command(command)
        log.info("Earthly (+dapp-appdisk) pulls from %s and builds local/application_disk.raw.", registry)

        stdout = run_streamable_command(
            command,
            verbose=verbose,
            cwd=Path.cwd(),
            display_command=display_command,
        )

    log.info(color_text(" ✓ Application disk ready in local/.", COLOR_GREEN))

    return stdout


@app.command("package-dapp-deployable-vm-image", rich_help_panel=COMMAND_PANEL_IMAGES)
@build_from_checkout
def package_dapp_deployable_vm_image(
    app_dir: Annotated[Optional[Path], typer.Option(help="DApp source directory containing metadata.json; defaults to examples/dapp in the checkout")] = None,
    push: Annotated[bool, typer.Option("--push/--no-push", help="Push the deployable VM image to Azure Container Registry")] = True,
    debug: Annotated[bool, typer.Option()] = False,
    persist_size: Annotated[
        Optional[str],
        typer.Option(
            help=(
                "Size of the persistent partition, for example 2G or 4096M. "
                "Defaults to metadata.json persist_size, then 2G"
            ),
            show_default=False,
        ),
    ] = None,
    tls_mode: Annotated[Optional[str], typer.Option("--tls-mode", help="TLS mode to embed in the DApp disk: internal or azure_vault")] = None,
    tls_keyvault_name: Annotated[Optional[str], typer.Option("--tls-keyvault-name", help="Azure Key Vault name to include in the measured egress policy")] = None,
    allow_warden_egress_profile: Annotated[bool, typer.Option("--allow-warden-egress-profile", help="Permit the broad, measured Warden egress profile")] = False,
    guest_attestation_image: Annotated[Optional[str], typer.Option(help=f"Guest attestation helper image. Defaults to VERITEE_GUEST_ATTESTATION_IMAGE or {DEFAULT_GUEST_ATTESTATION_IMAGE}")] = None,
    verbose: Annotated[bool, typer.Option(help="Show full Earthly build logs")] = False,
    os_release_key: Annotated[Optional[str], typer.Option(help="Advanced override: accepted OS manifest SHA-256. Otherwise resolve metadata.base_os_image automatically.")] = None,
    registration_preflight: Annotated[bool, typer.Option("--registration-preflight/--no-registration-preflight", help="Validate against Warden's rebuild recipe before packaging. Disable only for operator images not submitted for registration.")] = True,
):
    """Package a deployable VM image by extending a base Veritee OS image with a DApp."""
    if debug:
        raise DeployerException(
            "Debug deployable VM images are not supported yet. Package a release image instead."
        )

    app_dir_path = Path(app_dir)
    metadata = load_app_source_metadata(app_dir_path)
    tls_mode = prompt_tls_mode(tls_mode)
    tls_keyvault_name = resolve_packaging_tls_keyvault_name(
        tls_mode=tls_mode, app_dir=app_dir_path, app_name=metadata["name"], value=tls_keyvault_name,
    )
    guest_attestation_image = resolve_guest_attestation_image(guest_attestation_image)
    profile = local_registration_profile()
    validation = validate_dapp_packaging(
        app_dir_path, metadata, tls_mode=tls_mode, tls_keyvault_name=tls_keyvault_name,
        guest_image=guest_attestation_image, registration_preflight=registration_preflight,
        allow_warden=allow_warden_egress_profile,
        profile=profile,
    )
    selected_os = os_release.resolve_selection(os_release_key, base_os_image=metadata["base_os_image"])
    validate_dapp_packaging(
        app_dir_path, metadata, tls_mode=tls_mode, tls_keyvault_name=tls_keyvault_name,
        guest_image=guest_attestation_image, registration_preflight=registration_preflight,
        allow_warden=allow_warden_egress_profile, profile=validation["profile"], selected_os=selected_os,
    )
    selected_manifest = json.loads(selected_os["manifest"])
    if os_release.carrier_identity(metadata["base_os_image"]) != os_release.carrier_identity(selected_manifest["publication"]["reference"]):
        raise DeployerException("Project base_os_image disagrees with the selected accepted OS manifest")
    persist_size = resolve_persist_size(persist_size, metadata)
    acr_name = require_acr_name()
    registry = acr_registry(acr_name)
    deployable_vm_image = resolve_deployable_vm_image(metadata, acr_name)

    print_phase("PACKAGE INTRO & METADATA", 1, 6)

    log.info("=== Veritee package-dapp-deployable-vm-image ===")
    log.info(
        "This is a packaging operation, not a plain docker build. Veritee pulls a "
        "base Veritee OS image and an application container image from ACR, embeds "
        "the app into dm-verity partitions on an Azure SNP-ready VM image, and "
        "generates TEE measurements used for attestation."
    )
    log.info(f"DApp: {metadata['name']}")
    log.info(f"Description: {metadata['description']}")
    log.info("TLS mode: %s", tls_mode)
    if tls_keyvault_name is not None:
        log.info("Key Vault: %s", tls_keyvault_name)
    print_quiet_earthly_hint()

    warn_if_anonymous_dockerhub_pull()
    preflight_check_earthly_secrets(EARTHLY_EXTEND_OS_TARGET)
    log.info(
        color_text(
            f" ✓ Preflight: +{EARTHLY_EXTEND_OS_TARGET} secrets are satisfiable.",
            COLOR_GREEN,
        )
    )

    print_phase("PULL BASE VERITEE OS IMAGE", 2, 6)
    os_image_dir = Path.cwd() / DEFAULT_OS_DISK_DIR
    print_tee_step(f"Pulling base Veritee OS image from ACR ({metadata['base_os_image']})...")
    os_release.pull_selected(selected_os, os_image_dir)
    log.info(color_text(" ✓ Base Veritee OS image and measurements pulled.", COLOR_GREEN))

    print_phase("PACKAGE DEPLOYABLE VM IMAGE", 3, 6)

    acr_token = get_acr_access_token(acr_name)
    print_tee_step(
        f"Pulling application container image from ACR ({metadata['app_container_image']})..."
    )
    log.info(
        "Earthly (+veritee-os-azure-snp-extend-os) packages the application "
        "container image, creates app/persist partitions, and extends the "
        "base Veritee OS image."
    )

    with prepared_app_build_source(
        app_dir_path,
        tls_mode=tls_mode,
        tls_keyvault_name=tls_keyvault_name,
        allow_warden_egress_profile=allow_warden_egress_profile,
    ) as (build_app_dir, shipped_metadata):
        if pack_validation.source_tree(app_dir_path) != validation["source"]:
            raise DeployerException("App source changed during packaging preflight; retry with stable inputs")
        staged_source = pack_validation.source_tree(Path(build_app_dir))
        expected_files = dict(validation["source"]["files"])
        expected_files[APP_METADATA_FILE] = pack_validation.file_hash(Path(build_app_dir) / APP_METADATA_FILE)
        if (staged_source["files"] != expected_files
                or staged_source["directories"] != validation["source"]["directories"]
                or shipped_metadata != validation["shipped_metadata"]):
            raise DeployerException("App source changed while staging; retry with stable inputs")
        preflight_check_earthly_copy_sources(
            EARTHLY_EXTEND_OS_TARGET,
            {
                "APP_DIR": build_app_dir,
                "OS_RAW": str(DEFAULT_OS_DISK_DIR / "disk.raw"),
            },
        )
        log.info(
            color_text(
                f" ✓ Preflight: +{EARTHLY_EXTEND_OS_TARGET} COPY sources are present.",
                COLOR_GREEN,
            )
        )

        command = build_earthly_extend_os_command(
            app_dir=build_app_dir,
            persist_size=persist_size,
            app_container_image=metadata["app_container_image"],
            guest_attestation_image=guest_attestation_image,
            registry=registry,
            acr_token=acr_token,
            tls_mode=tls_mode,
        )
        display_command = redact_earthly_command(command)

        stdout = run_streamable_command(
            command,
            verbose=verbose,
            cwd=Path.cwd(),
            display_command=display_command,
        )

    log.info(color_text(" ✓ Deployable VM image packaging finished.", COLOR_GREEN))

    print_phase("TEE METADATA GENERATION", 4, 6)

    vm_image_output_dir = Path.cwd() / DAPP_OUTPUT_DIR
    disk_pcrs_path = vm_image_output_dir / PCRS_FILE

    print_tee_step("Generating Azure SNP TEE metadata for the deployable VM image...")
    application_root_hash = write_application_root_hash(
        vm_image_output_dir / "disk.manifest",
        disk_pcrs_path,
        require_app_label=True,
    )
    log.info(f"Application root hash (dm-verity app partition): {application_root_hash}")

    write_pcr_measurements(
        vm_image_output_dir / "disk.raw",
        disk_pcrs_path,
        "azure-snp",
    )
    pcr4 = load_pcr4_measurement(disk_pcrs_path)
    if pcr4 != selected_os["entry"]["pcr4"]:
        raise DeployerException("Packaged VM PCR4 differs from selected OS release")
    write_json(vm_image_output_dir / "os-release-selection.json", selected_os)
    log.info(f"Azure SNP PCR4 measurement: {pcr4}")

    policy_template = resolve_policy_template(Path.cwd(), vm_image_output_dir / POLICY_FILE)
    write_os_security_files(
        vm_image_output_dir,
        disk_pcrs_path,
        policy_template,
    )
    write_app_metadata(vm_image_output_dir, shipped_metadata)
    write_tls_mode(vm_image_output_dir, tls_mode)
    snapshot = pack_validation.make_snapshot(
        app_dir_path, (vm_image_output_dir / APP_METADATA_FILE).read_bytes(), tls_mode,
        guest_attestation_image, application_root_hash, pcr4, selected_os,
        validation["profile"], source_record=validation["source"],
    )
    snapshot["registration_preflight"] = registration_preflight
    snapshot_path = vm_image_output_dir / pack_validation.SNAPSHOT_FILE
    write_json(snapshot_path, snapshot)
    snapshot_path.chmod(0o600)
    log.info(color_text(
        f" ✓ Wrote metadata, TLS mode, policy template, application root hash, and PCR measurements to {DAPP_OUTPUT_DIR}/", COLOR_GREEN))

    print_phase("VHD CONVERSION", 5, 6)

    deployment_root = Path.cwd() / "cli"
    print_tee_step("Converting the deployable VM image to an Azure-compatible VHD...")
    resize_azure_disk(deployment_root, vm_image_output_dir)

    print_phase("PUBLISH & COMPLETE", 6, 6)

    if push:
        print_tee_step(f"Pushing deployable VM image to ACR ({deployable_vm_image})...")
        ensure_publish_disk_space(vm_image_output_dir, deployable_vm_push_artifacts())
        push_scratch_artifact_image(
            acr_name,
            deployable_vm_image,
            vm_image_output_dir,
            deployable_vm_push_artifacts(),
        )
        log.info(color_text(f" ✓ Published deployable VM image: {deployable_vm_image}", COLOR_GREEN))
    else:
        log.info("Skipping ACR push (--no-push).")

    log.info(
        "Deployable VM image ready. Deploy with: veritee create-vm --azuresnp"
    )

    return stdout

@app.command(rich_help_panel=COMMAND_PANEL_IMAGES)
def build_guest_attestation():
    """Build the guest attestation helper from this checkout."""
    print_phase("BUILD GUEST ATTESTATION IMAGE", 1, 1)
    log.info("Building the guest attestation Docker image...")
    command = "docker build -t guest-attestation:local server/guest_attestation".split()
    run_checked(command, stdin=sys.stdin)


@app.command("upload-tls-certs", rich_help_panel=COMMAND_PANEL_DEPLOYMENT)
def upload_tls_certs(
    app_dir: Annotated[Path, typer.Option(help="DApp source directory containing metadata.json")] = DEFAULT_APP_DIR,
    tls_keyvault_name: Annotated[Optional[str], typer.Option("--tls-keyvault-name", help="Azure Key Vault name. Defaults from the DApp metadata name.")] = None,
    resource_group: Annotated[Optional[str], typer.Option("--resource-group", help="Azure resource group for the Key Vault. Defaults from the DApp name.")] = None,
    location: Annotated[Optional[str], typer.Option("--location", help="Azure location used when creating the Key Vault.")] = None,
    fullchain: Annotated[Optional[Path], typer.Option("--fullchain", help="Path to fullchain.pem")] = None,
    privkey: Annotated[Optional[Path], typer.Option("--privkey", help="Path to privkey.pem")] = None,
):
    """Upload TLS certificate files to the convention-based Azure Key Vault secrets."""
    metadata_file, metadata = load_tls_vault_metadata(app_dir)

    print_phase("TLS CERTIFICATE UPLOAD DETAILS", 1, 3)
    log.info("Metadata: %s", metadata_file)
    log.info("DApp: %s", metadata["name"])

    subscription_id = os.getenv("ARM_SUBSCRIPTION_ID", "").strip()
    if not subscription_id:
        raise DeployerException(
            "ARM_SUBSCRIPTION_ID environment variable is not set. "
            "Set it to your Azure subscription ID and try again."
        )

    log.info("Azure subscription: %s", subscription_id)
    log.info("Azure Vault TLS uses runtime certs from Key Vault; no certs are written to the DApp disk.")
    log.info("Press Enter to accept the suggested value in [brackets], or type a different one.")

    vault_name = resolve_tls_keyvault_name(
        tls_mode="azure_vault",
        app_name=metadata["name"],
        value=tls_keyvault_name,
        prompt=True,
    )
    assert vault_name is not None

    default_rg = default_tls_keyvault_resource_group(metadata["name"])
    if resource_group is None:
        resource_group = typer.prompt("Enter Azure Key Vault resource group name", default=default_rg)
    resource_group = resource_group.strip()
    if not resource_group:
        raise typer.BadParameter("Azure resource group cannot be empty")

    if location is None:
        location = typer.prompt("Enter Azure Key Vault location", default="eastus")
    location = location.strip()
    if not location:
        raise typer.BadParameter("Azure location cannot be empty")

    fullchain = prompt_existing_file(
        "Path to fullchain.pem",
        fullchain,
        Path("fullchain.pem"),
        "TLS fullchain",
    )
    privkey = prompt_existing_file(
        "Path to privkey.pem",
        privkey,
        Path("privkey.pem"),
        "TLS private key",
    )

    log.info("TLS fullchain: %s", fullchain)
    log.info("TLS private key: %s", privkey)

    print_phase("AZURE KEY VAULT SETUP", 2, 3)
    log.info("Azure Key Vault: %s", vault_name)
    log.info("Azure resource group: %s", resource_group)
    log.info("Azure location: %s", location)
    log.info("Secrets: %s, %s", TLS_FULLCHAIN_SECRET_NAME, TLS_PRIVKEY_SECRET_NAME)

    vault_id = ensure_tls_keyvault(
        vault_name=vault_name,
        resource_group=resource_group,
        location=location,
        subscription_id=subscription_id,
    )
    log.info(color_text(f" ✓ Key Vault ready: {vault_id}", COLOR_GREEN))

    print_phase("UPLOAD TLS CERTS TO AZURE KEY VAULT", 3, 3)
    run_checked_with_retries(
        [
            "az",
            "keyvault",
            "secret",
            "set",
            "--vault-name",
            vault_name,
            "--name",
            TLS_FULLCHAIN_SECRET_NAME,
            "--file",
            str(fullchain),
            "--subscription",
            subscription_id,
            "--output",
            "none",
        ],
        attempts=12,
        delay_seconds=5,
    )
    run_checked_with_retries(
        [
            "az",
            "keyvault",
            "secret",
            "set",
            "--vault-name",
            vault_name,
            "--name",
            TLS_PRIVKEY_SECRET_NAME,
            "--file",
            str(privkey),
            "--subscription",
            subscription_id,
            "--output",
            "none",
        ],
        attempts=12,
        delay_seconds=5,
        display_command=[
            "az",
            "keyvault",
            "secret",
            "set",
            "--vault-name",
            vault_name,
            "--name",
            TLS_PRIVKEY_SECRET_NAME,
            "--file",
            "<private-key>",
            "--subscription",
            subscription_id,
            "--output",
            "none",
        ],
    )

    log.info(color_text(" ✓ Uploaded TLS certificate secrets to Azure Key Vault.", COLOR_GREEN))


@app.command("init-inventory", rich_help_panel=COMMAND_PANEL_DEPLOYMENT)
def init_inventory(
    resource_group: Annotated[
        str,
        typer.Option(
            "--resource-group",
            help="Resource group for shared inventory infrastructure",
        ),
    ] = DEFAULT_INVENTORY_RESOURCE_GROUP,
    location: Annotated[
        str,
        typer.Option(
            "--location",
            help="Azure region used when creating inventory infrastructure",
        ),
    ] = DEFAULT_INVENTORY_LOCATION,
    storage_account: Annotated[
        Optional[str],
        typer.Option(
            "--storage-account",
            help="Inventory Storage account name; defaults to a subscription-derived name",
        ),
    ] = None,
    container: Annotated[
        Optional[str],
        typer.Option(
            "--container",
            help=f"Inventory container name; defaults to {DEFAULT_INVENTORY_CONTAINER}",
        ),
    ] = None,
):
    """Create or reuse shared Azure infrastructure for deployment inventory."""
    subscription_id = require_azure_subscription_id()
    resource_group = resource_group.strip()
    location = location.strip()
    if not resource_group:
        raise typer.BadParameter("--resource-group cannot be empty")
    if not location:
        raise typer.BadParameter("--location cannot be empty")

    requested_account = storage_account or os.getenv(
        INVENTORY_STORAGE_ACCOUNT_ENV_VAR,
        "",
    )
    requested_account = requested_account.strip()
    accounts = query_azure_storage_accounts(subscription_id)
    tagged_accounts = [
        account
        for account in accounts
        if isinstance(account.get("tags"), dict)
        and str(account["tags"].get(INVENTORY_COMPONENT_TAG, "")).lower()
        == INVENTORY_COMPONENT_TAG_VALUE
    ]

    if requested_account:
        account_name = validate_inventory_storage_account(requested_account)
        existing_account = next(
            (
                account
                for account in accounts
                if str(account.get("name", "")).lower() == account_name
            ),
            None,
        )
    elif len(tagged_accounts) == 1:
        existing_account = tagged_accounts[0]
        account_name = validate_inventory_storage_account(
            str(existing_account.get("name", ""))
        )
    elif len(tagged_accounts) > 1:
        names = ", ".join(
            sorted(str(account.get("name", "")) for account in tagged_accounts)
        )
        raise DeployerException(
            "Multiple Veritee inventory Storage accounts already exist "
            f"({names}). Select one with --storage-account."
        )
    else:
        existing_account = None
        account_name = default_inventory_storage_account(subscription_id)

    container_name = validate_inventory_container(
        container
        or os.getenv(INVENTORY_CONTAINER_ENV_VAR, DEFAULT_INVENTORY_CONTAINER)
    )

    print_phase("INITIALIZE AZURE DEPLOYMENT INVENTORY", 1, 1)
    if existing_account is None:
        run_checked(
            [
                "az",
                "group",
                "create",
                "--name",
                resource_group,
                "--location",
                location,
                "--subscription",
                subscription_id,
                "--tags",
                f"{INVENTORY_COMPONENT_TAG}={INVENTORY_COMPONENT_TAG_VALUE}",
                "--output",
                "none",
            ]
        )
        run_checked(
            [
                "az",
                "storage",
                "account",
                "create",
                "--name",
                account_name,
                "--resource-group",
                resource_group,
                "--location",
                location,
                "--sku",
                "Standard_LRS",
                "--kind",
                "StorageV2",
                "--https-only",
                "true",
                "--min-tls-version",
                "TLS1_2",
                "--allow-blob-public-access",
                "false",
                "--allow-shared-key-access",
                "false",
                "--public-network-access",
                "Enabled",
                "--tags",
                f"{INVENTORY_COMPONENT_TAG}={INVENTORY_COMPONENT_TAG_VALUE}",
                "--subscription",
                subscription_id,
                "--output",
                "none",
            ]
        )
        account_resource_group = resource_group
    else:
        account_resource_group = str(
            existing_account.get("resourceGroup", "")
        ).strip()
        if not account_resource_group:
            raise DeployerException(
                f"Inventory Storage account {account_name} has no resource group"
            )
        log.info(
            "Reusing inventory Storage account %s in resource group %s.",
            account_name,
            account_resource_group,
        )

    wait_for_inventory_storage_account(account_name, subscription_id)
    run_checked(
        [
            "az",
            "storage",
            "account",
            "update",
            "--name",
            account_name,
            "--resource-group",
            account_resource_group,
            "--set",
            f"tags.{INVENTORY_COMPONENT_TAG}={INVENTORY_COMPONENT_TAG_VALUE}",
            "--subscription",
            subscription_id,
            "--output",
            "none",
        ]
    )
    ensure_inventory_blob_access(account_name, subscription_id)
    ensure_inventory_container(account_name, container_name, subscription_id)

    log.info(color_text(" ✓ Azure deployment inventory is ready.", COLOR_GREEN))
    typer.echo(f"Storage account: {account_name}")
    typer.echo(f"Container: {container_name}")


AZURE_VHD_SOURCE_RAW_HASH_FILE = "disk.img.vhd.source-raw.sha256"
AZURE_VHD_HASH_FILE = "disk.img.vhd.sha256"
AZURE_VHD_LEGACY_RAW_HASH_FILE = "disk.img.vhd.raw.sha256"
VHD_FOOTER_SIZE = 512
VHD_FOOTER_COOKIE = b"conectix"
VHD_FOOTER_TIMESTAMP_OFFSET = 24
VHD_FOOTER_CHECKSUM_OFFSET = 64
VHD_FOOTER_UNIQUE_ID_OFFSET = 68
VHD_FIXED_TIMESTAMP = 0


def qemu_virtual_size(path: Path) -> int:
    result = run_checked(["qemu-img", "info", "--output", "json", str(path)])
    try:
        payload = json.loads(result.stdout)
        return int(payload["virtual-size"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise DeployerException(f"Could not read qemu virtual size for {path}") from exc


def azure_vhd_size_mib(byte_size: int) -> int:
    if byte_size <= 0:
        raise DeployerException(f"Invalid disk size: {byte_size}")

    return (byte_size + 1024 * 1024 - 1) // (1024 * 1024)


def deterministic_azure_vhd_uuid(raw_hash: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", raw_hash):
        raise DeployerException(f"Invalid SHA-256 hash for Azure VHD UUID: {raw_hash!r}")

    return (
        f"{raw_hash[0:8]}-{raw_hash[8:12]}-"
        f"5{raw_hash[13:16]}-8{raw_hash[17:20]}-{raw_hash[20:32]}"
    )


def azure_vhd_footer_checksum(footer: bytes) -> int:
    if len(footer) != VHD_FOOTER_SIZE:
        raise DeployerException(f"Invalid Azure VHD footer size: {len(footer)}")

    checksum_footer = bytearray(footer)
    checksum_footer[
        VHD_FOOTER_CHECKSUM_OFFSET : VHD_FOOTER_CHECKSUM_OFFSET + 4
    ] = b"\0\0\0\0"
    return ~sum(checksum_footer) & 0xFFFFFFFF


def patch_fixed_azure_vhd_footer(vhd_path: Path, raw_hash: str) -> None:
    unique_id = bytes.fromhex(deterministic_azure_vhd_uuid(raw_hash).replace("-", ""))

    with vhd_path.open("r+b") as vhd:
        vhd.seek(-VHD_FOOTER_SIZE, os.SEEK_END)
        footer = bytearray(vhd.read(VHD_FOOTER_SIZE))
        if (
            len(footer) != VHD_FOOTER_SIZE
            or footer[: len(VHD_FOOTER_COOKIE)] != VHD_FOOTER_COOKIE
        ):
            raise DeployerException(f"{vhd_path} does not look like a fixed Azure VHD")

        footer[
            VHD_FOOTER_TIMESTAMP_OFFSET : VHD_FOOTER_TIMESTAMP_OFFSET + 4
        ] = VHD_FIXED_TIMESTAMP.to_bytes(4, "big")
        footer[VHD_FOOTER_UNIQUE_ID_OFFSET : VHD_FOOTER_UNIQUE_ID_OFFSET + 16] = unique_id
        footer[
            VHD_FOOTER_CHECKSUM_OFFSET : VHD_FOOTER_CHECKSUM_OFFSET + 4
        ] = b"\0\0\0\0"
        checksum = azure_vhd_footer_checksum(footer)
        footer[VHD_FOOTER_CHECKSUM_OFFSET : VHD_FOOTER_CHECKSUM_OFFSET + 4] = checksum.to_bytes(
            4,
            "big",
        )

        vhd.seek(-VHD_FOOTER_SIZE, os.SEEK_END)
        vhd.write(footer)


def resize_azure_disk(_deployment_root: Path, disk_dir: Path) -> int:
    raw_path = disk_dir / "disk.raw"
    vhd_path = disk_dir / "disk.img.vhd"
    azure_raw_path = disk_dir / "disk.azure.raw.tmp"
    vhd_tmp_path = disk_dir / "disk.img.vhd.tmp"
    source_raw_hash_path = disk_dir / AZURE_VHD_SOURCE_RAW_HASH_FILE
    vhd_hash_path = disk_dir / AZURE_VHD_HASH_FILE

    if not raw_path.exists():
        raise DeployerException(f"Required raw disk not found: {raw_path}")

    raw_hash = sha256_file(raw_path)
    if (
        vhd_path.exists()
        and source_raw_hash_path.exists()
        and vhd_hash_path.exists()
        and source_raw_hash_path.read_text().strip() == raw_hash
    ):
        vhd_hash = sha256_file(vhd_path)
        if vhd_hash_path.read_text().strip() == vhd_hash:
            log.info("Reusing existing Azure VHD %s; raw disk and VHD hashes match.", vhd_path)
            return qemu_virtual_size(vhd_path)

        log.warning("Existing Azure VHD hash mismatch; regenerating %s.", vhd_path)

    disk_size_mib = azure_vhd_size_mib(qemu_virtual_size(raw_path))

    try:
        if shutil.which("fallocate") is not None:
            run_checked(["fallocate", "--dig-holes", str(raw_path)])
        run_checked(
            ["cp", "--reflink=auto", "--sparse=always", str(raw_path), str(azure_raw_path)]
        )
        run_checked(
            ["qemu-img", "resize", "-f", "raw", str(azure_raw_path), f"{disk_size_mib}M"]
        )
        run_checked(
            [
                "qemu-img",
                "convert",
                "-q",
                "-f",
                "raw",
                "-o",
                "subformat=fixed,force_size",
                "-O",
                "vpc",
                str(azure_raw_path),
                str(vhd_tmp_path),
            ]
        )
        patch_fixed_azure_vhd_footer(vhd_tmp_path, raw_hash)
        run_checked(
            ["qemu-img", "compare", "-q", "-f", "raw", "-F", "vpc",
             str(azure_raw_path), str(vhd_tmp_path)]
        )
        parsed_disk_size = qemu_virtual_size(vhd_tmp_path)
        vhd_tmp_path.replace(vhd_path)
    finally:
        azure_raw_path.unlink(missing_ok=True)
        vhd_tmp_path.unlink(missing_ok=True)

    source_raw_hash_path.write_text(raw_hash + "\n")
    vhd_hash_path.write_text(sha256_file(vhd_path) + "\n")
    (disk_dir / AZURE_VHD_LEGACY_RAW_HASH_FILE).unlink(missing_ok=True)
    return parsed_disk_size


@app.command(rich_help_panel=COMMAND_PANEL_DEPLOYMENT)
def create_vm(
    azure_snp: Annotated[bool, typer.Option("--azuresnp", help="Deploy to Azure SEV-SNP")] = False,
    resource_group: Annotated[Optional[str], typer.Option("--resource-group", help="New Azure resource group for this immutable deployment")] = None,
    location: Annotated[Optional[str], typer.Option("--location", help="Azure region for this deployment")] = None,
    vm_size: Annotated[
        Optional[str],
        typer.Option(
            "--vm-size",
            help=(
                "Azure confidential VM size "
                f"(default: {DEFAULT_AZURE_VM_SIZE})"
            ),
            show_default=False,
        ),
    ] = None,
    tls_keyvault_name: Annotated[Optional[str], typer.Option("--tls-keyvault-name", help="Azure Key Vault name for azure_vault TLS mode")] = None,
    vm_name: Annotated[Optional[str], typer.Option(help="Azure VM name for this immutable deployment")] = None,
    gallery_name: Annotated[Optional[str], typer.Option(help="Azure Compute Gallery name for this immutable deployment")] = None,
    resume_deployment_id: Annotated[Optional[str], typer.Option("--resume-deployment-id", help="Resume interrupted provisioning from its local Terraform state, only before any VM has been created")] = None,
    attestation_domain_name: Annotated[Optional[str], typer.Option(help="Public Caddy hostname for live attestation. Defaults from the packaged DApp Caddyfile.")] = None,
    hydrate_policy: Annotated[
        bool,
        typer.Option(
            "--hydrate-policy/--no-hydrate-policy",
            help="After Azure SNP deployment, fetch attestation from the VM and hydrate local policy.json.",
        ),
    ] = True,
    use_tpm2_checkquote: Annotated[
        bool,
        typer.Option(
            "--use-tpm2-checkquote/--parse-tpm2-pcrs-only",
            help=(
                "Use tpm2_checkquote when create-vm hydrates PCR0-3. "
                "By default the CLI only parses the PCR blob; Warden performs verification."
            ),
        ),
    ] = False,
    unbound_attestation: Annotated[
        bool,
        typer.Option(
            "--unbound-attestation/--nonce-bound-attestation",
            help="Hydrate policy without sending an attestation nonce. Servers must explicitly allow this for dev/testing.",
        ),
    ] = False,
):
    """Create a new immutable Azure SEV-SNP deployment."""
    if not azure_snp:
        raise typer.BadParameter("pass --azuresnp to select the deployment target")

    repo_root = repo_root_from_cwd()
    metadata_dir = repo_root / DAPP_OUTPUT_DIR
    metadata = load_app_metadata(metadata_dir / APP_METADATA_FILE)
    app_name = metadata["name"]
    measurements = load_tee_measurements(metadata_dir / PCRS_FILE)
    application_root_hash = validate_sha256_hex(
        measurements["application_root_hash"],
        "application_root_hash",
    )
    created_at_value = datetime.now(timezone.utc)
    created_at = utc_timestamp(created_at_value)
    if resume_deployment_id is not None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]+", resume_deployment_id):
            raise typer.BadParameter("Invalid --resume-deployment-id")
        deployment_id = resume_deployment_id
    else:
        deployment_id = generate_deployment_id(app_name, created_at=created_at_value)
    tf_home = repo_root / TERRAFORM_WORK_ROOT / "deploy-azure-snp" / deployment_id

    print_phase("VM DETAILS", 1, 3)

    metadata_file = metadata_dir / APP_METADATA_FILE
    tls_mode_path = metadata_dir / TLS_MODE_FILE
    tls_mode = read_tls_mode_file(tls_mode_path) if tls_mode_path.is_file() else "internal"
    try:
        pack_validation.verify_snapshot(metadata_file, None, tls_mode)
    except (ValueError, KeyError, UnicodeError, OSError) as error:
        raise DeployerException(f"Deployment input drift: {error}") from error
    if hydrate_policy:
        attestation_domain_name = resolve_optional_deployment_attestation_domain(
            metadata_file,
            attestation_domain_name,
        )
        if attestation_domain_name is None:
            hydrate_policy = False
    if sys.stdin.isatty():
        log.info("Press Enter to accept the suggested value in [brackets], or type a different one.")
    packaged_tls_keyvault_name = load_json_file(metadata_file).get("tls_keyvault_name")
    if packaged_tls_keyvault_name is not None:
        if not isinstance(packaged_tls_keyvault_name, str):
            raise DeployerException(
                "Packaged tls_keyvault_name must be a string"
            )
        packaged_tls_keyvault_name = validate_tls_keyvault_name(packaged_tls_keyvault_name)
        if tls_keyvault_name is not None and tls_keyvault_name != packaged_tls_keyvault_name:
            raise DeployerException(
                "--tls-keyvault-name does not match the Key Vault bound into the "
                "packaged outbound policy"
            )
        tls_keyvault_name = packaged_tls_keyvault_name
    tls_keyvault_name = resolve_tls_keyvault_name(
        tls_mode=tls_mode,
        app_name=app_name,
        value=tls_keyvault_name,
        prompt=(
            tls_mode == "azure_vault"
            and packaged_tls_keyvault_name is None
            and sys.stdin.isatty()
        ),
    )
    resource_group = resolve_deployment_option(
        resource_group,
        option_name="--resource-group",
        prompt="Enter Azure resource group name",
        default=default_deployment_resource_group(deployment_id),
    )
    location = resolve_deployment_option(
        location,
        option_name="--location",
        prompt="Enter Azure location",
        default="eastus",
    )
    vm_size = resolve_vm_size(vm_size)
    vm_name = resolve_deployment_option(
        vm_name,
        option_name="--vm-name",
        prompt="Enter Azure VM name",
        default=default_vm_name_for_app(app_name),
    )
    gallery_name = resolve_deployment_option(
        gallery_name,
        option_name="--gallery-name",
        prompt="Enter Azure Compute Gallery name",
        default=default_gallery_name_for_app(app_name),
    )

    subscription_id = require_azure_subscription_id()
    inventory_storage_account, inventory_container = require_inventory_storage(
        subscription_id
    )
    git_sha = current_git_sha(repo_root)
    if resume_deployment_id is not None:
        group = validate_incomplete_deployment_resume(
            tf_home, resource_group, subscription_id, deployment_id, app_name,
        )
        created_at = resource_group_tags(group).get("temenos_created_at", created_at)
    deployment_tags = build_deployment_tags(
        metadata=metadata,
        application_root_hash=application_root_hash,
        deployment_id=deployment_id,
        vm_name=vm_name,
        created_at=created_at,
        git_sha=git_sha,
        tls_mode=tls_mode,
        tls_keyvault_name=tls_keyvault_name,
    )

    # All operator input and durable-inventory configuration is checked before
    # Terraform or the multi-gigabyte VHD conversion starts.
    Deployer.assert_available()
    ensure_inventory_storage_is_external(
        inventory_storage_account,
        resource_group,
        subscription_id,
    )
    if resume_deployment_id is None:
        ensure_resource_group_is_new(resource_group, subscription_id)
    ensure_inventory_container(
        inventory_storage_account,
        inventory_container,
        subscription_id,
    )
    operator = azure_operator(subscription_id)

    cloud = "deploy-azure-snp"
    deployment_root = repo_root / "cli"
    disk_dir = repo_root / DAPP_OUTPUT_DIR
    vhd_path = disk_dir / "disk.img.vhd"
    log.info("Converting %s to a deterministic Azure VHD (reads and rewrites the full image)...", disk_dir / "disk.raw")
    tf_vars = {
        "disk_size": resize_azure_disk(deployment_root, disk_dir),
        "vhd_path": str(vhd_path),
        "resource_group_name": resource_group,
        "resource_group_location": location,
        "instance_type": vm_size,
        "tls_keyvault_name": tls_keyvault_name or "",
        "vm_name": vm_name,
        "gallery_name": gallery_name,
        "deployment_tags": json.dumps(deployment_tags, separators=(",", ":")),
    }
    # resize_azure_disk has just verified or generated this exact VHD checksum.
    # Forward it rather than asking Terraform to rehash a multi-gigabyte file
    # during both planning and applying. Legacy direct Terraform calls retain
    # their filesha256 fallback.
    verified_hash_path = disk_dir / AZURE_VHD_HASH_FILE
    if verified_hash_path.is_file():
        tf_vars["vhd_sha256"] = validate_sha256_hex(
            verified_hash_path.read_text().strip(), "verified Azure VHD checksum",
        )

    print_phase("VM DEPLOYMENT", 2, 3)

    base_os_disk = metadata.get("base_os_image") or str(vhd_path)
    build_image = metadata.get("deployable_vm_image") or metadata.get("app_container_image") or str(vhd_path)

    log.info("App name     = %s", app_name)
    log.info("Deployment ID = %s", deployment_id)
    log.info("Resource group = %s", resource_group)
    log.info("VM name      = %s", vm_name)
    log.info("VM size      = %s", vm_size)
    log.info("Gallery name = %s", gallery_name)
    log.info("Veritee disk = %s", base_os_disk)
    log.info("Build image  = %s", build_image)
    log.info("TLS mode     = %s", tls_mode)
    if tls_keyvault_name is not None:
        log.info("Key Vault    = %s", tls_keyvault_name)

    print_tee_step(f"Deploying {app_name} on a CVM...")
    if tf_home.exists() and resume_deployment_id is None:
        raise DeployerException(
            f"Deployment work directory already exists: {tf_home}"
        )
    Deployer.init(tf_home, cloud)
    res = Deployer.launch_runner(tf_home, tf_vars)

    actual_resource_group = str(res.get("resource_group_name") or resource_group)
    if actual_resource_group != resource_group:
        raise DeployerException(
            "Terraform returned a different resource group than requested: "
            f"{actual_resource_group}"
        )

    output_tags = {
        key: str(value)
        for key, value in {
            "temenos_storage_account": res.get("storage_account_name"),
            "temenos_storage_container": res.get("storage_container_name"),
            "temenos_vm_principal_id": res.get("vm_principal_id"),
        }.items()
        if value
    }
    merge_resource_group_tags(
        actual_resource_group,
        output_tags,
        subscription_id,
    )
    all_tags = {**deployment_tags, **output_tags}
    public_ip = str(res.get("public_ip_address") or "unknown")
    append_inventory_record(
        storage_account=inventory_storage_account,
        container=inventory_container,
        subscription_id=subscription_id,
        deployment_id=deployment_id,
        event="created",
        record={
            "resource_group": actual_resource_group,
            "location": str(res.get("location") or location),
            "tags": all_tags,
            "public_ip": public_ip,
            "vm_principal_id": str(res.get("vm_principal_id") or ""),
            "operator": operator,
        },
    )

    print_tee_step("Deployable VM image uploaded to Azure and attached to the VM.")
    log.info(color_text(" ✓ Azure deployment complete.", COLOR_GREEN))
    print_phase("DEPLOYMENT RESULT AND COMPLETE", 3, 3)
    log.info("Deployment ID: %s", deployment_id)
    log.info("Resource group: %s", actual_resource_group)
    log.info("VM name: %s", res.get("vm_name", "unknown"))
    log.info("Public IP: %s", public_ip)
    if hydrate_policy and public_ip != "unknown":
        policy_output = disk_dir / POLICY_FILE
        assert attestation_domain_name is not None
        attestation_url = f"https://{attestation_domain_name}/tee_attestation"
        print_tee_step("Hydrating TEE policy from the deployed VM attestation...")
        if tls_mode == "internal":
            log.warning(
                "Bootstrapping the Caddy internal root CA from the static attestation "
                "document; the Warden must verify the attestation and PCR15 before "
                "the CA is trusted"
            )
        try:
            policy = hydrate_policy_after_create_vm(
                attestation_url,
                repo_root=repo_root,
                output=policy_output,
                pcrs_output=disk_dir / PCRS_FILE,
                use_tpm2_checkquote=use_tpm2_checkquote,
                unbound_attestation=unbound_attestation,
                resolved_host=public_ip,
                tls_mode=tls_mode,
            )
            mode = policy.get("attestation-type", "unknown")
            log.info(color_text(f" ✓ Hydrated {mode} policy at {policy_output}", COLOR_GREEN))
        except DeployerException as exc:
            try:
                template_hint = resolve_policy_template(repo_root, policy_output)
            except DeployerException:
                template_hint = repo_root / POLICY_TEMPLATE_FILE
            log.warning("Could not hydrate policy from deployed VM attestation: %s", exc)
            log.info(
                "Retry once the VM is ready with: veritee hydrate-policy-from-attestation "
                "--attestation-url %s --template-policy %s --output %s --pcrs-output %s%s",
                attestation_url,
                template_hint,
                policy_output,
                disk_dir / PCRS_FILE,
                (
                    f" --resolve {public_ip}"
                    f"{' --unbound-attestation' if unbound_attestation else ''}"
                ),
            )
    elif public_ip != "unknown":
        policy_output = disk_dir / POLICY_FILE
        pcrs_output = disk_dir / PCRS_FILE
        template_hint = policy_output if policy_output.exists() else repo_root / POLICY_TEMPLATE_FILE
        manual_attestation_url = (
            f"https://{attestation_domain_name}/tee_attestation"
            if attestation_domain_name is not None
            else "https://<attestation-domain>/tee_attestation"
        )
        log.info(
            "Hydrate policy from this VM with: veritee hydrate-policy-from-attestation "
            "--attestation-url %s --resolve %s --template-policy %s --output %s "
            "--pcrs-output %s",
            manual_attestation_url,
            public_ip,
            template_hint,
            policy_output,
            pcrs_output,
        )

    typer.echo(f"Deployment ID: {deployment_id}")


def deployment_summary(resource_group: dict) -> dict[str, str]:
    tags = resource_group_tags(resource_group)
    return deployment_summary_from_tags(
        resource_group=str(resource_group.get("name") or ""),
        tags=tags,
    )


def deployment_summary_from_tags(
    *,
    resource_group: str,
    tags: dict[str, str],
) -> dict[str, str]:
    return {
        "deployment_id": tags.get(VERITEE_DEPLOYMENT_ID_TAG, ""),
        "resource_group": resource_group,
        "app_name": tags.get("temenos_app_name", ""),
        "vm_name": tags.get("temenos_vm_name", ""),
        "created_at": tags.get("temenos_created_at", ""),
        "application_root_hash": tags.get("temenos_app_root_hash", ""),
        "app_image": tags.get("temenos_app_image", ""),
        "base_os_image": tags.get("temenos_base_os_image", ""),
        "tls_mode": tags.get("temenos_tls_mode", ""),
    }


def print_deployment_details(resource_group: dict) -> None:
    summary = deployment_summary(resource_group)
    fields = (
        ("Deployment ID", summary["deployment_id"]),
        ("DApp", summary["app_name"]),
        ("Resource group", summary["resource_group"]),
        ("VM", summary["vm_name"]),
        ("Created", summary["created_at"]),
        ("TLS mode", summary["tls_mode"]),
        ("Base OS", summary["base_os_image"]),
        ("DApp image", summary["app_image"]),
        ("Application root hash", summary["application_root_hash"]),
    )
    label_width = max(len(label) for label, _ in fields)
    for label, value in fields:
        typer.echo(f"{label.ljust(label_width)} : {value or '-'}")


def deployment_history_summaries(
    records: list[dict],
    live_resource_groups: list[dict],
) -> list[dict[str, str]]:
    live_by_id = {
        summary["deployment_id"]: summary
        for summary in (
            deployment_summary(group) for group in live_resource_groups
        )
        if summary["deployment_id"]
    }
    records_by_id: dict[str, list[dict]] = {}
    for record in records:
        deployment_id = str(record.get("deployment_id") or "").strip()
        if not deployment_id:
            raise DeployerException(
                f"Deployment inventory record {record.get('blob_name', '<unknown>')} "
                "has no deployment_id"
            )
        records_by_id.setdefault(deployment_id, []).append(record)

    rows = []
    for deployment_id in sorted(set(records_by_id) | set(live_by_id)):
        if deployment_id in live_by_id:
            summary = dict(live_by_id[deployment_id])
            summary["status"] = "active"
            rows.append(summary)
            continue

        deployment_records = records_by_id[deployment_id]
        created_record = next(
            (
                record
                for record in deployment_records
                if record.get("event") == "created"
            ),
            deployment_records[0],
        )
        tags: dict[str, str] = {}
        for record in deployment_records:
            record_tags = record.get("tags")
            if isinstance(record_tags, dict):
                tags.update(
                    {str(key): str(value) for key, value in record_tags.items()}
                )
        summary = deployment_summary_from_tags(
            resource_group=str(created_record.get("resource_group") or ""),
            tags=tags,
        )
        summary["deployment_id"] = deployment_id
        latest_event = str(deployment_records[-1].get("event") or "unknown")
        summary["status"] = {
            "destroyed": "destroyed",
            "destroy_requested": "destroy requested",
            "created": "missing",
        }.get(latest_event, latest_event.replace("_", " "))
        rows.append(summary)

    return sorted(rows, key=lambda item: item["created_at"])


def reconcile_destroy_requested_statuses(
    rows: list[dict[str, str]],
    subscription_id: str,
) -> None:
    pending = [row for row in rows if row.get("status") == "destroy requested"]
    if pending:
        log.info(
            "Checking Azure state for %s pending deletion%s...",
            len(pending),
            "" if len(pending) == 1 else "s",
        )
    for row in pending:
        resource_group = row.get("resource_group", "")
        if resource_group and not azure_resource_group_exists(
            resource_group,
            subscription_id,
        ):
            row["status"] = "destroyed"


def print_deployment_rows(
    rows: list[dict[str, str]],
    *,
    include_status: bool = False,
) -> None:
    columns = [
        ("DEPLOYMENT ID", "deployment_id"),
        ("RESOURCE GROUP", "resource_group"),
        ("DAPP", "app_name"),
        ("VM", "vm_name"),
        ("CREATED", "created_at"),
        ("BASE OS", "base_os_image"),
        ("APPLICATION ROOT HASH", "application_root_hash"),
    ]
    if include_status:
        columns.insert(2, ("STATUS", "status"))
    widths = {
        key: max(len(label), *(len(row.get(key, "")) for row in rows))
        for label, key in columns
    }
    typer.echo("  ".join(label.ljust(widths[key]) for label, key in columns))
    for row in sorted(rows, key=lambda item: item["created_at"]):
        typer.echo(
            "  ".join(row.get(key, "").ljust(widths[key]) for _, key in columns)
        )


def print_deployment_history(
    records: list[dict],
    *,
    storage_account: str,
    container: str,
) -> None:
    typer.echo(f"Inventory account   : {storage_account}")
    typer.echo(f"Inventory container : {container}")
    typer.echo()

    rows = []
    for record in records:
        operator = record.get("operator")
        operator_name = (
            str(operator.get("name") or "")
            if isinstance(operator, dict)
            else ""
        )
        keep_image = record.get("keep_image")
        rows.append(
            {
                "recorded_at": str(record.get("recorded_at") or ""),
                "event": str(record.get("event") or ""),
                "resource_group": str(record.get("resource_group") or ""),
                "operator": operator_name,
                "keep_image": "-" if keep_image is None else str(bool(keep_image)).lower(),
                "blob_name": str(record.get("blob_name") or ""),
            }
        )

    columns = (
        ("RECORDED", "recorded_at"),
        ("EVENT", "event"),
        ("RESOURCE GROUP", "resource_group"),
        ("OPERATOR", "operator"),
        ("KEEP IMAGE", "keep_image"),
        ("BLOB", "blob_name"),
    )
    widths = {
        key: max(len(label), *(len(row[key]) for row in rows))
        for label, key in columns
    }
    typer.echo("  ".join(label.ljust(widths[key]) for label, key in columns))
    for row in rows:
        typer.echo("  ".join(row[key].ljust(widths[key]) for _, key in columns))


def confirm_destroy(resource_group_name: str, yes: bool) -> None:
    if yes:
        return
    if not sys.stdin.isatty():
        raise typer.BadParameter(
            "--yes is required when stdin is not a TTY"
        )
    if not typer.confirm(
        f"Delete immutable Veritee deployment resource group {resource_group_name}?",
        default=False,
    ):
        raise typer.Abort()


@app.command("list-deployments", rich_help_panel=COMMAND_PANEL_DEPLOYMENT)
def list_deployments(
    as_json: Annotated[bool, typer.Option("--json", help="Print deployment summaries as JSON")] = False,
    include_all: Annotated[
        bool,
        typer.Option("--all", help="Include historical deployments from inventory records"),
    ] = False,
):
    """List live or historical immutable Veritee deployments."""
    subscription_id = require_azure_subscription_id()
    log.info("Querying Azure for live Veritee deployments...")
    resource_groups = query_managed_resource_groups(subscription_id)
    if include_all:
        storage_account, container = require_inventory_storage(subscription_id)
        log.info(
            "Querying deployment history from %s/%s...",
            storage_account,
            container,
        )
        records = load_inventory_records(
            storage_account=storage_account,
            container=container,
            subscription_id=subscription_id,
        )
        rows = deployment_history_summaries(records, resource_groups)
        reconcile_destroy_requested_statuses(rows, subscription_id)
    else:
        rows = [deployment_summary(group) for group in resource_groups]

    if as_json:
        typer.echo(json.dumps(rows, indent=2))
        return

    if not rows:
        if include_all:
            typer.echo("No Veritee deployment history found.")
        else:
            typer.echo(
                "No live Veritee deployments found. "
                "Use `veritee list-deployments --all` to include deployment history."
            )
        return

    print_deployment_rows(rows, include_status=include_all)


@app.command("deployment-history", rich_help_panel=COMMAND_PANEL_DEPLOYMENT)
def deployment_history(
    deployment_id: Annotated[str, typer.Argument(help="Veritee deployment id")],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Print complete audit records as JSON"),
    ] = False,
):
    """Show the durable audit history for one deployment."""
    subscription_id = require_azure_subscription_id()
    storage_account, container = require_inventory_storage(subscription_id)
    log.info(
        "Querying deployment history for %s from %s/%s...",
        deployment_id,
        storage_account,
        container,
    )
    records = load_inventory_records(
        storage_account=storage_account,
        container=container,
        subscription_id=subscription_id,
        deployment_id=deployment_id,
    )
    if not records:
        raise DeployerException(
            f"No deployment history found for {deployment_id}"
        )
    if as_json:
        typer.echo(json.dumps(records, indent=2))
        return

    print_deployment_history(
        records,
        storage_account=storage_account,
        container=container,
    )


@app.command("destroy-vm", rich_help_panel=COMMAND_PANEL_DEPLOYMENT)
def destroy_vm(
    deployment_id: Annotated[Optional[str], typer.Option("--deployment-id", help="Veritee deployment id to destroy")] = None,
    resource_group: Annotated[Optional[str], typer.Option("--resource-group", help="Veritee-managed Azure resource group to destroy")] = None,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm destruction without prompting")] = False,
    keep_image: Annotated[bool, typer.Option("--keep-image", help="Copy the measured VHD to durable inventory storage before deletion")] = False,
):
    """Destroy one immutable Veritee deployment and preserve its audit record."""
    if bool(deployment_id) == bool(resource_group):
        raise typer.BadParameter(
            "Pass exactly one of --deployment-id or --resource-group"
        )
    if not yes and not sys.stdin.isatty():
        raise typer.BadParameter("--yes is required when stdin is not a TTY")

    print_phase("VALIDATE DEPLOYMENT DESTRUCTION REQUEST", 1, 4)
    subscription_id = require_azure_subscription_id()
    inventory_storage_account, inventory_container = require_inventory_storage(
        subscription_id
    )
    selected = resolve_managed_resource_group(
        subscription_id=subscription_id,
        deployment_id=deployment_id,
        resource_group=resource_group,
    )
    selected_name = str(selected.get("name") or "").strip()
    if not selected_name:
        raise DeployerException("Azure resource group has no name")
    tags = resource_group_tags(selected)
    resolved_deployment_id = tags.get(VERITEE_DEPLOYMENT_ID_TAG, "").strip()
    if not resolved_deployment_id:
        raise DeployerException(
            f"Resource group {selected_name} has no {VERITEE_DEPLOYMENT_ID_TAG} tag"
        )

    print_deployment_details(selected)
    confirm_destroy(selected_name, yes)

    print_phase("PRESERVE DEPLOYMENT AUDIT RECORD", 2, 4)
    ensure_inventory_storage_is_external(
        inventory_storage_account,
        selected_name,
        subscription_id,
    )
    ensure_inventory_container(
        inventory_storage_account,
        inventory_container,
        subscription_id,
    )
    retained_image = None
    if keep_image:
        retained_image = preserve_deployment_vhd(
            resource_group=selected,
            inventory_storage_account=inventory_storage_account,
            inventory_container=inventory_container,
            subscription_id=subscription_id,
        )
        log.info("Retained measured VHD as %s", retained_image)
    else:
        log.info("Measured VHD retention was not requested.")

    operator = azure_operator(subscription_id)
    destroy_record = {
        "resource_group": selected_name,
        "tags": tags,
        "operator": operator,
        "keep_image": keep_image,
        "retained_image": retained_image,
    }
    append_inventory_record(
        storage_account=inventory_storage_account,
        container=inventory_container,
        subscription_id=subscription_id,
        deployment_id=resolved_deployment_id,
        event="destroy_requested",
        record=destroy_record,
    )
    log.info(
        color_text(" ✓ Destroy request recorded in durable inventory.", COLOR_GREEN)
    )

    print_phase("CLEAN UP EXTERNAL ACCESS", 3, 4)
    remove_external_keyvault_role_assignment(selected, subscription_id)
    if tags.get("temenos_tls_mode") == "azure_vault":
        log.info(
            color_text(
                " ✓ Removed the VM identity's external Key Vault access.",
                COLOR_GREEN,
            )
        )
    else:
        log.info("No external TLS Key Vault access to remove.")

    print_phase("DELETE AZURE DEPLOYMENT", 4, 4)
    log.info(
        "Deleting Azure resource group %s and all deployment resources...",
        selected_name,
    )
    delete_resource_group_and_wait(selected_name, subscription_id)
    append_inventory_record(
        storage_account=inventory_storage_account,
        container=inventory_container,
        subscription_id=subscription_id,
        deployment_id=resolved_deployment_id,
        event="destroyed",
        record=destroy_record,
    )
    log.info(
        color_text(
            f" ✓ Destroyed Veritee deployment {resolved_deployment_id}.",
            COLOR_GREEN,
        )
    )
