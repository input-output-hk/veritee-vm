"""Phase-one release sidecars. Nothing here modifies a measured app file."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Optional
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import requests
import typer


from . import build as native_build
from .os_release_carrier import fetch_carrier, read_json, verify_files

BASE_OS_TARGET = "+veritee-os-azure-snp"
LEGACY_BASE_OS_TARGET = "+temen-os-tpm"


def release_env(name, default=None):
    if name in os.environ:
        return os.environ[name]
    return os.environ.get(name.replace("VERITEE_", "TEMENOS_", 1), default)

commands = typer.Typer(help="Approve and inspect immutable base-OS releases. Phase one does not rebuild the OS.",
                       pretty_exceptions_show_locals=False)


def canonical(value):
    # Closed phase-one schemas: integral safe numbers and valid Unicode only.
    # Sort UTF-16 units, not Python's Unicode scalar order (RFC 8785).
    if value is None or type(value) is bool:
        return json.dumps(value)
    if type(value) is int:
        if abs(value) > 2**53 - 1:
            raise ValueError("unsafe JSON integer")
        return str(value)
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        keys = sorted(value, key=lambda k: k.encode("utf-16be"))
        return "{" + ",".join(canonical(k) + ":" + canonical(value[k]) for k in keys) + "}"
    raise ValueError("unsupported phase-one JSON value")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def carrier_identity(reference):
    """Compare repository/digest while retaining the original signed spelling."""
    if (not isinstance(reference, str) or ".." in reference or
            not re.fullmatch(r"[a-z0-9.-]+/[a-z0-9_./-]+(?::[A-Za-z0-9_.-]+)?@sha256:[0-9a-f]{64}", reference)):
        raise ValueError("OS carrier must be digest-pinned")
    repository, hash_value = reference.split("@")
    return repository.split(":")[0] + "@" + hash_value


def file_descriptor(path):
    path = Path(path)
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return {"name": path.name, "sha256": h.hexdigest(), "size": str(path.stat().st_size)}


def source_identity(repository):
    def git(*args):
        return subprocess.run(["git", *args], cwd=repository, check=True, capture_output=True, text=True).stdout.strip()
    modified = bool(git("status", "--porcelain", "--untracked-files=normal"))
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"), "modified": modified}


def record_build(repository, output, source, command, mode):
    if source_identity(repository) != source:
        raise ValueError("source changed during OS build")
    record = {"version": 1, "source": source, "command": command, "attestation_mode": mode,
              "artifacts": [file_descriptor(Path(output) / name) for name in ("disk.raw", "pcrs.json")]}
    if command[:4] == ["python3", "-m", "veritee.build", "azure-snp-base"]:
        record["dockerfile_sha256"] = digest((Path(repository) / "build/Dockerfile").read_bytes())
    (Path(output) / "os-build.json").write_text(canonical(record), encoding="utf-8")


def create_manifest(input_dir, release_id, version, reference, source_repository):
    carrier_identity(reference)
    directory = Path(input_dir)
    record = read_json((directory / "os-build.json").read_bytes())
    mode = record["attestation_mode"]
    # Preserve the actual config name in historical build records and manifests.
    recipes = (
        (BASE_OS_TARGET, "config-azure.yaml"),
        (BASE_OS_TARGET, "config-snp-azure.yaml"),
        (LEGACY_BASE_OS_TARGET, "config-snp-azure.yaml"),
    )
    expected = [
        (["earthly", "--no-cache", "-P", target, f"--OS_CONFIG={config}",
          f"--ATTESTATION_MODE={mode}", "--ALLOW_UNBOUND_ATTESTATION=false"], config)
        for target, config in recipes
    ]
    configuration = next((config for command, config in expected if record["command"] == command), None)
    build = {"command": "build-base-os-image", "recipe_version": 1, "earthly_target": record["command"][3],
             "profile": "azure-snp", "configuration": configuration,
             "arguments": {"ATTESTATION_MODE": mode, "ALLOW_UNBOUND_ATTESTATION": False}}
    if record["command"] == native_build.base_command("config-azure.yaml", mode, False):
        configuration = "config-azure.yaml"
        dockerfile_hash = record.get("dockerfile_sha256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", dockerfile_hash):
            raise ValueError("missing recorded Dockerfile hash")
        build = {**build, "recipe_version": 2, "configuration": configuration,
                 "docker_target": "azure-snp-os-builder", "dockerfile": "build/Dockerfile",
                 "dockerfile_sha256": dockerfile_hash}
        del build["earthly_target"]
    if configuration is None or mode not in ("maa", "raw-sev-snp") or record["source"]["modified"] is not False:
        raise ValueError("not a supported bound Azure SNP release build")
    artifacts = [file_descriptor(directory / name) for name in ("disk.raw", "pcrs.json")]
    if artifacts != record["artifacts"]:
        raise ValueError("build outputs changed after the recorded build")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", release_id) or not 0 < len(version.encode()) <= 32 or len(canonical(version).encode()) > 34:
        raise ValueError("invalid release id/version")
    pcr4 = read_json((directory / "pcrs.json").read_bytes())["measurements"]["4"]
    if not re.fullmatch(r"[0-9a-f]{64}", pcr4):
        raise ValueError("invalid PCR4")
    return {"version": 1, "release_id": release_id, "release_version": version, "attestation_mode": mode,
            "source": {"repository": source_repository, **record["source"]},
            "build": build,
            "publication": {"reference": reference, "platform": "linux/amd64"}, "artifacts": artifacts,
            "measurements": {"pcr4": pcr4, "pcr4_bank": "sha256", "pcr4_profile": "azure_cvm"}}


def sign_manifest(manifest_bytes, private_key, audience, request_id, now, validity):
    manifest = read_json(manifest_bytes)
    if canonical(manifest).encode() != manifest_bytes:
        raise ValueError("release manifest must be canonical JSON with no newline")
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("an individual P-256 developer key is required")
    if not 1 <= validity <= 86400:
        raise ValueError("validity must be between 1 and 86400 seconds (Warden may impose a smaller limit)")
    public_der = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    header = {"alg": "ES256", "kid": "sha256:" + digest(public_der), "typ": "application/temenos-os-release-approval+jws"}
    utc = lambda date: date.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = {"version": 1, "type": "temenos_os_release_approval", "operation": "approve_release", "request_id": request_id,
               "audience": audience, "release_manifest_digest": "sha256:" + digest(manifest_bytes),
               "release_id": manifest["release_id"], "decision": "approve", "signed_at": utc(now),
               "expires_at": utc(now + timedelta(seconds=validity))}
    encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    protected, body = encode(canonical(header).encode()), encode(canonical(payload).encode())
    signature = private_key.sign(f"{protected}.{body}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature)
    return {"manifest": manifest_bytes.decode("utf-8"), "jws": {"protected": protected, "payload": body,
            "signature": encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}}


def query_registry(action, **arguments):
    cli = release_env("VERITEE_ATTESTATION_CLI_DIR")
    network, registry = release_env("VERITEE_OS_NETWORK"), release_env("VERITEE_OS_REGISTRY")
    if not cli or not network or not registry or not re.fullmatch(r"[0-9a-f]{64}", registry):
        raise ValueError("Set VERITEE_ATTESTATION_CLI_DIR, VERITEE_OS_NETWORK and VERITEE_OS_REGISTRY")
    command = ["node", "--import=tsx", "src/run.ts", f"--action={action}", f"--network={network}", f"--contract={registry}"]
    command.extend(f"--{k.replace('_', '-')}={v}" for k, v in arguments.items())
    env = {k: v for k, v in os.environ.items() if k not in ("WALLET_SEED", "WARDEN_WALLET_SEED", "POINTER_ADMIN_SEED")}
    result = subprocess.run(command, cwd=cli, env=env, check=True, capture_output=True, text=True, timeout=120)
    for line in reversed(result.stdout.splitlines()):
        if line.startswith(("{", "[", "null")):
            return read_json(line)
    raise ValueError("registry did not return a typed JSON result")


def bounded_response(response, maximum=2 * 1024 * 1024):
    response.raise_for_status()
    if response.is_redirect:
        response.close()
        raise ValueError("OS release redirects are not allowed")
    chunks, length = [], 0
    try:
        for chunk in response.iter_content(64 * 1024):
            length += len(chunk)
            if length > maximum:
                raise ValueError("OS release response size limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        response.close()


def selection_from_entry(key, entry):
    base = release_env("VERITEE_WARDEN_URL", "").rstrip("/")
    if not base.startswith("https://"):
        raise ValueError("VERITEE_WARDEN_URL must be HTTPS for OS manifest retrieval")
    response = requests.get(f"{base}/os/releases/{key}", timeout=120, allow_redirects=False, stream=True)
    selected = read_json(bounded_response(response))
    if selected["entry"] != entry or selected["os_key"] != key or selected["network"] != release_env("VERITEE_OS_NETWORK") or selected["registry_address"] != release_env("VERITEE_OS_REGISTRY"):
        raise ValueError("Warden OS view disagrees with configured ledger")
    manifest_bytes = selected["manifest"].encode("utf-8")
    manifest = read_json(manifest_bytes)
    if digest(manifest_bytes) != key or canonical(manifest).encode() != manifest_bytes:
        raise ValueError("OS manifest digest/canonicalization mismatch")
    if (entry["release_version"] != manifest["release_version"] or entry["pcr4"] != manifest["measurements"]["pcr4"] or
            entry["raw_disk_sha256"] != manifest["artifacts"][0]["sha256"] or entry["attestation_mode"] != manifest["attestation_mode"]):
        raise ValueError("manifest disagrees with typed OS identity")
    verify_acceptance_evidence(selected)
    return selected


def confirmed_selections(*, strict=True):
    entries = query_registry("list-os-releases")
    if not isinstance(entries, list):
        raise ValueError("Invalid OS registry listing")
    seen = set()
    for row in entries:
        key = row.get("os_key") if isinstance(row, dict) else None
        if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key) or key in seen:
            raise ValueError("Invalid or duplicate OS registry entry")
        seen.add(key)
        # The confirmed chain supplies authority; Warden supplies checked bytes.
        try:
            selected = selection_from_entry(key, {field: value for field, value in row.items() if field != "os_key"})
        except (ValueError, KeyError, IndexError, TypeError, InvalidSignature, requests.RequestException) as error:
            if strict:
                raise ValueError(f"Cannot verify OS entry {key}; image resolution is incomplete. "
                                 "Inspect `veritee os-release list` and select a verified release explicitly.") from error
            logging.getLogger("veritee").warning("Skipping unavailable or invalid OS entry %s: %s", key, error)
            continue
        yield selected


def resolve_selection(key=None, *, base_os_image=None):
    identity = carrier_identity(base_os_image) if base_os_image is not None else None
    key = key or release_env("VERITEE_OS_RELEASE_KEY")
    if key is not None:
        if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ValueError("Invalid OS release selector")
        entry = query_registry("get-os-release", os_key=key)
        if not entry:
            raise ValueError("unknown OS release")
        selected = selection_from_entry(key, entry)
    else:
        if not isinstance(base_os_image, str) or not base_os_image:
            raise ValueError("Choose a base_os_image from `veritee os-release list`")
        logging.getLogger("veritee").info("Resolving the approved OS for %s...", base_os_image)
        matches = []
        for candidate in confirmed_selections():
            if carrier_identity(read_json(candidate["manifest"])["publication"]["reference"]) == identity:
                matches.append(candidate)
                if len(matches) > 1:
                    raise ValueError("Multiple approved releases match this OS image; the release operator must disambiguate them")
        if not matches:
            raise ValueError("This OS image has no confirmed approval. Choose an available OS with `veritee os-release list`")
        selected = matches[0]
    if identity is not None and carrier_identity(read_json(selected["manifest"])["publication"]["reference"]) != identity:
        raise ValueError("The OS release selector disagrees with the project's base_os_image")
    return selected


def verify_acceptance_evidence(selected):
    entry, key = selected["entry"], selected["os_key"]
    evidence_bytes = selected["evidence"].encode()
    if entry["evidence_digest"] != "sha256:" + digest(evidence_bytes):
        raise ValueError("acceptance evidence digest mismatch")
    receipt = read_json(evidence_bytes)
    if canonical(receipt).encode() != evidence_bytes or receipt["os_key"] != key or receipt["release_manifest_digest"] != "sha256:" + key:
        raise ValueError("invalid acceptance evidence identity")
    if receipt["acceptance"] != "dev_signature_verified" or entry["acceptance"] != receipt["acceptance"]:
        raise ValueError("unsupported phase-two evidence; use its version-matched client")
    for field, digest_field in (("report", "artifact_report_digest"), ("jws", "signature_digest"), ("payload", "payload_digest")):
        if receipt[digest_field] != "sha256:" + digest(selected[field].encode()):
            raise ValueError("acceptance graph digest mismatch")
    jws = read_json(selected["jws"])
    decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    header, payload = read_json(decode(jws["protected"])), read_json(decode(jws["payload"]))
    if decode(jws["payload"]) != selected["payload"].encode():
        raise ValueError("retained payload does not match the signed bytes")
    public_key = serialization.load_pem_public_key(receipt["developer"]["public_key_pem"].encode())
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("acceptance key is not P-256")
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if header != {"alg": "ES256", "kid": "sha256:" + digest(der), "typ": "application/temenos-os-release-approval+jws"} or header["kid"] != receipt["developer"]["kid"]:
        raise ValueError("acceptance signing identity mismatch")
    raw = decode(jws["signature"])
    if len(raw) != 64:
        raise ValueError("invalid ES256 signature encoding")
    signature = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    public_key.verify(signature, f'{jws["protected"]}.{jws["payload"]}'.encode(), ec.ECDSA(hashes.SHA256()))
    expected_audience = {"warden_id": receipt["audience"]["warden_id"], "network": selected["network"], "os_registry_address": selected["registry_address"]}
    if payload["audience"] != expected_audience or payload["release_manifest_digest"] != "sha256:" + key:
        raise ValueError("approval does not authorize this release/audience")
    enrollment = receipt["configuration"]["developers"].get(header["kid"])
    if (not enrollment or enrollment["identity"] != receipt["developer"]["identity"] or
            enrollment["public_key_pem"] != receipt["developer"]["public_key_pem"] or
            "approve_release" not in enrollment["operations"] or receipt["configuration"]["audience"] != expected_audience):
        raise ValueError("retained enrollment does not authorize the signer")
    stamp = lambda value: datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    limits = receipt["configuration"]["limits"]
    accepted, signed, expires = receipt["accepted_at"], stamp(payload["signed_at"]), stamp(payload["expires_at"])
    if not (0 < expires - signed <= limits["max_validity_seconds"] and
            signed <= accepted + limits["clock_skew_seconds"] and accepted < expires):
        raise ValueError("approval was not valid at retained acceptance time")
    manifest, report = read_json(selected["manifest"]), read_json(selected["report"])
    if (payload["type"] != "temenos_os_release_approval" or payload["operation"] != "approve_release" or
            payload["decision"] != "approve" or payload["version"] != 1 or payload["release_id"] != manifest["release_id"] or
            receipt["raw_disk_sha256"] != entry["raw_disk_sha256"] or receipt["measurements"] != manifest["measurements"] or
            report["artifacts"] != manifest["artifacts"] or report["pcr4"] != entry["pcr4"] or
            report["validation"] != "published_files_checked_not_reproduced"):
        raise ValueError("acceptance report does not describe this published release")


def pull_selected(selected, output):
    manifest = read_json(selected["manifest"])
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        timeout = int(release_env("VERITEE_OS_DOWNLOAD_TIMEOUT_SECONDS", "1800"))
        if not 1 <= timeout <= 86400:
            raise ValueError()
    except ValueError:
        raise ValueError("VERITEE_OS_DOWNLOAD_TIMEOUT_SECONDS must be an integer from 1 to 86400") from None
    with tempfile.TemporaryDirectory(prefix="veritee-os-", dir=output.parent) as temp:
        maximum = sum(int(item["size"]) for item in manifest["artifacts"])
        fetch_carrier(manifest, Path(temp) / "files", maximum + 64 * 1024 * 1024, maximum, timeout)
        output.mkdir(exist_ok=True)
        for item in manifest["artifacts"]:
            os.replace(Path(temp) / "files" / item["name"], output / item["name"])
        verify_files(manifest, output)
        (output / "os-release-selection.json").write_text(canonical(selected), encoding="utf-8")


@commands.command("keygen")
def keygen(private_key: Path = typer.Option(...), public_key: Path = typer.Option(...)):
    """Generate an individual developer key. Enroll only its public half."""
    if private_key.exists() or public_key.exists():
        raise typer.BadParameter("refusing to replace an existing key")
    key = ec.generate_private_key(ec.SECP256R1())
    fd = os.open(private_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with public_key.open("xb") as stream:
        stream.write(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    typer.echo("sha256:" + digest(der))


@commands.command("manifest")
def manifest_command(input_dir: Path = typer.Option(Path("local-base-os")), release_id: str = typer.Option(...),
                     version: str = typer.Option(...), reference: str = typer.Option(...), source_repository: str = typer.Option(...),
                     output: Path = typer.Option(Path("os-release-manifest.json"))):
    value = create_manifest(input_dir, release_id, version, reference, source_repository)
    data = canonical(value).encode()
    with output.open("xb") as stream:
        stream.write(data)
    typer.echo("sha256:" + digest(data))


@commands.command("sign")
def sign_command(manifest: Path = typer.Option(...), private_key: Path = typer.Option(...), warden_id: str = typer.Option(...),
                 network: str = typer.Option(...), registry: str = typer.Option(...), output: Path = typer.Option(...),
                 request_id: Optional[str] = typer.Option(None), validity_seconds: int = typer.Option(3600)):
    if private_key.stat().st_mode & 0o077:
        raise typer.BadParameter("private key permissions must be 0600 or stricter")
    key = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
    envelope = sign_manifest(manifest.read_bytes(), key, {"warden_id": warden_id, "network": network, "os_registry_address": registry},
                             request_id or str(uuid.uuid4()), datetime.now(timezone.utc), validity_seconds)
    with output.open("x", encoding="utf-8") as stream:
        stream.write(canonical(envelope))


@commands.command("submit")
def submit(envelope: Path = typer.Option(...)):
    endpoint = release_env("VERITEE_WARDEN_URL", "").rstrip("/")
    if not endpoint.startswith("https://"):
        raise typer.BadParameter("VERITEE_WARDEN_URL must be HTTPS")
    data = envelope.read_bytes()
    if len(data) > 2 * 1024 * 1024 or canonical(read_json(data)).encode() != data:
        raise typer.BadParameter("expected bounded canonical approval envelope")
    response = requests.post(f"{endpoint}/os/releases/approve", data=data, headers={"Content-Type": "application/json"},
                             timeout=1800, allow_redirects=False, stream=True)
    typer.echo(json.dumps(read_json(bounded_response(response)), indent=2))


@commands.command("list")
def list_releases(as_json: bool = typer.Option(False, "--json", help="Print approved OS releases and their identifiers as JSON")):
    """List available, confirmed OS images for application projects."""
    logging.getLogger("veritee").info("Querying available Veritee OS releases...")
    rows = [{**selected["entry"], "os_key": selected["os_key"],
             "base_os_image": read_json(selected["manifest"])["publication"]["reference"]}
            for selected in confirmed_selections(strict=False)]
    rows = [row for row in rows if re.search(r"@sha256:[0-9a-f]{64}$", row["base_os_image"])]
    rows.sort(key=lambda row: (row["release_version"], row["base_os_image"], row["os_key"]))
    if as_json:
        typer.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        typer.echo("No confirmed, digest-pinned OS releases available.")
        return
    columns = [("OS VERSION", "release_version"), ("MODE", "attestation_mode"), ("IMAGE", "base_os_image")]
    widths = {key: max(len(label), *(len(row[key]) for row in rows)) for label, key in columns}
    typer.echo("  ".join(label.ljust(widths[key]) for label, key in columns))
    for row in rows:
        typer.echo("  ".join(row[key].ljust(widths[key]) for _, key in columns))


@commands.command("select")
def select(key: str = typer.Option(...), output: Path = typer.Option(Path("os-release-selection.json"))):
    selected = resolve_selection(key)
    output.write_text(canonical(selected), encoding="utf-8")
    typer.echo(key)
