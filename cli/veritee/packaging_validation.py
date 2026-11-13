"""Checks and external snapshots for the inputs to a registration rebuild.

None of the records in this module belongs on the measured application disk.
"""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlparse


SNAPSHOT_FILE = "packaged-inputs.json"
PROFILE_VERSION = 1
OVERRIDDEN_FILES = {"metadata.json", "run.d/Caddyfile.template", "run.d/docker-compose.yml"}
GENERATED_CERTS = "run.d/certs"
# These encoded-byte budgets match Warden's native app projection validator.
# Checking this bundled copy requires no requests to a running service.
LIMITS_FILE = "registration-limits-v1.json"


def registration_limits():
    limits = json.loads(Path(__file__).with_name(LIMITS_FILE).read_bytes())
    if type(limits.get("version")) is not int or limits["version"] != 1:
        raise ValueError("Unsupported bundled registration limits version")
    return limits


def encoded_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def exact_text(path):
    # Path.read_text() silently translates CRLF. These bytes must survive the
    # JSON request and Warden's fs::write without newline conversion.
    return Path(path).read_bytes().decode("utf-8")


def excluded_path(relative):
    return (relative == GENERATED_CERTS or relative.startswith(GENERATED_CERTS + "/")
            or relative == ".git" or relative.startswith(".git/"))


def source_tree(directory):
    """Inventory regular files and directories without following symlinks."""
    directory = Path(directory)
    files, directories = {}, []
    def walk(parent):
        for path in sorted(parent.iterdir()):
            relative = path.relative_to(directory).as_posix()
            if excluded_path(relative):
                continue
            if path.is_symlink():
                raise ValueError(f"Unreproducible app source symlink: {relative}")
            if path.is_dir():
                directories.append(relative)
                walk(path)
            elif path.is_file():
                files[relative] = file_hash(path)
            else:
                raise ValueError(f"Unsupported app source file type: {relative}")
    walk(directory)
    return {"files": files, "directories": sorted(directories)}


def conf_files(parent):
    result = {}
    for path in sorted(Path(parent).glob("*.conf")):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Invalid repart definition: {path.name}")
        result[path.name] = file_hash(path)
    return result


def local_profile(repository, guest_image):
    repository = Path(repository)
    template = source_tree(repository / "examples/dapp")
    return {
        "version": PROFILE_VERSION,
        "app_details": registration_limits(),
        "rebuild": {
            "guest_attestation_image": guest_image,
            "allow_warden_egress_profile": False,
            "fixed_files": {p: h for p, h in template["files"].items() if p not in OVERRIDDEN_FILES},
            "directories": template["directories"],
            "repart_files": conf_files(repository / "veritee-os/app-disk"),
            "fallback_scripts": {
                p: file_hash(repository / "veritee-os/app-disk" / p)
                for p in ("run.d/main", "setup.d/main")
            },
            "excluded_paths": [GENERATED_CERTS, ".git"],
        },
    }


def require_pinned_image(reference, field):
    # Accept tag@digest spelling, including registries with a port. Do not
    # resolve or rewrite a caller's tag and change measured metadata.
    if (not isinstance(reference, str) or not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", reference)
            or "://" in reference or any(c in reference for c in "?#\\")):
        raise ValueError(f"{field} must be pinned as <image>@sha256:<64 lowercase hex digits>")


def image_identity(reference):
    require_pinned_image(reference, "container image")
    repository, digest = reference.split("@")
    last_slash = repository.rfind("/")
    tag = repository.find(":", last_slash + 1)
    return (repository[:tag] if tag >= 0 else repository) + "@" + digest


def validate_projection(projection, profile, *, complete=True):
    details = profile["app_details"]
    for field, value in projection.items():
        budget = details["field_encoded_bytes"][field]
        size = len(encoded_json(value))
        if size > budget:
            raise ValueError(f"app field {field} uses {size} JSON-encoded UTF-8 bytes; maximum is {budget} (including quotes/escapes)")
    if complete and len(encoded_json(projection)) > details["max_bytes"]:
        raise ValueError(f"app_details exceeds {details['max_bytes']} encoded bytes")


def normalized_endpoint(address):
    address = address.strip().rstrip("/")
    parsed = urlparse(address if address.startswith(("http://", "https://")) else "http://" + address)
    if (not parsed.hostname or parsed.scheme not in ("http", "https")
            or parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment
            or parsed.username is not None or parsed.password is not None or parsed.port is not None):
        raise ValueError("DApp address must be only an IP address or base URL, without a port or credentials")
    host = parsed.hostname.lower()
    try:
        ip = ipaddress.ip_address(host)
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        host = host.encode("idna").decode("ascii")
    return parsed.scheme + "://" + host


def projection(metadata, address, domain, tls_mode, *, version="", os_key=None):
    endpoint = normalized_endpoint(address)
    domain = domain.strip().rstrip(".").lower()
    return {
        "name": metadata["name"].strip(), "description": metadata.get("description", ""),
        "address": endpoint, "deployment_url": endpoint,
        "attestation_url": "https://" + domain, "attestation_domain_name": domain,
        "tls_mode": tls_mode, "public_key": "", "application_id": "0" * 64,
        "base_os_version": version,
        "base_os_release_manifest_digest": "sha256:" + os_key if os_key else None,
    }


def guest_site_addresses(caddyfile):
    """Mirror the released launcher's awk site_host, including CRLF behavior."""
    result, depth = [], 0
    for line in caddyfile.split("\n"):
        # awk's default FS recognizes space/tab, not a final carriage return.
        fields = [v for v in re.split(r"[ \t]+", line.strip(" \t")) if v]
        if not fields or fields[0].startswith("#"):
            continue
        if fields[0] == "}":
            depth -= 1
            continue
        if depth == 0 and len(fields) >= 2 and fields[-1] == "{" and fields[0] != "{":
            result.append(fields[0])
        if fields[-1] == "{":
            depth += 1
    return result


def validate_rebuild(source, platform_dir, profile, guest_image, allow_warden, repository):
    rebuild = profile["rebuild"]
    if image_identity(guest_image) != image_identity(rebuild["guest_attestation_image"]):
        raise ValueError("Guest attestation image differs from the Warden's bundled rebuild pin")
    if allow_warden and not rebuild["allow_warden_egress_profile"]:
        raise ValueError("The Warden registration builder does not accept --allow-warden-egress-profile")
    actual = source_tree(source)
    files = actual["files"]
    fixed, fallbacks = rebuild["fixed_files"], rebuild["fallback_scripts"]
    for path, digest in files.items():
        if path in OVERRIDDEN_FILES:
            continue
        expected = fixed.get(path, fallbacks.get(path))
        if digest != expected:
            raise ValueError(f"Warden cannot reproduce app file {path}: only metadata.json, Caddyfile.template and docker-compose.yml are submitted")
    for path, digest in fixed.items():
        if files.get(path) != digest:
            raise ValueError(f"App source is missing or changes Warden template file {path}")
    allowed_dirs = set(rebuild["directories"]) | {"run.d", "setup.d"}
    if set(actual["directories"]) - allowed_dirs:
        raise ValueError("Warden cannot reproduce extra app directories: " + ", ".join(sorted(set(actual["directories"]) - allowed_dirs)))
    if conf_files(platform_dir) != rebuild["repart_files"]:
        raise ValueError("App repart definitions differ from the Warden rebuild recipe")
    for path, digest in fallbacks.items():
        if file_hash(Path(repository) / "veritee-os/app-disk" / path) != digest:
            raise ValueError(f"Local default script differs from Warden's recipe: {path}")
    return actual


def make_snapshot(source, shipped_metadata, tls_mode, guest_image, root_hash, pcr4, selected_os, profile, source_record=None):
    return {
        "version": 1, "source": source_record if source_record is not None else source_tree(source),
        "repart_files": profile["rebuild"]["repart_files"],
        "metadata_sha256": hashlib.sha256(shipped_metadata).hexdigest(),
        "tls_mode": tls_mode, "guest_attestation_image": guest_image,
        "application_root_hash": root_hash, "pcr4": pcr4,
        "os_key": selected_os["os_key"], "os_network": selected_os["network"],
        "os_registry_address": selected_os["registry_address"],
        "os_release_version": selected_os["entry"]["release_version"],
        "build_recipe": profile,
    }


def verify_snapshot(metadata_file, source, tls_mode=None):
    path = Path(metadata_file).parent / SNAPSHOT_FILE
    if not path.exists():
        return None
    snapshot = json.loads(path.read_bytes())
    if type(snapshot.get("version")) is not int or snapshot["version"] != 1:
        raise ValueError("Unsupported packaged-inputs snapshot version; repackage the image")
    if file_hash(metadata_file) != snapshot["metadata_sha256"]:
        raise ValueError("Packaged metadata changed after packaging; repackage the image")
    if tls_mode is not None and snapshot["tls_mode"] != tls_mode:
        raise ValueError("TLS mode differs from the packaged image; repackage the image")
    if source is not None:
        if source_tree(source) != snapshot["source"]:
            raise ValueError("App source changed after packaging; repackage the image")
    pcrs = json.loads((Path(metadata_file).parent / "pcrs.json").read_bytes())
    if (pcrs.get("application_root_hash") != snapshot["application_root_hash"]
            or pcrs.get("measurements", {}).get("4") != snapshot["pcr4"]):
        raise ValueError("Packaged measurements differ from the input snapshot; repackage the image")
    return snapshot
