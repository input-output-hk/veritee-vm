#!/usr/bin/env python3
"""Exercise a DApp project's host proxy hop with real Docker networking."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request
import uuid

import yaml


ROOT = Path(__file__).resolve().parents[1]
CADDY = "caddy@sha256:25cdc846626b62d05f6b633b9b40c2c9f6ef89b515dc76133cefd920f7dbe562"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-dir", type=Path, default=ROOT / "projects/proof_server_preprod")
    parser.add_argument("--app-port", type=int, choices=(80, 6300), default=6300)
    args = parser.parse_args()
    authored = yaml.safe_load((args.app_dir / "run.d/docker-compose.yml").read_text())
    project = "veritee-proxy-test-" + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix="veritee-proxy-test-") as temporary:
        work = Path(temporary)
        (work / "certs").mkdir()
        template = (args.app_dir / "run.d/Caddyfile.template").read_text()
        (work / "Caddyfile.generated").write_text(
            template.replace("{{ATTESTATION_TLS}}", "tls internal")
            .replace("{{APP_TLS}}", "tls internal")
        )
        services = {name: authored["services"][name] for name in ("caddy", "app")}
        services["caddy"]["image"] = CADDY
        services["caddy"]["environment"]["APP_UPSTREAM"] = f"app:{args.app_port}"
        services["app"]["image"] = CADDY
        services["app"]["command"] = [
            "caddy", "file-server", "--listen", f":{args.app_port}",
            "--root", "/usr/share/caddy",
        ]
        proxy_ports = [
            str(port).split(":")[-1]
            for port in services["caddy"].get("ports", [])
            if str(port).startswith("127.0.0.1:8080:")
        ]
        if len(proxy_ports) != 1 or services["app"].get("ports"):
            raise RuntimeError("the host proxy must publish only through loopback Caddy")
        # Keep the authored upstream port, using a free host port for the test.
        services["caddy"]["ports"] = ["127.0.0.1::" + proxy_ports[0]]
        config = {"services": services, "networks": authored["networks"],
                  "volumes": authored["volumes"]}
        compose_file = work / "compose.json"
        compose_file.write_text(json.dumps(config))
        command = ["docker", "compose", "--project-name", project, "-f", str(compose_file)]
        try:
            subprocess.run(command + ["up", "-d"], check=True)
            address = subprocess.check_output(
                command + ["port", "caddy", proxy_ports[0]], text=True
            ).strip()
            # Reach this host's own Docker port directly, independently of HTTP_PROXY.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            for attempt in range(40):
                try:
                    with opener.open("http://" + address + "/", timeout=2) as response:
                        if response.status != 200 or b"Caddy" not in response.read():
                            raise RuntimeError("unexpected host proxy response")
                    break
                except OSError:
                    if attempt == 39:
                        raise
                    time.sleep(.5)
            app_id = subprocess.check_output(command + ["ps", "-q", "app"], text=True).strip()
            inspected = json.loads(subprocess.check_output(["docker", "inspect", app_id], text=True))[0]
            for network in inspected["NetworkSettings"]["Networks"]:
                detail = json.loads(subprocess.check_output(
                    ["docker", "network", "inspect", network], text=True
                ))[0]
                if detail["Internal"] is not True:
                    raise RuntimeError("app gained a non-internal network")
            subprocess.run(["docker", "exec", app_id, "wget", "--help"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            admin = subprocess.run(
                ["docker", "exec", app_id, "wget", "-T", "2", "-q", "-O", "-",
                 "http://caddy:2019/pki/ca/local"], capture_output=True,
            )
            if admin.returncode == 0:
                raise RuntimeError("app can access Caddy's private control API")
            print(json.dumps({"host_proxy_http_status": 200, "app_port": args.app_port, "app_networks_internal": True,
                              "private_admin_inaccessible_to_app": True}))
        except BaseException:
            subprocess.run(command + ["logs", "--no-color"])
            raise
        finally:
            subprocess.run(command + ["down", "--volumes", "--remove-orphans"], check=True)


if __name__ == "__main__":
    main()
