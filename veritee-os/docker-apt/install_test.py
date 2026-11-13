"""Exercise the pinned mkosi/APT path without building or booting an OS disk."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    mkosi, packages, package_manager, result_path = sys.argv[1:]
    lock = json.loads((Path(__file__).parent / "lock.json").read_text())
    packages = Path(packages).resolve()
    with tempfile.TemporaryDirectory(prefix="apt-install-", dir=Path.cwd()) as temporary:
        root = Path(temporary)
        shutil.copytree(package_manager, root / "mkosi.pkgmngr")
        # An additional local package directory must keep working alongside Docker.
        extra = root / "extra-packages"
        extra.mkdir()
        control = root / "extra/DEBIAN/control"
        control.parent.mkdir(parents=True)
        control.write_text("Package: veritee-local-package-test\nVersion: 1\nArchitecture: all\n"
                           "Maintainer: Test <test@example.invalid>\nDescription: local input fixture\n")
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(control.parent.parent),
                        str(extra / "fixture.deb")], check=True)
        pins = [f"{p['name']}={p['version']}" for p in lock["packages"]]
        (root / "mkosi.conf").write_text(
            "[Distribution]\nDistribution=ubuntu\nRelease=jammy\nArchitecture=x86-64\n"
            "[Content]\nBootable=no\nWithRecommends=no\n"
            f"PackageDirectories={packages}\nPackageDirectories={extra}\n"
            "Packages=" + "\n ".join([*pins, "veritee-local-package-test=1"]) + "\n"
            "[Output]\nFormat=directory\nOutput=image\n"
        )
        subprocess.run([mkosi, "--debug"], cwd=root, check=True)
        installed = {}
        for package in lock["packages"]:
            fields = subprocess.check_output(
                ["dpkg-query", f"--admindir={root / 'image/var/lib/dpkg'}", "--show",
                 "--showformat=${Status}\n${Version}\n${Architecture}\n", package["name"]],
                text=True,
            ).splitlines()
            if fields != ["install ok installed", package["version"], package["architecture"]]:
                raise ValueError(f"Incorrect installed package identity: {package['name']}")
            installed[package["name"]] = package["version"]
        fixture = subprocess.check_output(
            ["dpkg-query", f"--admindir={root / 'image/var/lib/dpkg'}", "--show",
             "--showformat=${Status}", "veritee-local-package-test"], text=True,
        )
        if fixture != "install ok installed":
            raise ValueError("Additional local package directory was not preserved")
        result = {"passed": True, "installed": installed, "additional_package_directory": True}
        Path(result_path).write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))


if __name__ == "__main__":
    main()
