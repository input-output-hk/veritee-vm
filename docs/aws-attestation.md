# AWS bare SNP attestation

The experimental AWS profile builds an Ubuntu 24.04 EC2 disk with an AWS kernel,
ENA/NVMe support, cloud-init SSH provisioning and a pinned `snpguest` binary.
The collector talks directly to `/dev/sev-guest` at VMPL0. The Hyper-V/HCL feature
is disabled in the tool build.

From the repository root:

```sh
veritee build-base-os-image --provider aws --verbose
```

The output is `local-aws-snp/disk.raw`, its package inventory and
`aws-build.json`, with source identity, build-input hashes and artifact hashes.
AWS needs neither Azure credentials nor ACR publication for this build.
The existing Azure default still writes `local-base-os/`.

This is a writable bare-attestation image. At EC2 launch, cloud-init imports
the supplied public SSH key for the `ubuntu` user. Root/password SSH logins are
disabled. Account access is needed to import the raw disk as a UEFI AMI and
launch it with `AmdSevSnp=enabled`; these AWS deployment operations are not yet
integrated into `create-vm`.

For a first shared-tenancy test, AWS documents `m6a.large` in Ireland
(`eu-west-1`). Shared instances return a VLEK, rather than a VCEK. See
[AWS requirements](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sev-snp.html)
and [report verification](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snp-attestation.html).

Create the challenge on the **client**. For example, bind a fresh 32-byte nonce
and a payload digest into the report's 64-byte `report_data`:

```python
import hashlib, secrets
from pathlib import Path

nonce = secrets.token_bytes(32)
payload = b"Veritee AWS attestation test"
report_data = hashlib.sha512(
    b"veritee-aws-probe-v1\0" + nonce + hashlib.sha256(payload).digest()
).digest()
Path("report-data.bin").write_bytes(report_data)
```

Send those bytes to the guest and collect the report into a new directory:

```sh
sudo veritee-snp-report report-data.bin evidence
```

Copy the evidence back to the client. Check its signature and certificate
chain against independently obtained AMD roots, compare `report_data` with the
original client bytes, and check VMPL, debug policy and TCB. Negative cases
must reject a different nonce or changed report. A guest-supplied root
certificate is not a trust anchor.

Live EC2 validation is pending. A valid raw report authenticates the hardware
report and supplied challenge; it does not establish an approved Veritee OS or
DApp measurement. AWS emits no Azure PCR4/policy files and has no Warden
registration path yet. Existing OS approval and DApp deployment remain Azure
operations.
