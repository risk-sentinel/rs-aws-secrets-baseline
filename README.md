# rs-aws-secrets-baseline

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_aws-secrets-baseline)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_aws-secrets-baseline)

InSpec baseline for **AWS Secrets Manager** — 14 controls covering rotation,
encryption, resource-policy exposure, replication, governance tagging, audit
logging and network reachability.

No CIS Benchmark or DISA STIG exists for Secrets Manager. Controls are anchored
to **NIST 800-53 r5** (primary), **AWS Foundational Security Best Practices**
(`SecretsManager.1`–`.4`), the AWS Secrets Manager best-practices guide, and
DISA SRG CCI anchors where they apply. The full derivation is in
[`PROVENANCE.md`](PROVENANCE.md) — read that before adopting this as evidence,
because a bespoke baseline is only as good as its stated basis.

Targets **AWS Commercial** and **AWS GovCloud (non-DoD)**. Per-control
partition applicability is in [`partition_applicability.yml`](partition_applicability.yml)
and encoded as `tag applicable_partitions:`.

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/rs-aws-secrets-baseline
cd rs-aws-secrets-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t aws:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

`--input-file` is **not optional**. cinc-auditor does not auto-load a
profile-root inputs file, and several controls scope themselves out when their
input is empty — so without it you get a quieter run rather than a wrong one,
which is harder to notice.

### Credentials

Standard AWS credential resolution (environment, profile, instance role). The
identity needs read-only access to Secrets Manager, KMS, CloudTrail and EC2:

```
secretsmanager:ListSecrets      secretsmanager:DescribeSecret
secretsmanager:GetResourcePolicy
kms:DescribeKey                 kms:GetKeyRotationStatus
cloudtrail:DescribeTrails       cloudtrail:GetTrailStatus
ec2:DescribeVpcEndpoints
```

No control reads a secret's **value**. This baseline assesses configuration.

### What a first run looks like

Against an account with 8 customer-owned secrets: **76 results across 14
controls**, in a few seconds.

**If you see far fewer, stop and investigate rather than celebrating.** A run
that assesses nothing exits 0 and looks clean. The specific shape to watch for
is a wave of `No customer-owned Secrets Manager secrets in scope` skips on an
account that definitely has secrets — that meant a swallowed API error for the
entire life of this profile before it was found (#12). Cross-check with:

```bash
aws secretsmanager list-secrets --query 'length(SecretList)'
```

---

## Inputs

Every input is documented in [`inputs/example.yml`](inputs/example.yml), grouped
by what it does. The four categories matter more than the individual values:

| Group | Meaning |
|---|---|
| **Required to run** | `aws_partition` — which partition you are scanning |
| **Scoping** | `max_rotation_days`, `require_cmk`, `stale_days`, `require_vpc_endpoint` — decide which controls apply and how strictly |
| **Allow-lists** | `required_tag_keys`, `dr_critical_secret_arns`, `secret_arn_allowlist` — deliberately empty until you have something to exempt |
| **Attestation** | `*_attestation_*`, `*_base` — evidence for checks no API can answer |

**Empty is never neutral.** `dr_critical_secret_arns` empty makes SEC-4.1 Not
Applicable, because the profile cannot infer which of your secrets are
DR-critical and guessing would be worse than declining to answer. The example
file states the consequence of an empty value for every input that has one.

---

## Controls

| ID | Assesses | NIST |
|---|---|---|
| SEC-1.1 | Automatic rotation is enabled | IA-5(1) |
| SEC-1.2 | Rotation interval within the allowed window | IA-5(1) |
| SEC-1.3 | Last rotation within the allowed window | IA-5(1) |
| SEC-2.1 | Encrypted with a customer-managed CMK | SC-12 |
| SEC-2.2 | The CMK itself has rotation enabled | SC-12(2) |
| SEC-2.3 | FIPS-validated cryptography (AWS-inherited) | SC-13 |
| SEC-3.1 | No public / wildcard-principal resource policy | AC-3, AC-6 |
| SEC-3.2 | Resource policy enforces TLS | SC-8, SC-8(1) |
| SEC-3.3 | Account blocks public resource policies | AC-3 |
| SEC-4.1 | DR-critical secrets are cross-region replicated | CP-9 |
| SEC-5.1 | Secrets carry required governance tags | CM-8 |
| SEC-5.2 | Stale / unused secrets are remediated | AC-2(3) |
| SEC-6.1 | CloudTrail captures Secrets Manager events | AU-2 |
| SEC-7.1 | Reachable via an interface VPC endpoint | SC-7 |

---

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For evidence, continue past the exec:

```bash
# 1. assess, keeping the machine-readable result
cinc-auditor exec . -t aws:// --input-file inputs/mine.yml \
  --reporter cli json:results.json

# 2. convert to native HDF v3 — use `hdf convert`, NOT `saf convert`
hdf convert results.json -o results.v3.json

# 3. attach the audit record (see below)
python3 tools/hdf_audit.py --hdf results.v3.json --out results.audited.json \
  --raw results.json \
  --target "<what you assessed>" --target-type cloudAccount \
  --scan-type runtime --profile-name rs-aws-secrets-v1r1

# 4. label the target component, and GUARD that the label landed
hdf label set results.audited.json target="<what you assessed>" -o results.final.json
hdf label show results.final.json | grep -q '^Component:' \
  || { echo "hdf label wrote nothing — no components in the document"; exit 1; }

# 5. gate on the schema
hdf validate --type results results.final.json
```

Verified end to end against a live account: 76 results, converts without
`--no-validate`, and validates.

### Three things worth knowing before you copy that

**`hdf convert`, not `saf convert sarif2hdf`.** On identical input, `hdf convert`
preserves `tool: {format, name, version}` while the saf converter emits a
profile named `"SARIF"` with the scanner name nowhere in the file. Evidence that
cannot say what produced it is not evidence anyone can act on.

**`hdf label set` reports success even when it labels nothing.** On a document
with no components it prints `Labels written` and writes a byte-identical file.
Step 4's guard is not defensive padding.

**The auto-generated component describes the transport, not the target.** For an
`aws://` run the converter emits a `host` component named `aws`. That is the
InSpec backend, not your account — which is why steps 3 and 4 exist.

### The audit record

`tools/hdf_audit.py` writes a `passthrough.audit` block, always — clean run,
failed run, findings or none. It records the target, scan window, scanner,
profile and version, pipeline provenance (auto-detected from GitHub Actions
environment variables), who triggered it, the converter, a **sha256 of the
pre-conversion artifact**, and outcome counts.

Two properties are deliberate:

- **Absent is not empty.** A field that does not apply is omitted. A field that
  applies but could not be determined is `null`, with the reason in
  `audit.notes`.
- **It marks what is corroborable.** Run id, run URL, commit and `raw_digest`
  can be checked against systems the producer does not control. `scan.mode` and
  `actor.triggered_by` are self-asserted. An audit chain where every field is
  self-asserted is a story, and the record says which is which.

Schema authority: [dev-sec-ops-baseline#33](https://github.com/risk-sentinel/dev-sec-ops-baseline/issues/33).

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: rs-aws-secrets-v1r1
    git: https://github.com/risk-sentinel/rs-aws-secrets-baseline.git
    tag: v0.1.0
```

Then `include_controls 'rs-aws-secrets-v1r1'` and supply your own inputs. Input
overrides reach the depended profile's controls, so your values win without
editing anything here.

## Contributing

Control logic changes belong here, in this repository. Issues and PRs welcome.
`cinc-auditor check` only *loads* a profile — it will not catch a resource that
returns empty because an API call failed. Anything touching `libraries/` needs a
real `exec` against a real account before it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
