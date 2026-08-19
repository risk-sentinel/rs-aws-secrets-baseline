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
scanner output. For that, use the CI template — it is the whole pipeline, and it
is **YAML with no helper scripts behind it**, deliberately:

**GitHub** — call the reusable workflow:

```yaml
jobs:
  evidence:
    uses: risk-sentinel/rs-aws-secrets-baseline/.github/workflows/exec-evidence.yml@v0.1.0
    with:
      target: my-account
      profile_name: rs-aws-secrets-v1r1
      profile_version: "0.1.0"
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**GitLab** — include the template:

```yaml
include:
  - project: risk-sentinel/rs-aws-secrets-baseline
    ref: v0.1.0
    file: /ci/gitlab/exec-evidence.yml
    inputs:
      target: my-account
      profile_name: rs-aws-secrets-v1r1
      profile_version: "0.1.0"
```

### Why the logic is in the YAML and not in a script

An `include:` brings YAML and nothing else. A helper script in this repository's
`tools/` directory would simply not exist on an including project's runner — and
the same is true for a GitHub caller using `uses:`. Putting the steps in the YAML
is what makes this work for *include it* and *clone it on the fly*, on both
forges. The duplication between the GitHub and GitLab files is deliberate, and
preferable to a dependency a consumer cannot satisfy.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only the facts that cannot
exist until afterwards — finish time, the digest of the produced artifact, and
the outcome counts — are added at the end.

### Running it by hand

The same steps, outside CI:

```bash
STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# 1. assess, keeping the machine-readable result
cinc-auditor exec . -t aws:// --input-file inputs/mine.yml \
  --reporter cli json:results.json

# 2. convert to native HDF v3 — `hdf convert`, NOT `saf convert`
hdf convert results.json -o results.v3.json

# 3. apply the audit record
jq --arg started "$STARTED_AT" \
   --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
   --arg digest "sha256:$(sha256sum results.json | cut -d' ' -f1)" \
   --arg target "my-account" '
   ([.baselines[]?.requirements[]?.results[]?.status]) as $st
   | .passthrough.audit = {
       schema_version: 1,
       target: {id: $target, type: "cloudAccount", boundary: "sparc"},
       scan:   {type: "runtime", started_at: $started, finished_at: $finished},
       scanner: {name: "rs-aws-secrets-v1r1", version: "0.1.0"},
       conversion: {converter: (.generator.name // null),
                    raw_artifact: "results.json", raw_digest: $digest},
       outcome: {total: ($st|length),
                 passed: ($st|map(select(.=="passed"))|length),
                 failed: ($st|map(select(.=="failed"))|length)}
     }' results.v3.json > results.audited.json

# 4. label the target, and GUARD that the label landed
hdf label set results.audited.json target="my-account" -o results.final.json
hdf label show results.final.json | grep -q '^Component:' \
  || { echo "hdf label wrote nothing — no components in the document"; exit 1; }

# 5. gate on the schema, then show the result
hdf validate --type results results.final.json
saf view summary -i results.json
hdf list results.final.json
```

Verified end to end against a live account, on both templates: 76 results,
converts without `--no-validate`, labels, and validates.

### Three things worth knowing before you copy that

**`hdf convert`, not `saf convert sarif2hdf`.** On identical input, `hdf convert`
preserves `tool: {format, name, version}` while the saf converter emits a profile
named `"SARIF"` with the scanner name nowhere in the file. Evidence that cannot
say what produced it is not evidence anyone can act on.

**`hdf label set` reports success even when it labels nothing.** On a document
with no components it prints `Labels written` and writes a byte-identical file.
The guard in step 4 is not defensive padding.

**The auto-generated component describes the transport, not the target.** For an
`aws://` run the converter emits a `host` component named `aws` — the InSpec
backend, not your account. That is why steps 3 and 4 exist.

### Two artifacts, and why

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 (`baselines[]`) | the authoritative evidence — schema-validated, carries the audit record and typed target components, and is what `hdf convert --to oscal-sar` consumes |
| `results-heimdall.json` | InSpec exec-json (`profiles[]`) | loading into Heimdall |

The Heimdall copy is a **carry-across, not a conversion**: cinc-auditor's own
`--reporter json` output is already the shape Heimdall loads, so the pipeline
copies it and adds the audit record rather than converting anything. Verified by
loading both shapes into a live Heimdall instance.

**The version-namespace trap — and it moved.** "HDF v2" means two different
things, and which one you get depends on the CLI version:

| `--to` | hdf-libs **3.4.1** | hdf-libs **3.5.1** |
|---|---|---|
| `hdf` (default) | `baselines[]` | `baselines[]` |
| `hdf@1` | `profiles[]` | `profiles[]` |
| `hdf@2` | `baselines[]` — same as the default | **`profiles[]`** |
| `hdf@3` | *not a version* | `baselines[]` |

In the Heimdall/SAF world "HDF" has always meant the exec-json `profiles[]`
shape. hdf-libs **renumbered its own namespace between 3.4.1 and 3.5.1**, so the
identical command changes meaning across an image bump:

- On **3.4.1**, `hdf convert --to hdf@2 results.final.json` returns the input
  **byte for byte unchanged** — same sha256 — and produces nothing Heimdall
  renders.
- On **3.5.1**, the same command emits the `profiles[]` shape Heimdall does load.

Measured across three different input formats, consistent in each.

If you do use `--to hdf@2` on 3.5.1, know what it costs against the artifact
cinc-auditor already wrote: it drops `resource_params` from every result,
`depends` / `status` / `status_message` from the profile, and the whole
`passthrough` block — so the audit record has to be re-attached afterwards. It
does keep `resource_class`, `resource_id`, `attributes`, `sha256` and `refs`,
which the older `--to hdf@1` downgrade strips.

The pipeline copies cinc-auditor's own output instead. That loses nothing, keeps
the audit record, and means the Heimdall artifact does not silently change shape
the next time the image is bumped.

### What the audit record carries

Target, scan window, scanner, profile and version, pipeline provenance, who
triggered it, the converter, a **sha256 of the pre-conversion artifact**, and
outcome counts. Written on every run — clean, failed, findings or none — because
the case it exists for is the one where there are no results to speak for
themselves.

Two properties are deliberate:

- **Absent is not empty.** A field that does not apply is omitted rather than
  written as a blank.
- **It marks what is corroborable.** Run id, run URL, commit and `raw_digest` can
  be checked against systems the producer does not control. `scan.mode` and
  `actor.triggered_by` are self-asserted. An audit chain where every field is
  self-asserted is a story, and the record says which is which.

Schema authority: [dev-sec-ops-baseline#33](https://github.com/risk-sentinel/dev-sec-ops-baseline/issues/33).

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
