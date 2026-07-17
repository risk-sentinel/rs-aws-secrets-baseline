# Provenance — `rs-aws-secrets-baseline`

## What this profile is

A **bespoke, Risk Sentinel–authored** security baseline for **AWS Secrets Manager** — there is
no single published benchmark for secrets-management configuration, so every control is anchored
to a stack of federal + AWS authoritative sources, documented here so each check is defensible in
an assessment. 14 controls across 7 families (SEC‑1…SEC‑7); each carries a `tag nist:` (NIST
800‑53 Rev 5), a DISA `tag cci:` + (where applicable) `tag srg:` (DISA **Cloud** SRG), and, where
an AWS‑native control exists, a `tag fsbp:`.

## Authoritative sources

| Key | Source | Role here |
|---|---|---|
| **NIST 800-53r5** | SP 800-53 Rev 5 control catalog | The control each check maps to (`tag nist:`) — IA / SC / AC / CP / CM / AU families. |
| **DISA Cloud SRG** | DISA Cloud Computing Security Requirements Guide | Cloud-service requirements — `tag cci:` (CCI-*) + `tag srg:` (SRG-OS-*-CLD-*, SRG-NET-*-CLD-*). Primary DoD anchor. |
| **AWS FSBP** | AWS Foundational Security Best Practices (Security Hub) | The AWS-native controls — `tag fsbp:` (`SecretsManager.*`). |
| **NIST 800-53r5 (IA-5)** | Authenticator management | The secrets-management framing — rotation, protection, and lifecycle of secret material. |

## Control-family provenance

| Family | Verifies | NIST 800-53r5 | DISA CLD SRG / CCI | FSBP | Rationale (risk addressed) |
|---|---|---|---|---|---|
| **SEC-1** Rotation | Automatic rotation enabled; interval within the max window | IA-5 (1) | CCI-002361 | SecretsManager.1 | Static long-lived secrets are the primary credential-theft blast radius — rotate them. |
| **SEC-2** Encryption at rest | Customer-managed KMS key (where required); CMK key rotation | SC-28, SC-12 | SRG-OS-000404-CLD-000080 · CCI-002475 | — | Protect secret material at rest under a controlled, rotated key — cryptographic protection. |
| **SEC-3** Access policy | No public / wildcard-principal resource policy; enforce TLS | AC-3, AC-6 | SRG-OS-000001-CLD-000010 · CCI-000366 | — | An over-broad resource policy exposes the secret cross-account/public — least privilege + in-transit protection. |
| **SEC-4** DR replication | DR-critical secrets replicated to a second region | CP-9 | CCI-000535 | SecretsManager.replication | A single-region secret is unrecoverable in a regional event — contingency/backup. |
| **SEC-5** Governance | Required governance tags; stale/unused secrets remediated | CM-8, AC-2 (3) | CCI-000366 | — | Untagged/orphaned secrets escape inventory + review — configuration + account management. |
| **SEC-6** Audit | CloudTrail captures Secrets Manager events | AU-2, AU-12 | SRG-OS-000342-CLD-000020 · CCI-000172 | — | Access to secrets must be auditable — audit generation. |
| **SEC-7** Network reachability | Reachable via an interface VPC endpoint (private) | SC-7, AC-17 | SRG-NET-000205-CLD-000085 · CCI-001097 | — | Private-only reachability keeps secret retrieval off the public path — boundary protection. |

## Notes

- **Granularity:** the table is per **family** (SEC‑N); the 14 individual controls (SEC‑N.n) each
  carry the authoritative `tag nist:` / `tag cci:` / `tag srg:` / `tag fsbp:` — the per-control
  cross-reference for OSCAL/Heimdall rollup.
- **DISA SRG family:** these anchor to the DISA **Cloud** SRG (`SRG-OS-*-CLD-*` / `SRG-NET-*-CLD-*`),
  not the Container Platform SRG — this is a cloud-service (Secrets Manager) baseline, not a
  container one.
- Keep this doc in sync when controls are added/removed or re-anchored.

_Closes #3._
