# encoding: UTF-8

control "SEC-3.3" do
  title "Account must block public resource policies on secrets (BlockPublicPolicy)"
  desc "AWS recommends granting secretsmanager:PutResourcePolicy only with "\
       "BlockPublicPolicy=true so users cannot attach a broadly-public policy. "\
       "This guardrail lives in identity policies / SCPs, not on the secret "\
       "resource, so it cannot be read per-secret. SEC-3.1 provides detective "\
       "coverage of any policy that did become public; this control attests "\
       "the preventive guardrail is in place."
  desc  'check', "
    Attestation. The guardrail lives in identity policies or SCPs, which this profile cannot read per secret. Resolve the attestation document: the input `sec_3_3_attestation_uri`, or else the `SEC-3.3` entry under `boundary_docs_base`. It must be reachable, exist, and be no older than `attestation_max_age_days` (default 365). When no location is configured, the control is skipped with instructions. SEC-3.1 gives detective coverage of any policy that did become public.
  "
  desc  'fix', "
    Allow `secretsmanager:PutResourcePolicy` only with the `secretsmanager:BlockPublicPolicy` condition, in identity policies or an SCP, for example:

    ```
    { \"Effect\": \"Deny\", \"Action\": \"secretsmanager:PutResourcePolicy\", \"Resource\": \"*\", \"Condition\": { \"Bool\": { \"secretsmanager:BlockPublicPolicy\": \"false\" } } }
    ```

    Record the SCP or policy as the attestation, publish it where the scanner can read it, and set `boundary_docs_base` or `sec_3_3_attestation_uri` (and `block_public_policy_attestation_ref`). Alternatively, record a CMS-pattern attestation with `saf attest apply`.
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["AC-3", "AC-6"]
  tag ksi:                   ["KSI-IAM-APM", "KSI-IAM-ELP", "KSI-IAM-JIT"]
  tag nist_r4:               ["AC-3", "AC-6"]
  tag cci:                   ["CCI-000213", "CCI-000225"]
  tag local_number:          "SEC-3.3"
  tag fsbp:                  "SecretsManager (BlockPublicPolicy)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "alternative"
  tag attestation_category:  "policy"

  # BlockPublicPolicy guardrail is an account/SCP/identity-policy control with no
  # per-secret API surface (SEC-3.1 gives detective coverage). Converted to
  # Pass-with-evidence via document_attestation: the SCP /
  # identity-policy attestation is a `boundary`-class doc. Resolves to the
  # sec_3_3_attestation_uri override, else attestation_uri(:boundary, 'SEC-3.3');
  # empty -> Skip (preserves the prior attestation + saf attest apply fallback).
  ref = input("block_public_policy_attestation_ref")
  uri = input("sec_3_3_attestation_uri", value: "")
  uri = attestation_uri(:boundary, "SEC-3.3") if uri.to_s.empty?
  max_age_days = input("attestation_max_age_days", value: 365)

  if uri.to_s.empty?
    describe "BlockPublicPolicy guardrail attestation" do
      skip "MANUAL/ATTESTATION: confirm identity policies or SCPs grant "\
           "secretsmanager:PutResourcePolicy only with Condition Bool "\
           "secretsmanager:BlockPublicPolicy=true. Detective coverage of "\
           "effective public access is provided by SEC-3.1. Set boundary_docs_base / "\
           "sec_3_3_attestation_uri to the guardrail attestation, or `saf attest apply`. "\
           "Reference: #{ref.empty? ? 'TBD — populate block_public_policy_attestation_ref' : ref}"
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "SEC-3.3 BlockPublicPolicy guardrail attestation (#{uri})" do
      it("reachable") { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
