# encoding: UTF-8
#
# SEC-3.x — Resource policy. NIST AC-3 / AC-6 / SC-8.
# Deep checks parse the actual resource policy via
# aws_secretsmanager_secret_policy (custom resource).

control "SEC-3.1" do
  title "Secret resource policies must not grant public / wildcard-principal access"
  desc "An Allow statement with Principal \"*\" and no narrowing condition "\
       "makes a secret effectively public. The deep check parses each "\
       "statement. ARNs in secret_arn_allowlist are exempt."
  tag severity:              "high"
  tag nist:                  ["AC-3", "AC-6"]
  tag cci:                   ["CCI-000366"]
  tag local_number:          "SEC-3.1"
  tag srg:                   "SRG-OS-000001-CLD-000010"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  allow = input("secret_arn_allowlist")
  scoped = secrets_in_scope.reject { |a| allow.include?(a) }
  applicable = !scoped.empty?
  impact 0.7
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    policy = aws_secretsmanager_secret_policy(secret_id: arn)
    describe "Resource policy for #{arn}" do
      it "must not contain public (wildcard-principal) Allow statements" do
        expect(policy.public_statements).to be_empty
      end
      it "must not grant wildcard actions to external principals" do
        expect(policy.wildcard_action_statements).to be_empty
      end
    end
  end
end

control "SEC-3.2" do
  title "Secret resource policies must enforce encryption in transit (TLS)"
  desc "When a resource policy is present it should Deny non-TLS access via "\
       "aws:SecureTransport=false. Secrets with no resource policy rely on "\
       "the Secrets Manager TLS-only endpoints (AWS-inherited) and are N/A."
  tag severity:              "medium"
  tag nist:                  ["SC-8", "SC-8 (1)"]
  tag cci:                   ["CCI-002418"]
  tag local_number:          "SEC-3.2"
  tag srg:                   "SRG-OS-000033-CLD-000115"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  scoped = secrets_in_scope
  applicable = !scoped.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    policy = aws_secretsmanager_secret_policy(secret_id: arn)
    next unless policy.has_resource_policy? # no policy => TLS-only endpoint inherited

    describe "TLS enforcement in resource policy for #{arn}" do
      subject { policy.enforce_secure_transport? }
      it { should eq true }
    end
  end
end

control "SEC-3.3" do
  title "Account must block public resource policies on secrets (BlockPublicPolicy)"
  desc "AWS recommends granting secretsmanager:PutResourcePolicy only with "\
       "BlockPublicPolicy=true so users cannot attach a broadly-public policy. "\
       "This guardrail lives in identity policies / SCPs, not on the secret "\
       "resource, so it cannot be read per-secret. SEC-3.1 provides detective "\
       "coverage of any policy that did become public; this control attests "\
       "the preventive guardrail is in place."
  tag severity:              "medium"
  tag nist:                  ["AC-3", "AC-6"]
  tag cci:                   ["CCI-000366"]
  tag local_number:          "SEC-3.3"
  tag fsbp:                  "SecretsManager (BlockPublicPolicy)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "alternative"

  ref = input("block_public_policy_attestation_ref")
  describe "BlockPublicPolicy guardrail attestation" do
    skip "MANUAL/ATTESTATION: confirm identity policies or SCPs grant "\
         "secretsmanager:PutResourcePolicy only with Condition Bool "\
         "secretsmanager:BlockPublicPolicy=true. Detective coverage of "\
         "effective public access is provided by SEC-3.1. Attestation "\
         "reference: #{ref.empty? ? 'TBD — populate block_public_policy_attestation_ref' : ref}"
  end
end
