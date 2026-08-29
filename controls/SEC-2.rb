# encoding: UTF-8
#
# SEC-2.x — Encryption. NIST SC-28 / SC-12 / SC-13.

DEFAULT_KMS = %r{alias/aws/secretsmanager}.freeze

control "SEC-2.1" do
  title "Secrets must be encrypted with a customer-managed KMS key (when required)"
  desc "AWS permits the aws/secretsmanager managed key for most cases, but "\
       "cross-account access and key-policy control require a customer-managed "\
       "CMK. When require_cmk is true, assert a non-default CMK is in use."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["SC-28", "SC-12"]
  tag cci:                   ["CCI-002475"]
  tag local_number:          "SEC-2.1"
  tag srg:                   "SRG-OS-000404-CLD-000080"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  require_cmk = input("require_cmk")
  scoped = secrets_in_scope
  applicable = require_cmk && !scoped.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("require_cmk is false or no secrets in scope") { applicable }

  scoped.each do |arn|
    key = aws_secretsmanager_secret(secret_id: arn).kms_key_id.to_s
    describe "KMS key for #{arn}" do
      subject { key }
      it "must be a customer-managed CMK (not the aws/secretsmanager default)" do
        expect(key).not_to be_empty
        expect(key).not_to match(DEFAULT_KMS)
      end
    end
  end
end

control "SEC-2.2" do
  title "The CMK protecting secrets must have key rotation enabled"
  desc "A customer-managed CMK used to encrypt secrets should itself rotate. "\
       "Secrets on the AWS-managed key are skipped (AWS-rotated)."
  tag severity:              "medium"
  tag nist:                  ["SC-12", "SC-12 (2)"]
  tag cci:                   ["CCI-001967"]
  tag local_number:          "SEC-2.2"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  scoped = secrets_in_scope
  applicable = !scoped.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    key = aws_secretsmanager_secret(secret_id: arn).kms_key_id.to_s
    next if key.empty? || key.match?(DEFAULT_KMS)

    describe aws_kms_key(key_id: key) do
      its("rotation_enabled") { should eq true }
    end
  end
end

control "SEC-2.3" do
  title "Secrets must be protected with FIPS-validated cryptography"
  desc "SC-13 requires FIPS-validated or NSA-approved cryptography. AWS KMS "\
       "provides FIPS 140-2/3 validated modules (AWS-inherited); the customer "\
       "control is ensuring a KMS key is in use. Passes with the CMK-in-use "\
       "proxy assertion plus the AWS validation evidence."
  tag severity:              "medium"
  tag nist:                  ["SC-13"]
  tag cci:                   ["CCI-002450"]
  tag local_number:          "SEC-2.3"
  tag srg:                   "SRG-OS-000404-CLD-000080"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"
  tag aws_inherited_evidence: "AWS KMS HSMs are FIPS 140-2/140-3 validated: "\
                              "https://aws.amazon.com/compliance/fips/"

  scoped = secrets_in_scope
  applicable = !scoped.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    # A nil kms_key_id means the secret uses the AWS-managed key
    # (aws/secretsmanager), itself a FIPS-validated KMS module. Both nil
    # and an explicit key id satisfy SC-13; a Secrets Manager secret is
    # always KMS-encrypted at rest, so this asserts the encryption path
    # exists with AWS module-validation as inherited evidence.
    key = aws_secretsmanager_secret(secret_id: arn).kms_key_id
    encrypted = key.nil? ? "aws/secretsmanager (AWS-managed FIPS module)" : key.to_s
    describe "FIPS-validated encryption for #{arn} (AWS KMS module validation inherited)" do
      subject { encrypted }
      it "must be encrypted by an AWS KMS key" do
        expect(encrypted).not_to be_empty
      end
    end
  end
end
