# encoding: UTF-8

control "SEC-2.1" do
  title "Secrets must be encrypted with a customer-managed KMS key (when required)"
  desc "AWS permits the aws/secretsmanager managed key for most cases, but "\
       "cross-account access and key-policy control require a customer-managed "\
       "CMK. When require_cmk is true, assert a non-default CMK is in use."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['SC-12', 'SC-28 (1)']
  tag ksi:                   ['KSI-SVC-ASM', 'KSI-SVC-SIN']
  tag nist_r4:               ['SC-12', 'SC-28 (1)']
  tag cci:                   ['CCI-002441', 'CCI-002476']
  tag local_number:          "SEC-2.1"
  tag srg:                   "SRG-OS-000404-CLD-000080"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  require_cmk = input("require_cmk")
  scoped = secrets_in_scope
  default_kms = secretsmanager_default_kms
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
        expect(key).not_to match(default_kms)
      end
    end
  end
end
