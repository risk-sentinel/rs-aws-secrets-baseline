# encoding: UTF-8

control "SEC-2.3" do
  title "Secrets must be protected with FIPS-validated cryptography"
  desc "Every secret is encrypted by a KMS key. That key must be usable and "\
       "must do its cryptography inside AWS KMS's FIPS 140 validated HSMs, so "\
       "the AWS validation can be inherited. A key in an external key store, "\
       "a disabled or pending-deletion key, or a non-symmetric key fails."
  desc  'check', "
    For every customer-owned secret in the scan regions, describe its KMS key: the customer managed key in `KmsKeyId`, or `alias/aws/secretsmanager` in the secret's region when none is set. Confirm the key was readable, `KeyState` is `Enabled`, `KeySpec` is `SYMMETRIC_DEFAULT`, `KeyUsage` is `ENCRYPT_DECRYPT`, and `Origin` is `AWS_KMS`, `EXTERNAL` (imported material, still held in AWS KMS HSMs) or `AWS_CLOUDHSM`. An `EXTERNAL_KEY_STORE` origin means the cryptography runs outside AWS, where AWS's FIPS 140 validation does not apply.
  "
  desc  'fix', "
    Re-encrypt the secret with a symmetric KMS key held in AWS KMS or a CloudHSM custom key store: `aws secretsmanager update-secret --secret-id <arn> --kms-key-id <key-arn>`. Re-enable a disabled key or cancel a scheduled deletion with `aws kms enable-key` / `aws kms cancel-key-deletion`. Keep AWS's FIPS 140 validation evidence for KMS (https://aws.amazon.com/compliance/fips/) with the system's leveraged evidence, and use the FIPS endpoints (`secretsmanager-fips.<region>.amazonaws.com`) where the system requires them.
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['SC-13 b']
  tag ksi:                   ['KSI-SVC-SIN', 'KSI-SVC-VRI']
  tag nist_r4:               ['SC-13']
  tag cci:                   ['CCI-002450']
  tag local_number:          "SEC-2.3"
  tag srg:                   "SRG-OS-000404-CLD-000080"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"
  tag aws_inherited_evidence: "AWS KMS HSMs are FIPS 140-2/140-3 validated: "\
                              "https://aws.amazon.com/compliance/fips/"

  scoped = secrets_in_scope
  default_kms = secretsmanager_default_kms
  fips_origins = %w(AWS_KMS EXTERNAL AWS_CLOUDHSM)
  applicable = !scoped.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    region = arn.split(":")[3]
    key_id = aws_secretsmanager_secret(secret_id: arn).kms_key_id.to_s
    key_id = "alias/aws/secretsmanager" if key_id.empty? || key_id.match?(default_kms)
    key = aws_kms_key_crypto(key_id: key_id, region: region)

    describe "KMS key encrypting #{arn}" do
      subject { key }
      it { should be_assessed }
    end

    next unless key.assessed?

    describe "KMS key encrypting #{arn} (#{key.key_arn})" do
      subject { key }
      its("key_state") { should eq "Enabled" }
      its("key_spec")  { should eq "SYMMETRIC_DEFAULT" }
      its("key_usage") { should eq "ENCRYPT_DECRYPT" }
      its("origin")    { should be_in fips_origins }
    end
  end
end
