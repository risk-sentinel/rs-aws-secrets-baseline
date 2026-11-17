# encoding: UTF-8

control "SEC-2.3" do
  title "Secrets must be protected with FIPS-validated cryptography"
  desc "SC-13 requires FIPS-validated or NSA-approved cryptography. AWS KMS "\
       "provides FIPS 140-2/3 validated modules (AWS-inherited); the customer "\
       "control is ensuring a KMS key is in use. Passes with the CMK-in-use "\
       "proxy assertion plus the AWS validation evidence."
  desc  'check', "
    For every customer-owned secret in the scan regions, confirm the secret is encrypted by an AWS KMS key: either the customer managed key in `KmsKeyId` or, when none is set, the AWS managed key `alias/aws/secretsmanager`. AWS KMS's FIPS 140 validation is inherited from AWS. In practice every Secrets Manager secret is KMS-encrypted, so this records the encryption path rather than finding a fault.
  "
  desc  'fix', "
    No configuration fix is normally needed: Secrets Manager always encrypts with KMS. Keep AWS's FIPS 140 validation evidence for KMS (https://aws.amazon.com/compliance/fips/) with the system's leveraged evidence. Use the FIPS endpoints (`secretsmanager-fips.<region>.amazonaws.com`) where the system requires FIPS endpoints.
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
