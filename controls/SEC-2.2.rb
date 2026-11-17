# encoding: UTF-8

control "SEC-2.2" do
  title "The CMK protecting secrets must have key rotation enabled"
  desc "A customer-managed CMK used to encrypt secrets should itself rotate. "\
       "Secrets on the AWS-managed key are skipped (AWS-rotated)."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["SC-12", "SC-12 (2)"]
  tag ksi:                   ["KSI-SVC-ASM"]
  tag nist_r4:               ["SC-12", "SC-12 (2)"]
  tag cci:                   ["CCI-002428", "CCI-002443"]
  tag local_number:          "SEC-2.2"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  scoped = secrets_in_scope
  default_kms = secretsmanager_default_kms
  applicable = !scoped.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    key = aws_secretsmanager_secret(secret_id: arn).kms_key_id.to_s
    next if key.empty? || key.match?(default_kms)

    # aws_kms_key_rotation, not the stock aws_kms_key: the stock resource does
    # not expose rotation_enabled at the pinned inspec-aws version, so every
    # assertion raised undefined-method and the control failed while assessing
    # nothing (#13).
    rotation = aws_kms_key_rotation(key_id: key)

    # Assert we actually looked BEFORE asserting what we found. Without this an
    # AccessDenied reads as "rotation disabled" — an inability to assess wearing
    # the costume of a finding, which is the defect #13 was really about.
    describe rotation do
      it { should be_assessed }
    end

    next unless rotation.assessed?

    describe rotation do
      its("rotation_enabled") { should eq true }
    end
  end
end
