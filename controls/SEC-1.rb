# encoding: UTF-8
#
# SEC-1.x — Rotation. NIST IA-5(1); FSBP SecretsManager.1/2/4.

control "SEC-1.1" do
  title "Secrets Manager secrets must have automatic rotation enabled"
  desc "Long-lived static secrets are more likely to be compromised. "\
       "Automatic rotation limits the window of exposure."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["SC-28"]
  tag cci:                   ["CCI-001199"]
  tag local_number:          "SEC-1.1"
  tag fsbp:                  "SecretsManager.1"
  tag baseline:              "Risk Sentinel AWS Secrets Manager Baseline"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  scoped = secrets_in_scope
  applicable = !scoped.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    describe aws_secretsmanager_secret(secret_id: arn) do
      its("rotation_enabled") { should eq true }
    end
  end
end

control "SEC-1.2" do
  title "Secret rotation interval must be within the maximum allowed window"
  desc "Rotation must occur at least as often as policy requires."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["IA-5 (1) (e)"]
  tag cci:                   ["CCI-002041"]
  tag local_number:          "SEC-1.2"
  tag fsbp:                  "SecretsManager.4"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  max_days = input("max_rotation_days")
  scoped = secrets_in_scope
  applicable = !scoped.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    secret = aws_secretsmanager_secret(secret_id: arn)
    next unless secret.rotation_enabled # rotation-off is caught by SEC-1.1

    rules = secret.rotation_rules
    interval = rules.is_a?(Hash) ? rules[:automatically_after_days] : nil
    describe "Rotation interval for #{arn}" do
      subject { interval }
      it "must be set" do
        expect(interval).not_to be_nil
      end
      it "must be <= #{max_days} days" do
        expect(interval).to be <= max_days unless interval.nil?
      end
    end
  end
end

control "SEC-1.3" do
  title "Secrets must have rotated within the maximum allowed window"
  desc "A rotation schedule that never fires provides no protection; assert "\
       "the last successful rotation is recent enough."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["SC-28"]
  tag cci:                   ["CCI-001199"]
  tag local_number:          "SEC-1.3"
  tag fsbp:                  "SecretsManager.2"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  max_days = input("max_rotation_days")
  scoped = secrets_in_scope
  applicable = !scoped.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    secret = aws_secretsmanager_secret(secret_id: arn)
    next unless secret.rotation_enabled

    last = secret.last_rotated_date
    age_days = last.nil? ? nil : ((Time.now - last) / 86_400).floor
    describe "Last rotation age for #{arn}" do
      subject { age_days }
      it "must have a recorded rotation" do
        expect(last).not_to be_nil
      end
      it "must be <= #{max_days} days old" do
        expect(age_days).to be <= max_days unless age_days.nil?
      end
    end
  end
end
