# encoding: UTF-8

control "SEC-1.2" do
  title "Secret rotation interval must be within the maximum allowed window"
  desc "Rotation must occur at least as often as policy requires."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['IA-5 f']
  tag ksi:                   ['KSI-IAM-APM']
  tag nist_r4:               ['IA-5 g']
  tag cci:                   ['CCI-000182']
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
