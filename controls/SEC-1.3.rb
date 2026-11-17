# encoding: UTF-8

control "SEC-1.3" do
  title "Secrets must have rotated within the maximum allowed window"
  desc "A rotation schedule that never fires provides no protection; assert "\
       "the last successful rotation is recent enough."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["SC-28"]
  tag ksi:                   ["KSI-SVC-SIN"]
  tag nist_r4:               ["SC-28"]
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
