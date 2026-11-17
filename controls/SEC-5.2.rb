# encoding: UTF-8

control "SEC-5.2" do
  title "Unused / stale secrets must be remediated"
  desc "Secrets not accessed within stale_days are candidates for removal to "\
       "reduce the attack surface. Never-accessed/new secrets are not flagged."
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ['AC-2 (3) (d)']
  tag ksi:                   ['KSI-IAM-AAM', 'KSI-IAM-JIT', 'KSI-IAM-SUS']
  tag nist_r4:               ['AC-2 (3)']
  tag cci:                   ['CCI-000017']
  tag local_number:          "SEC-5.2"
  tag fsbp:                  "SecretsManager.3"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  stale_days = input("stale_days")
  scoped = secrets_in_scope
  applicable = !scoped.empty?
  impact 0.3
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    last = aws_secretsmanager_secret(secret_id: arn).last_accessed_date
    age_days = last.nil? ? nil : ((Time.now - last) / 86_400).floor
    describe "Last access age for #{arn}" do
      subject { age_days }
      it "must be <= #{stale_days} days (or never-accessed/new)" do
        expect(age_days).to be <= stale_days unless age_days.nil?
      end
    end
  end
end
