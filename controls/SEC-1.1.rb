# encoding: UTF-8

control "SEC-1.1" do
  title "Secrets Manager secrets must have automatic rotation enabled"
  desc "Long-lived static secrets are more likely to be compromised. "\
       "Automatic rotation limits the window of exposure."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["SC-28"]
  tag ksi:                   ["KSI-SVC-SIN"]
  tag nist_r4:               ["SC-28"]
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
