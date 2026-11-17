# encoding: UTF-8

control "SEC-3.1" do
  title "Secret resource policies must not grant public / wildcard-principal access"
  desc "An Allow statement with Principal \"*\" and no narrowing condition "\
       "makes a secret effectively public. The deep check parses each "\
       "statement. ARNs in secret_arn_allowlist are exempt."
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["AC-3", "AC-6"]
  tag ksi:                   ["KSI-IAM-APM", "KSI-IAM-ELP", "KSI-IAM-JIT"]
  tag nist_r4:               ["AC-3", "AC-6"]
  tag cci:                   ["CCI-000213", "CCI-000225"]
  tag local_number:          "SEC-3.1"
  tag srg:                   "SRG-OS-000001-CLD-000010"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  allow = input("secret_arn_allowlist")
  scoped = secrets_in_scope.reject { |a| allow.include?(a) }
  applicable = !scoped.empty?
  impact 0.7
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    policy = aws_secretsmanager_secret_policy(secret_id: arn)
    describe "Resource policy for #{arn}" do
      it "must not contain public (wildcard-principal) Allow statements" do
        expect(policy.public_statements).to be_empty
      end
      it "must not grant wildcard actions to external principals" do
        expect(policy.wildcard_action_statements).to be_empty
      end
    end
  end
end
