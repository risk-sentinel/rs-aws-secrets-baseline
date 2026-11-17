# encoding: UTF-8

control "SEC-3.1" do
  title "Secret resource policies must not grant public / wildcard-principal access"
  desc "An Allow statement with Principal \"*\" and no narrowing condition "\
       "makes a secret effectively public. The deep check parses each "\
       "statement. ARNs in secret_arn_allowlist are exempt."
  desc  'check', "
    For every customer-owned secret in the scan regions that is not listed in the input `secret_arn_allowlist`, parse the resource policy. It must contain no Allow statement with a wildcard principal (`*`, or `AWS: \"*\"`) and no `Condition`, and no Allow statement whose action contains `*`.
  "
  desc  'fix', "
    Replace wildcard principals with specific account or role ARNs, or add a condition that narrows access (for example `aws:PrincipalOrgID`). Replace wildcard actions with the specific actions needed, such as `secretsmanager:GetSecretValue`. Validate before applying:

    ```
    aws secretsmanager validate-resource-policy --secret-id <secret-arn> --resource-policy file://policy.json
    aws secretsmanager put-resource-policy --secret-id <secret-arn> --resource-policy file://policy.json --block-public-policy
    ```

    To remove the policy entirely: `aws secretsmanager delete-resource-policy --secret-id <secret-arn>`.
  "
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
      it "must not contain Allow statements with wildcard actions" do
        expect(policy.wildcard_action_statements).to be_empty
      end
    end
  end
end
