# encoding: UTF-8
#
# SEC-4.x — Replication / resilience. NIST CP-9.

control "SEC-4.1" do
  title "DR-critical secrets must be replicated to a second region"
  desc "Secrets required for disaster recovery should be replicated "\
       "cross-region so they survive a regional outage. Only secrets listed "\
       "in dr_critical_secret_arns are in scope; cross-partition replication "\
       "into GovCloud is not supported and is treated as N/A."
  tag severity:              "medium"
  tag nist:                  ["CP-9"]
  tag cci:                   ["CCI-000535"]
  tag local_number:          "SEC-4.1"
  tag fsbp:                  "SecretsManager.replication"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  dr_arns = input("dr_critical_secret_arns")
  in_scope = secrets_in_scope & dr_arns
  applicable = !in_scope.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("No DR-critical secrets declared (dr_critical_secret_arns empty)") { applicable }

  in_scope.each do |arn|
    describe aws_secretsmanager_secret_policy(secret_id: arn) do
      it { should be_replicated }
    end
  end
end
