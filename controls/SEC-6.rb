# encoding: UTF-8
#
# SEC-6.x — Audit. NIST AU-2 / AU-12.

control "SEC-6.1" do
  title "CloudTrail must capture Secrets Manager events"
  desc "Access to secrets (GetSecretValue) and management actions must be "\
       "auditable. At least one multi-region CloudTrail trail must be logging "\
       "and capturing global/management events."
  tag severity:              "medium"
  tag nist:                  ["AU-2", "AU-12"]
  tag cci:                   ["CCI-000172"]
  tag local_number:          "SEC-6.1"
  tag srg:                   "SRG-OS-000342-CLD-000020"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  impact 0.5

  describe aws_cloudtrail_trails.where { is_multi_region_trail } do
    it { should exist }
  end

  aws_cloudtrail_trails.where { is_multi_region_trail }.trail_arns.each do |trail_arn|
    describe aws_cloudtrail_trail(trail_arn) do
      it { should be_logging }
      its("include_global_service_events") { should eq true }
    end
  end
end
