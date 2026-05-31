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

  # The plural resource only registers trail_arns/names columns (no
  # multi-region filter), so resolve multi-region + logging on the
  # singular resource per trail.
  trail_names = aws_cloudtrail_trails.names
  multi_region_logging = trail_names.select do |name|
    t = aws_cloudtrail_trail(name)
    t.exists? && t.is_multi_region_trail && t.logging?
  end

  describe "Multi-region CloudTrail trails that are actively logging" do
    subject { multi_region_logging }
    it "must include at least one trail (captures Secrets Manager events)" do
      expect(multi_region_logging).not_to be_empty
    end
  end
end
