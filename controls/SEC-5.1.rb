# encoding: UTF-8

control "SEC-5.1" do
  title "Secrets must carry required governance tags"
  desc "Secrets must be tagged for ownership / classification. When "\
       "required_tag_keys is set, every listed key must be present; when "\
       "empty, at least one non-system tag must exist."
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ['CM-8 a 5']
  tag ksi:                   ['KSI-PIY-GIV']
  tag nist_r4:               ['CM-8']
  tag cci:                   ['CCI-003967']
  tag local_number:          "SEC-5.1"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  required = input("required_tag_keys")
  scoped = secrets_in_scope
  applicable = !scoped.empty?
  impact 0.3
  impact 0.0 unless applicable
  only_if("No customer-owned Secrets Manager secrets in scope") { applicable }

  scoped.each do |arn|
    raw = aws_secretsmanager_secret(secret_id: arn).tags
    # describe_secret returns Tags as an array of {key:, value:} hashes.
    present_keys = Array(raw).map { |t| t.is_a?(Hash) ? (t[:key] || t["Key"]) : nil }.compact.map(&:to_s)
    describe "Tags for #{arn}" do
      subject { present_keys }
      if required.empty?
        it "must have at least one tag" do
          expect(present_keys).not_to be_empty
        end
      else
        it "must include all required tag keys (#{required.join(', ')})" do
          expect(present_keys).to include(*required)
        end
      end
    end
  end
end
