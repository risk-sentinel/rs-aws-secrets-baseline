# encoding: UTF-8
#
# SEC-5.x — Inventory hygiene. NIST CM-8 / AC-2(3).

control "SEC-5.1" do
  title "Secrets must carry required governance tags"
  desc "Secrets must be tagged for ownership / classification. When "\
       "required_tag_keys is set, every listed key must be present; when "\
       "empty, at least one non-system tag must exist."
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ["CM-8"]
  tag cci:                   ["CCI-000366"]
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

control "SEC-5.2" do
  title "Unused / stale secrets must be remediated"
  desc "Secrets not accessed within stale_days are candidates for removal to "\
       "reduce the attack surface. Never-accessed/new secrets are not flagged."
  tag severity:              "low"
  tag nist:                  ["AC-2 (3)"]
  tag cci:                   ["CCI-000017"]
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
