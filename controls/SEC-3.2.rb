# encoding: UTF-8

control "SEC-3.2" do
  title "Secret resource policies must enforce encryption in transit (TLS)"
  desc "When a resource policy is present it should Deny non-TLS access via "\
       "aws:SecureTransport=false. Secrets with no resource policy rely on "\
       "the Secrets Manager TLS-only endpoints (AWS-inherited) and are N/A."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['SC-8 (1)', 'SC-8']
  tag ksi:                   ['KSI-CNA-MAT', 'KSI-CNA-ULN', 'KSI-SVC-SIN']
  tag nist_r4:               ['SC-8', 'SC-8 (1)']
  tag cci:                   ['CCI-002421', 'CCI-002418']
  tag local_number:          "SEC-3.2"
  tag srg:                   "SRG-OS-000033-CLD-000115"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  # Applicability is TWO conditions, and both have to be expressed as impact +
  # only_if. Previously the second was a bare `next`, so when no secret carried
  # a resource policy the control registered no describe blocks at all and
  # emitted zero results: not passed, not N/A, absent. A control that asserts
  # nothing while reporting not-red is the exact failure this profile exists to
  # catch, and it also blocks `hdf convert`, whose schema requires at least one
  # result per requirement.
  scoped = secrets_in_scope
  with_policy = scoped.select { |arn| aws_secretsmanager_secret_policy(secret_id: arn).has_resource_policy? }
  applicable = !with_policy.empty?
  impact 0.5
  impact 0.0 unless applicable
  # Secrets with no resource policy rely on the Secrets Manager TLS-only
  # endpoints, which is AWS-inherited — genuinely N/A, and now says so.
  only_if("No customer-owned secret carries a resource policy; TLS enforcement is inherited from the Secrets Manager TLS-only endpoints") { applicable }

  with_policy.each do |arn|
    describe "TLS enforcement in resource policy for #{arn}" do
      subject { aws_secretsmanager_secret_policy(secret_id: arn).enforce_secure_transport? }
      it { should eq true }
    end
  end
end
