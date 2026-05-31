# encoding: UTF-8
#
# Helper module mixed into the InSpec control-eval context so every
# control can call `secrets_in_scope` directly (same pattern as
# cis-aws-compute's _compute_service_scope_helpers).
#
# secrets_in_scope returns the ARNs of customer-owned secrets only:
# secrets created and managed by another AWS service (owning_service set,
# e.g. RDS/Redshift-managed master-user secrets) are excluded — their
# rotation, KMS key and policy are AWS-managed, so failing them against a
# customer baseline would be a false positive (inherited-from-AWS).
module SecretsScopeHelpers
  def secrets_in_scope
    @secrets_in_scope ||= begin
      all = aws_secretsmanager_secrets
      customer_owned = []
      all.arns.each_with_index do |arn, i|
        owning = all.owning_services[i]
        next if owning && !owning.to_s.empty?
        customer_owned << arn
      end
      customer_owned
    rescue StandardError
      []
    end
  end
end

::Inspec::Rule.include(SecretsScopeHelpers)
