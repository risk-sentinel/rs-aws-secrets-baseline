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
  # Raised when the secrets in scope cannot be listed. An empty list would make
  # every per-secret control skip as "no secrets in scope" -- reporting an
  # account it could not read as an account with nothing to check.
  class ScopeUnreadable < StandardError; end

  def secrets_in_scope
    @secrets_in_scope ||= begin
      # Resources cannot read inputs, so the region scope is passed in here.
      all = aws_secretsmanager_secrets(regions: input("scan_regions"))
      # The resource records a region it could not list in region_errors and
      # moves on, and a missing scan_regions fails the resource. Either way
      # the list below would be short or empty, so stop here instead.
      problems = all.resource_failed? ? [all.resource_exception_message.to_s] : []
      problems += all.region_errors.map { |region, err| "#{region}: #{err}" }
      unless problems.empty?
        raise ScopeUnreadable,
              "could not list Secrets Manager secrets, so nothing was assessed: #{problems.join('; ')}"
      end

      customer_owned = []
      all.arns.each_with_index do |arn, i|
        owning = all.owning_services[i]
        next if owning && !owning.to_s.empty?
        customer_owned << arn
      end
      customer_owned
    end
  end
end

::Inspec::Rule.include(SecretsScopeHelpers)
