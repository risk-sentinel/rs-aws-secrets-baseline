require "aws_backend"

# The `aws-sdk-secretsmanager` gem is not part of inspec-aws's default vendored
# set, so `Aws::SecretsManager` is undefined at exec time even though the gem is
# present in the image. Defensive require (per the aws_account_contact /
# aws_workdocs_inventory pattern) so a missing gem degrades to a clear,
# attributable failure instead of `uninitialized constant Aws::SecretsManager`.
# Guarded so the three secretsmanager resources can each declare it without a
# redefinition warning, whatever order the library files load in.
unless defined?(SECRETSMANAGER_GEM_LOAD_ERROR)
  SECRETSMANAGER_GEM_LOAD_ERROR = begin
    require "aws-sdk-secretsmanager"
    nil
  rescue LoadError => e
    "aws-sdk-secretsmanager gem not installed: #{e.message}. File a tracking " \
      "issue against the cinc-auditor docker image to bundle the gem."
  end
end


# aws_secretsmanager_secret_policy — resource-policy + replication
# introspection for a single Secrets Manager secret.
#
# The stock inspec-aws aws_secretsmanager_secret resource (describe_secret)
# exposes rotation, KMS key, dates, tags and primary_region, but NOT the
# resource policy (GetResourcePolicy). This custom resource adds it so the
# SEC-3.x resource-policy deep checks and SEC-4.1 replication check can
# assert real configuration rather than presence alone.
#
# Uses the aws_client(Aws::SecretsManager::Client) escape hatch. An earlier
# version of this comment asserted secretsmanager_client was enumerated in
# AwsConnection's <service>_client dispatcher. It is not, at the inspec-aws
# version this profile pins — the claim was never verified, and the resulting
# NoMethodError was swallowed by catch_aws_errors, emptying the secret table
# and skipping eleven controls against an account holding eight real secrets.
#
# Resource-policy statement analysis is delegated to the pure-Ruby
# IamPolicyStatement module (ported from foundations #72).
class AwsSecretsManagerSecretPolicy < AwsResourceBase
  name "aws_secretsmanager_secret_policy"
  desc "Resource policy and replication posture for a Secrets Manager secret."
  example <<~EX
    describe aws_secretsmanager_secret_policy(secret_id: arn) do
      it { should_not have_public_statements }
      it { should enforce_secure_transport }
    end
  EX

  attr_reader :secret_id, :policy_json, :statements, :replica_regions

  def initialize(opts = {})
    opts = { secret_id: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: %i(secret_id))
    raise ArgumentError, "#{@__resource_name__}: secret_id must be provided" unless opts[:secret_id] && !opts[:secret_id].empty?

    @display_name    = opts[:secret_id]
    @secret_id       = opts[:secret_id]
    @statements      = []
    @replica_regions = []
    @policy_json     = nil
    @exists          = false

    catch_aws_errors do
      load_policy
      load_replication
    end
  end

  def exists?
    @exists
  end

  # Allow statements with a wildcard principal and no narrowing condition.
  def public_statements
    @statements.select { |s| IamPolicyStatement.effectively_public?(s) }
  end

  def has_public_statements?
    !public_statements.empty?
  end

  # True only when the policy contains an explicit Deny on non-TLS access.
  def enforce_secure_transport?
    @statements.any? { |s| IamPolicyStatement.denies_insecure_transport?(s) }
  end

  def wildcard_action_statements
    @statements.select { |s| IamPolicyStatement.allow?(s) && IamPolicyStatement.action_is_wildcard?(s) }
  end

  def has_resource_policy?
    !@statements.empty?
  end

  def replicated?
    !@replica_regions.empty?
  end

  def to_s
    "Secrets Manager secret policy #{@display_name}"
  end

  private

  def load_policy
    resp = secretsmanager_client.get_resource_policy({ secret_id: @secret_id })
    @exists = true
    @policy_json = resp.resource_policy
    return if @policy_json.nil?
    @statements = IamPolicyStatement.parse(@policy_json)
  end

  def load_replication
    resp = secretsmanager_client.describe_secret({ secret_id: @secret_id })
    @exists = true
    @replica_regions = Array(resp.replication_status).map(&:region).compact
  end

  def secretsmanager_client
    if SECRETSMANAGER_GEM_LOAD_ERROR
      raise Inspec::Exceptions::ResourceFailed, SECRETSMANAGER_GEM_LOAD_ERROR
    end
    @aws.aws_client(Aws::SecretsManager::Client)
  end
end
