require "aws_backend"

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
# IamPolicyStatement module (ported from the AWS Foundations baseline).
class AwsSecretsManagerSecretPolicy < AwsResourceBase
  include RegionScope
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
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    explicit_region = opts.delete(:region)
    super(opts)
    validate_parameters(required: %i(secret_id))
    raise ArgumentError, "#{@__resource_name__}: secret_id must be provided" unless opts[:secret_id] && !opts[:secret_id].empty?

    @display_name    = opts[:secret_id]
    @secret_id       = opts[:secret_id]

    # A secret ARN already names its region, so an ARN answers the question by
    # itself. A bare NAME does not -- the same name can exist in several regions
    # -- so rather than assume one, resolve it. Silently picking a region would
    # report confidently on a secret that may not be the one meant.
    @region = client_region_for(@secret_id, explicit_region)
    @all_regions = @region ? [@region] : region_scope_or_fail!(@aws, region_override)
    @found_in_regions = []

    # A bare NAME is only unique within a region, so SEARCH for it rather than
    # binding to whichever region happens to be first. Taking the first would be
    # this whole defect in miniature: reporting confidently on a secret that may
    # not be the one meant, in a region that may not hold it at all.
    if @region.nil?
      each_region_client(::Aws::SecretsManager::Client) do |c, region|
        found = c.describe_secret(secret_id: @secret_id) rescue nil
        next if found.nil?
        @found_in_regions << region
        @region ||= region
      end
    end
    @statements      = []
    @replica_regions = []
    @policy_json     = nil
    @exists          = false

    catch_aws_errors do
      load_policy
      load_replication
    end
  end

  # Every region the secret name was found in. More than one means the NAME is
  # ambiguous across regions and a control should say which region it meant.
  attr_reader :region, :found_in_regions

  def ambiguous_across_regions?
    Array(@found_in_regions).size > 1
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

  # Region-bound when the region is known. @aws.aws_client caches by class with
  # no region in the key, so going through it would pin every lookup to whichever
  # region was seen first -- the original bug, one layer down.
  def secretsmanager_client
    r = @region || Array(@all_regions).first
    return ::Aws::SecretsManager::Client.new(region: r) if r
    @aws.aws_client(Aws::SecretsManager::Client)
  end
end
