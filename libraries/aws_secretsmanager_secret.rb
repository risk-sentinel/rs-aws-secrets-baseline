require "aws_backend"

# Vendored from inspec-aws (Apache-2.0). The inspec-aws version this
# profile resolves to no longer ships aws_secretsmanager_secret(s), so we
# carry a local copy. describe_secret exposes rotation_enabled,
# rotation_rules, last_rotated_date, last_accessed_date, kms_key_id, tags,
# primary_region, etc., via create_resource_methods.
class AWSSecretsManagerSecret < AwsResourceBase
  include RegionScope
  name "aws_secretsmanager_secret"
  desc "Retrieves the details of a secret."

  example "
    describe aws_secretsmanager_secret(secret_id: 'Secret-Id') do
      it { should exist }
    end
  "

  def initialize(opts = {})
    opts = { secret_id: opts } if opts.is_a?(String)
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    explicit_region = opts.delete(:region)
    super(opts)
    validate_parameters(required: %i(secret_id))
    raise ArgumentError, "#{@__resource_name__}: secret_id must be provided" unless opts[:secret_id] && !opts[:secret_id].empty?
    @display_name = opts[:secret_id]

    # A secret ARN already names its region, so an ARN answers the question by
    # itself. A bare NAME does not -- the same name can exist in several regions
    # -- so resolve it rather than assume. Silently picking a region would report
    # confidently on a secret that may not be the one meant.
    @region = client_region_for(opts[:secret_id], explicit_region)
    @all_regions = @region ? [@region] : region_scope_or_fail!(@aws, region_override)
    @found_in_regions = []

    # A bare NAME is only unique within a region, so SEARCH for it rather than
    # binding to whichever region happens to be first. Taking the first would be
    # this whole defect in miniature: reporting confidently on a secret that may
    # not be the one meant, in a region that may not hold it at all.
    if @region.nil?
      each_region_client(::Aws::SecretsManager::Client) do |c, region|
        found = c.describe_secret(secret_id: opts[:secret_id]) rescue nil
        next if found.nil?
        @found_in_regions << region
        @region ||= region
      end
    end

    catch_aws_errors do
      resp = secretsmanager_client.describe_secret({ secret_id: opts[:secret_id] })
      # describe_secret omits fields that are unset (e.g. KmsKeyId for the
      # AWS-managed key, RotationEnabled for never-rotated secrets), so
      # create_resource_methods would not define those accessors and the
      # control would hit NoMethodError. Merge nil-defaults for every
      # field a control may read, so the accessor always exists.
      defaults = {
        arn: nil, name: nil, kms_key_id: nil, rotation_enabled: nil,
        rotation_rules: nil, rotation_lambda_arn: nil, last_rotated_date: nil,
        last_changed_date: nil, last_accessed_date: nil, deleted_date: nil,
        tags: [], owning_service: nil, created_date: nil, primary_region: nil,
        replication_status: []
      }
      @res = defaults.merge(resp.to_h)
      create_resource_methods(@res)
      # create_resource_methods does NOT define an accessor for a nil value, so
      # merging nil-defaults above is not by itself enough — verified against a
      # never-accessed secret, where `last_accessed_date` still raised
      # NoMethodError. Define whatever it skipped, so every documented field
      # answers nil instead of blowing up the control that reads it.
      defaults.each_key do |field|
        next if respond_to?(field)
        define_singleton_method(field) { @res[field] }
      end
    end
  end

  def resource_id
    @res[:arn]
  end

  def secret_id
    return nil unless exists?
    @res[:secret_id]
  end

  # Every region the secret name was found in. More than one means the NAME is
  # ambiguous across regions and a control should say which region it meant.
  attr_reader :region, :found_in_regions

  def ambiguous_across_regions?
    Array(@found_in_regions).size > 1
  end

  def exists?
    !@res.nil? && !@res.empty?
  end

  def to_s
    "Secret ID: #{@display_name}"
  end

  private

  # See aws_secretsmanager_secrets: the <service>_client dispatcher is a closed
  # list and does not include secretsmanager_client at the pinned inspec-aws
  # version. aws_client(klass) is the supported, version-independent path.
  # Region-bound when the region is known. @aws.aws_client caches by class with
  # no region in the key, so going through it would pin every lookup to whichever
  # region was seen first -- the original bug, one layer down.
  def secretsmanager_client
    r = @region || Array(@all_regions).first
    return ::Aws::SecretsManager::Client.new(region: r) if r
    @aws.aws_client(Aws::SecretsManager::Client)
  end
end
