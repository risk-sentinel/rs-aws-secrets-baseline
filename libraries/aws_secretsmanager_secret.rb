require "aws_backend"

# Vendored from inspec-aws (Apache-2.0). The inspec-aws version this
# profile resolves to no longer ships aws_secretsmanager_secret(s), so we
# carry a local copy. describe_secret exposes rotation_enabled,
# rotation_rules, last_rotated_date, last_accessed_date, kms_key_id, tags,
# primary_region, etc., via create_resource_methods.
class AWSSecretsManagerSecret < AwsResourceBase
  name "aws_secretsmanager_secret"
  desc "Retrieves the details of a secret."

  example "
    describe aws_secretsmanager_secret(secret_id: 'Secret-Id') do
      it { should exist }
    end
  "

  def initialize(opts = {})
    opts = { secret_id: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: %i(secret_id))
    raise ArgumentError, "#{@__resource_name__}: secret_id must be provided" unless opts[:secret_id] && !opts[:secret_id].empty?
    @display_name = opts[:secret_id]
    catch_aws_errors do
      resp = @aws.secretsmanager_client.describe_secret({ secret_id: opts[:secret_id] })
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
    end
  end

  def resource_id
    @res[:arn]
  end

  def secret_id
    return nil unless exists?
    @res[:secret_id]
  end

  def exists?
    !@res.nil? && !@res.empty?
  end

  def to_s
    "Secret ID: #{@display_name}"
  end
end
