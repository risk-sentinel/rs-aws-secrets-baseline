require "aws_backend"

# aws_kms_key_crypto — the cryptographic properties of one KMS key, from
# DescribeKey: state, key spec, usage and key-material origin.
#
#   key = aws_kms_key_crypto(key_id: arn_or_alias, region: "us-east-1")
#   describe key do
#     it { should be_assessed }
#     its("key_state") { should eq "Enabled" }
#   end
#
# A key ARN names its region; a bare key id or alias is resolved in the region
# passed. When DescribeKey does not answer, every property stays nil,
# `assessed?` is false and `connection_error` says why, so a control can tell
# "the key is wrong" from "the key could not be read".
class AwsKmsKeyCrypto < AwsResourceBase
  name "aws_kms_key_crypto"
  desc "State, key spec, usage and origin of a KMS key."
  example <<~EX
    describe aws_kms_key_crypto(key_id: "alias/aws/secretsmanager", region: "us-east-1") do
      it { should be_assessed }
      its("key_spec") { should eq "SYMMETRIC_DEFAULT" }
    end
  EX

  attr_reader :key_id, :region, :key_arn, :key_state, :key_spec, :key_usage,
              :origin, :key_manager, :connection_error

  def initialize(opts = {})
    opts = { key_id: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: %i(key_id), allow: %i(region))
    raise ArgumentError, "#{@__resource_name__}: key_id must be provided" if opts[:key_id].to_s.empty?

    @key_id = opts[:key_id].to_s
    arn_region = @key_id.start_with?("arn:") ? @key_id.split(":")[3].to_s : ""
    @region = arn_region.empty? ? opts[:region].to_s : arn_region
    @assessed = false
    @connection_error = nil

    catch_aws_errors do
      client = @region.empty? ? @aws.aws_client(Aws::KMS::Client) : ::Aws::KMS::Client.new(region: @region)
      meta = client.describe_key(key_id: @key_id).key_metadata
      @key_arn     = meta.arn
      @key_state   = meta.key_state
      @key_spec    = meta.respond_to?(:key_spec) && meta.key_spec ? meta.key_spec : meta.customer_master_key_spec
      @key_usage   = meta.key_usage
      @origin      = meta.origin
      @key_manager = meta.key_manager
      @assessed    = true
    end

    # catch_aws_errors logs and swallows Aws::Errors::*, leaving no exception.
    if !@assessed && @connection_error.nil?
      @connection_error = "DescribeKey did not answer (see the AWS Service Error warning in the run log)"
    end
  rescue StandardError => e
    @connection_error = "#{e.class}: #{e.message}"
    @assessed = false
  end

  def assessed?
    @assessed
  end

  def exists?
    @assessed
  end

  def to_s
    suffix = @connection_error ? " — NOT ASSESSED: #{@connection_error}" : ""
    "KMS key #{@key_id}#{suffix}"
  end
end
