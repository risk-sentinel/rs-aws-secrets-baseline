require "aws_backend"

# aws_secretsmanager_vpc_endpoints — lists interface VPC endpoints for the
# Secrets Manager service in the current region. The resolved inspec-aws
# version does not ship aws_vpc_endpoints, so we query ec2_client
# (DescribeVpcEndpoints, an enumerated client) directly. Partition-aware:
# matches any service_name ending in ".secretsmanager" so it works in both
# com.amazonaws.<region>.secretsmanager (Commercial) and the aws-us-gov
# namespace.
class AwsSecretsManagerVpcEndpoints < AwsResourceBase
  include RegionScope
  name "aws_secretsmanager_vpc_endpoints"
  desc "Interface VPC endpoints for AWS Secrets Manager in the current region."
  example <<~EX
    describe aws_secretsmanager_vpc_endpoints do
      it { should exist }
    end
  EX

  attr_reader :endpoint_ids, :service_names

  def initialize(opts = {})
    super(opts)
    validate_parameters
    @endpoint_ids = []
    @service_names = []
    @endpoint_regions = {}
    # A VPC endpoint is regional. Checking one region answers for one region --
    # and a boundary with endpoints in us-west-2 but none in us-east-1 would
    # report as having none at all.
    @all_regions = region_scope_or_fail!(@aws, region_override)

    each_region_client(::Aws::EC2::Client) do |client, region|
      token = nil
      loop do
        params = {
          filters: [{ name: "vpc-endpoint-type", values: ["Interface"] }],
        }
        params[:next_token] = token if token
        resp = client.describe_vpc_endpoints(params)
        resp.vpc_endpoints.each do |ep|
          next unless ep.service_name.to_s.end_with?(".secretsmanager")
          @endpoint_ids << ep.vpc_endpoint_id
          @service_names << ep.service_name
          (@endpoint_regions[region] ||= []) << ep.vpc_endpoint_id
        end
        token = resp.next_token
        break unless token
      end
    end
  end

  # Which regions actually have a Secrets Manager interface endpoint, so a gap
  # names where it is rather than reading as a global absence.
  def endpoint_regions
    @endpoint_regions ||= {}
  end

  def regions_without_endpoint
    Array(@all_regions) - endpoint_regions.keys
  end

  def exists?
    !@endpoint_ids.empty?
  end

  def to_s
    "Secrets Manager VPC endpoints (#{@endpoint_ids.size})"
  end
end
