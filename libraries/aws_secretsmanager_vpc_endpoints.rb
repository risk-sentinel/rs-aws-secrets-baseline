require "aws_backend"

# aws_secretsmanager_vpc_endpoints — lists interface VPC endpoints for the
# Secrets Manager service in the current region. The resolved inspec-aws
# version does not ship aws_vpc_endpoints, so we query EC2 directly via
# DescribeVpcEndpoints. NOTE the accessor is `compute_client`, not
# `ec2_client`: AwsConnection is a closed-list dispatcher that defines roughly
# sixty explicit <service>_client methods and EC2's is named compute_client.
# `@aws.ec2_client` raises NoMethodError at exec, and neither `cinc-auditor
# check` nor `json` can see it because they only load the resource. Partition-aware:
# matches any service_name ending in ".secretsmanager" so it works in both
# com.amazonaws.<region>.secretsmanager (Commercial) and the aws-us-gov
# namespace.
class AwsSecretsManagerVpcEndpoints < AwsResourceBase
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

    catch_aws_errors do
      token = nil
      loop do
        params = {
          filters: [{ name: "vpc-endpoint-type", values: ["Interface"] }],
        }
        params[:next_token] = token if token
        resp = @aws.compute_client.describe_vpc_endpoints(params)
        resp.vpc_endpoints.each do |ep|
          next unless ep.service_name.to_s.end_with?(".secretsmanager")
          @endpoint_ids << ep.vpc_endpoint_id
          @service_names << ep.service_name
        end
        token = resp.next_token
        break unless token
      end
    end
  end

  def exists?
    !@endpoint_ids.empty?
  end

  def to_s
    "Secrets Manager VPC endpoints (#{@endpoint_ids.size})"
  end
end
