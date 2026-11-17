# encoding: UTF-8
#
# SEC-7.x — Private network access. NIST SC-7 / AC-17.

control "SEC-7.1" do
  title "Secrets Manager must be reachable via an interface VPC endpoint"
  desc "AWS recommends running on private networks: an interface VPC endpoint "\
       "(PrivateLink) for Secrets Manager keeps secret retrieval off the "\
       "public internet. Gated on require_vpc_endpoint."
  desc  'check', "
    Applies only when the input `require_vpc_endpoint` is true. Across the scan regions, at least one interface VPC endpoint for the Secrets Manager service (`com.amazonaws.<region>.secretsmanager`) must exist.
  "
  desc  'fix', "
    Create an interface endpoint in each VPC whose workloads read secrets:

    ```
    aws ec2 create-vpc-endpoint --vpc-endpoint-type Interface --vpc-id <vpc> --service-name com.amazonaws.<region>.secretsmanager --subnet-ids <subnet> ... --security-group-ids <sg> --private-dns-enabled
    ```
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['SC-7 a']
  tag ksi:                   ['KSI-CNA-ULN', 'KSI-SVC-EIS']
  tag nist_r4:               ['SC-7 a']
  tag cci:                   ['CCI-001097']
  tag local_number:          "SEC-7.1"
  tag srg:                   "SRG-NET-000205-CLD-000085"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  require_ep = input("require_vpc_endpoint")
  impact 0.5
  impact 0.0 unless require_ep
  only_if("require_vpc_endpoint is false") { require_ep }

  describe "Secrets Manager interface VPC endpoint" do
    subject { aws_secretsmanager_vpc_endpoints }
    it { should exist }
  end
end
