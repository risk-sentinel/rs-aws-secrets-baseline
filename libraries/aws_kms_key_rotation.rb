require "aws_backend"

# aws_kms_key_rotation — key-rotation status for a single KMS CMK.
#
# Why this exists (#13): SEC-2.2 read `rotation_enabled` off the stock
# `aws_kms_key` resource, which does not expose that property at the
# inspec-aws version this profile pins (tag: v1.21.0). Every assertion raised
# `undefined method 'rotation_enabled'`, so the control failed seven times
# while assessing nothing. That is an INABILITY TO ASSESS wearing the costume
# of a finding — SC-12(2) was unevidenced for the boundary, and a reader of
# the HDF could not tell that from a genuine rotation gap.
#
# Uses the `aws_client(Aws::KMS::Client)` escape hatch and calls
# GetKeyRotationStatus directly, which is version-independent. This is the same
# route aws_secretsmanager_secret_policy took for GetResourcePolicy, and it is
# preferred over bumping the inspec-aws pin: that pin also governs which
# <service>_client accessors exist, so moving it has a far wider blast radius
# than one property.
#
# On error the resource does NOT pretend rotation is off. `rotation_enabled`
# stays nil, `assessed?` is false, and `connection_error` carries the reason —
# so a control can distinguish "rotation is disabled" from "we could not look",
# which is the distinction the original defect destroyed.
class AwsKmsKeyRotation < AwsResourceBase
  name "aws_kms_key_rotation"
  desc "Key-rotation status for a KMS customer-managed key."
  example <<~EX
    describe aws_kms_key_rotation(key_id: arn) do
      it { should be_assessed }
      its("rotation_enabled") { should eq true }
    end
  EX

  attr_reader :key_id, :rotation_enabled, :connection_error

  def initialize(opts = {})
    opts = { key_id: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: %i(key_id))
    raise ArgumentError, "#{@__resource_name__}: key_id must be provided" if opts[:key_id].to_s.empty?

    @key_id           = opts[:key_id].to_s
    @rotation_enabled = nil
    @assessed         = false
    @connection_error = nil

    catch_aws_errors do
      resp = @aws.aws_client(Aws::KMS::Client).get_key_rotation_status(key_id: @key_id)
      @rotation_enabled = resp.key_rotation_enabled
      @assessed         = true
    end

    # catch_aws_errors swallows Aws::Errors::* after logging a warning, so a
    # denied or throttled call lands here with @assessed still false and no
    # exception to rescue. Without this the resource reports "not assessed"
    # correctly but cannot say why, and the warning is buried in the run log
    # rather than carried into the evidence.
    if !@assessed && @connection_error.nil?
      @connection_error = "GetKeyRotationStatus did not answer (see the AWS Service Error warning in the run log)"
    end
  rescue StandardError => e
    # Deliberately broad, and deliberately NOT silent. catch_aws_errors handles
    # only Aws::Errors::*; anything else (a missing method, a malformed key id)
    # would otherwise abort the whole control run. Recorded so `assessed?` is
    # false and the reason is visible, rather than leaving rotation_enabled nil
    # and letting it read as "rotation disabled".
    @connection_error = "#{e.class}: #{e.message}"
    @assessed = false
  end

  # True only when GetKeyRotationStatus actually answered. A control asserting
  # rotation should assert this FIRST, so an access failure cannot be reported
  # as a rotation finding.
  def assessed?
    @assessed
  end

  def exists?
    @assessed
  end

  def rotation_enabled?
    @rotation_enabled == true
  end

  def to_s
    suffix = @connection_error ? " — NOT ASSESSED: #{@connection_error}" : ""
    "KMS key rotation (#{@key_id})#{suffix}"
  end
end
