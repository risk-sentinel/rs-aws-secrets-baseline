#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Bidirectional check for aws_kms_key_rotation (#13).
#
# #13 requires proving BOTH directions — "a key with rotation disabled fails, a
# key with it enabled passes — verified in both directions, not just the passing
# one". A resource hardwired to return false would satisfy a one-sided test, and
# that is close to the original defect: seven assertions that could never pass.
#
# Also asserts the third state the original code could not express: when the API
# call fails, the resource must report NOT ASSESSED rather than letting a nil
# rotation_enabled read as "rotation disabled".
#
# Run: ruby tests/unit/kms_rotation_test.rb   (needs `cinc-auditor vendor` first)

ENV["AWS_REGION"]            ||= "us-east-1"
ENV["AWS_ACCESS_KEY_ID"]     ||= "stubbed"
ENV["AWS_SECRET_ACCESS_KEY"] ||= "stubbed"

require "inspec"
require "aws-sdk-core"
require "aws-sdk-kms"

vendor = Dir.glob("vendor/*/libraries").find { |d| File.exist?(File.join(d, "aws_backend.rb")) }
abort "FATAL: no vendored inspec-aws — run `cinc-auditor vendor . --overwrite` first." if vendor.nil?
$LOAD_PATH.unshift(vendor)
require "aws_backend"
Dir.glob("libraries/_*.rb").sort.each { |f| eval(File.read(f), TOPLEVEL_BINDING, f) } # rubocop:disable Security/Eval
eval(File.read("libraries/aws_kms_key_rotation.rb"), TOPLEVEL_BINDING, "libraries/aws_kms_key_rotation.rb") # rubocop:disable Security/Eval

KEY = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"
FAILURES = []

def check(desc, actual, expected)
  if actual == expected
    puts "  PASS  #{desc} (#{actual.inspect})"
  else
    puts "  FAIL  #{desc} — expected #{expected.inspect}, got #{actual.inspect}"
    FAILURES << desc
  end
end

Aws.config[:stub_responses] = true

Aws.config[:kms] = { stub_responses: { get_key_rotation_status: { key_rotation_enabled: true } } }
r = AwsKmsKeyRotation.new(key_id: KEY)
check("rotation enabled -> assessed?",        r.assessed?,        true)
check("rotation enabled -> rotation_enabled", r.rotation_enabled, true)

Aws.config[:kms] = { stub_responses: { get_key_rotation_status: { key_rotation_enabled: false } } }
r = AwsKmsKeyRotation.new(key_id: KEY)
check("rotation disabled -> assessed?",        r.assessed?,        true)
check("rotation disabled -> rotation_enabled", r.rotation_enabled, false)

Aws.config[:kms] = { stub_responses: { get_key_rotation_status: "AccessDeniedException" } }
r = AwsKmsKeyRotation.new(key_id: KEY)
check("access denied -> assessed?",        r.assessed?,        false)
check("access denied -> rotation_enabled", r.rotation_enabled, nil)
puts "  note  to_s = #{r}"

puts
if FAILURES.empty?
  puts "kms rotation: OK (both directions plus the unassessed case)"
  exit 0
end
warn "kms rotation: #{FAILURES.size} FAILURE(S): #{FAILURES.join(', ')}"
exit 1
