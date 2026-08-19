# encoding: UTF-8
#
# SDK availability for the Secrets Manager resources. Deliberately a file of its
# own, containing no class or module definition, so the `require` sits at the
# top of a file with nothing above it to be "after" — and so the three
# secretsmanager resources declare this once between them rather than three
# times.
#
# The `aws-sdk-secretsmanager` gem ships in the cinc-auditor image but is NOT
# part of inspec-aws's vendored require set, so `Aws::SecretsManager` is
# undefined at exec time unless something asks for it. Without the guard a
# missing gem surfaces as `uninitialized constant Aws::SecretsManager` from
# whichever control happened to run first, which attributes the failure to the
# control rather than to the image.
#
# Underscore prefix matches the existing helper convention here
# (_aws_backend_bootstrap, _secrets_scope_helpers) and loads ahead of the
# aws_secretsmanager_* resources.

SECRETSMANAGER_GEM_LOAD_ERROR = begin
  require "aws-sdk-secretsmanager"
  nil
rescue LoadError => e
  "aws-sdk-secretsmanager gem not installed: #{e.message}. File a tracking " \
    "issue against the cinc-auditor docker image to bundle the gem."
end
