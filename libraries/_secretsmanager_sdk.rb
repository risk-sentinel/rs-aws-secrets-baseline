# encoding: UTF-8
#
# SDK availability for the Secrets Manager resources.
#
# The `aws-sdk-secretsmanager` gem ships in the cinc-auditor image but is NOT
# part of inspec-aws's vendored require set, so `Aws::SecretsManager` is
# undefined at exec time unless something asks for it. Left unasked, the failure
# surfaces as `uninitialized constant Aws::SecretsManager` from whichever
# control happened to run first — which blames the control for a problem with
# the image.
#
# A file of its own, with no class or module definition, so the three
# secretsmanager resources declare this once between them rather than three
# times. The underscore prefix matches the existing helper convention here
# (_aws_backend_bootstrap, _secrets_scope_helpers) and loads ahead of the
# aws_secretsmanager_* resources.
require "aws-sdk-secretsmanager"

# ---- Why this is a bare require and not a guarded one -----------------------
#
# The estate's other resources wrap this in `begin/rescue LoadError` and hand
# controls a friendly message. That pattern is deliberate elsewhere, where one
# missing SDK should not stop a profile whose other controls do not need it.
#
# It is the wrong trade here. Twelve of this profile's fourteen controls need
# Secrets Manager, so degrading gracefully buys almost nothing — and a bare
# require fails with `cannot load such file -- aws-sdk-secretsmanager`, which
# names the missing gem more precisely than any message we would write. Failing
# at load time, loudly, on the actual cause beats fourteen controls each
# reporting a resource error.
#
# It also keeps the `require` at the top of the file where a reader and the
# linter both expect it (SonarCloud rubydre:S7816).
