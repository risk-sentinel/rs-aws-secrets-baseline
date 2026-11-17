# encoding: UTF-8
#
# The AWS-managed key Secrets Manager uses when a secret names no
# customer-managed KMS key. Controls that require a customer-managed key match
# a secret's key id against it.
#
# A method on ::Inspec::Rule rather than a constant: a constant defined in a
# library is not visible from control bodies. Read it into a local in the
# control body; `it` blocks run in RSpec's scope, where the method is absent.

module SecretsKmsDefaults
  def secretsmanager_default_kms
    %r{alias/aws/secretsmanager}
  end
end

::Inspec::Rule.include(SecretsKmsDefaults)
