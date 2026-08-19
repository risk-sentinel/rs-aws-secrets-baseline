require "aws_backend"

# The `aws-sdk-secretsmanager` gem is not part of inspec-aws's default vendored
# set, so `Aws::SecretsManager` is undefined at exec time even though the gem is
# present in the image. Defensive require (per the aws_account_contact /
# aws_workdocs_inventory pattern) so a missing gem degrades to a clear,
# attributable failure instead of `uninitialized constant Aws::SecretsManager`.
# Guarded so the three secretsmanager resources can each declare it without a
# redefinition warning, whatever order the library files load in.
unless defined?(SECRETSMANAGER_GEM_LOAD_ERROR)
  SECRETSMANAGER_GEM_LOAD_ERROR = begin
    require "aws-sdk-secretsmanager"
    nil
  rescue LoadError => e
    "aws-sdk-secretsmanager gem not installed: #{e.message}. File a tracking " \
      "issue against the cinc-auditor docker image to bundle the gem."
  end
end


# Vendored from inspec-aws (Apache-2.0). Carried locally because the
# resolved inspec-aws version no longer ships this resource. Enumerates
# all secrets via list_secrets with pagination.
class AWSSecretsManagerSecrets < AwsResourceBase
  name "aws_secretsmanager_secrets"
  desc "Lists all of the secrets that are stored by Secrets Manager in the AWS account."

  example "
    describe aws_secretsmanager_secrets do
      it { should exist }
    end
  "

  attr_reader :table

  FilterTable.create
    .register_column(:arns,                      field: :arn)
    .register_column(:names,                     field: :name)
    .register_column(:descriptions,              field: :description)
    .register_column(:kms_key_ids,               field: :kms_key_id)
    .register_column(:rotation_enableds,         field: :rotation_enabled)
    .register_column(:rotation_lambda_arns,      field: :rotation_lambda_arn)
    .register_column(:rotation_rules,            field: :rotation_rules)
    .register_column(:last_rotated_dates,        field: :last_rotated_date)
    .register_column(:last_changed_dates,        field: :last_changed_date)
    .register_column(:last_accessed_dates,       field: :last_accessed_date)
    .register_column(:deleted_dates,             field: :deleted_date)
    .register_column(:tags,                      field: :tags)
    .register_column(:secret_versions_to_stages, field: :secret_versions_to_stages)
    .register_column(:owning_services,           field: :owning_service)
    .register_column(:created_dates,             field: :created_date)
    .register_column(:primary_regions,           field: :primary_region)
    .install_filter_methods_on_resource(self, :table)

  def initialize(opts = {})
    super(opts)
    validate_parameters
    @query_params = {}
    @table = fetch_data
  end

  def fetch_data
    rows = []
    first = true
    loop do
      catch_aws_errors do
        @api_response = secretsmanager_client.list_secrets(@query_params)
      end
      # A nil response means catch_aws_errors swallowed something — an
      # AccessDenied, or a coding error such as calling a client accessor
      # AwsConnection does not define. Returning [] here would report an
      # account with secrets as an account with none, and every control that
      # scopes on `secrets_in_scope` would skip while looking clean. Not
      # being able to look is not the same as there being nothing to see.
      if @api_response.nil?
        raise Inspec::Exceptions::ResourceFailed,
              'aws_secretsmanager_secrets: list_secrets returned no response. The API call ' \
              'failed and the error was suppressed — check credentials, region and ' \
              'secretsmanager:ListSecrets permission. This is NOT an empty account.'
      end
      return rows if first && @api_response.secret_list.empty?
      first = false
      @api_response.secret_list.each do |res|
        rows += [{
          arn: res.arn,
          name: res.name,
          description: res.description,
          kms_key_id: res.kms_key_id,
          rotation_enabled: res.rotation_enabled,
          rotation_lambda_arn: res.rotation_lambda_arn,
          rotation_rules: res.rotation_rules,
          last_rotated_date: res.last_rotated_date,
          last_changed_date: res.last_changed_date,
          last_accessed_date: res.last_accessed_date,
          deleted_date: res.deleted_date,
          tags: res.tags,
          owning_service: res.owning_service,
          created_date: res.created_date,
          primary_region: res.primary_region,
        }]
      end
      break unless @api_response.next_token
      @query_params[:next_token] = @api_response.next_token
    end
    rows
  end

  private

  # AwsConnection's <service>_client accessors are a CLOSED LIST whose contents
  # vary by inspec-aws version: `main` defines ~60, the v1.21.0 tag this profile
  # pins defines 25 — and secretsmanager_client is not among them. Calling it
  # raises NoMethodError, which catch_aws_errors then swallows. aws_client(klass)
  # is the supported escape hatch and is version-independent.
  def secretsmanager_client
    if SECRETSMANAGER_GEM_LOAD_ERROR
      raise Inspec::Exceptions::ResourceFailed, SECRETSMANAGER_GEM_LOAD_ERROR
    end
    @aws.aws_client(Aws::SecretsManager::Client)
  end
end
