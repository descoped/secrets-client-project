/**
 * The {@code aws-secrets-manager} secrets provider. See
 * {@link io.descoped.secrets.provider.aws.AwsSecretsManagerClientInitializer}.
 */
module io.descoped.secrets.provider.aws {
    requires transitive io.descoped.secrets.api;

    exports io.descoped.secrets.provider.aws;

    provides io.descoped.secrets.api.SecretManagerClientInitializer with
            io.descoped.secrets.provider.aws.AwsSecretsManagerClientInitializer;
}
