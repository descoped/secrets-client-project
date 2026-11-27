# Provider: aws-secrets-manager

[AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) through its JSON API, signed with Signature Version 4,
with no AWS SDK and no dependency but the API. It uses the library's own HTTP/1.1 client, JSON reader and codecs, and
TLS, SHA-256 and HMAC-SHA256 through the system's OpenSSL 3, all on guarded memory: the secret access key, the
session token and the values are never on the Java heap.

- Maven: `io.descoped.secrets:secrets-provider-aws-secrets-manager`, scope `runtime`
- Provider name: `aws-secrets-manager`
- JPMS module: `io.descoped.secrets.provider.aws`; only the initializer is public
- Depends on: [secrets-client-api](../api.md) only
- Needs native access: `--enable-native-access=io.descoped.secrets.api` (`ALL-UNNAMED` on the class path)
- Needs OpenSSL 3: `libssl.so.3` and `libcrypto.so.3` on Linux (Debian and Ubuntu: the `libssl3` package, which
  minimal and distroless images may lack); on macOS, `brew install openssl@3`

## Configuration

Key | Description
---|---
`secrets.provider` | `aws-secrets-manager` (required)
`secrets.region` | the region, such as `eu-north-1`; else `AWS_REGION`, else `AWS_DEFAULT_REGION` (required)
`secrets.credentials` | where credentials come from: `default` (the default), the chain below; or only `profile`, `container`, `instance` or `environment`
`secrets.credentials-path` | the shared credentials file; else the file `AWS_SHARED_CREDENTIALS_FILE` names, else `~/.aws/credentials` (`~` from `HOME`)
`secrets.aws-profile` | the profile in that file; else `AWS_PROFILE`, else `default`
`secrets.container-credentials-uri` | the container credentials endpoint; else `AWS_CONTAINER_CREDENTIALS_FULL_URI`, else `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` on `169.254.170.2`. http only to the ECS and EKS Pod Identity addresses or a loopback address; else https
`secrets.container-authorization-token-file` | the file of that endpoint's authorization token; else `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`
`secrets.instance-metadata-endpoint` | EC2 instance metadata; else `AWS_EC2_METADATA_SERVICE_ENDPOINT`, else `http://169.254.169.254`
`secrets.endpoint` | the API endpoint, default `https://secretsmanager.<region>.amazonaws.com` (`amazonaws.com.cn` in the China regions): a VPC or FIPS endpoint, or a test server; https, plain http only for a loopback address
`secrets.kms-key-id` | the KMS key for secrets that `addVersion` creates (key ID, ARN or alias); the account's `aws/secretsmanager` key when absent
`secrets.replica-regions` | comma-separated regions to replicate secrets that `addVersion` creates to
`secrets.connect-timeout` | ISO-8601 duration for connecting, default `PT10S`
`secrets.request-timeout` | ISO-8601 duration for a whole request, default `PT30S`
`secrets.tls.ca-file` | a PEM file of the only certificates to trust, such as a private CA; the system's trusted certificates when absent
`secrets.memory.guard`, `secrets.memory.lock` | the guarded memory; see [the API](../api.md#guarded-memory-secretmemory-and-secret)

```java
try (SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "aws-secrets-manager",
        "secrets.region", "eu-north-1"));
     Secret key = client.read("payments/signing-key")) {
    key.withSegment(segment -> sign(segment, message));
}
```

## Credentials

Credentials come from the source `secrets.credentials` names, or else from the first of this chain that applies, in
the order of the AWS SDKs where that keeps the guarantee:

1. `AWS_ACCESS_KEY_ID` set: the client refuses to start. The JVM holds its environment as `String`s on the heap for
   its whole life, so keys there are outside the guarantee whatever the client does. `secrets.credentials=environment`
   uses them anyway (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`), for a platform that offers
   nothing else, such as AWS Lambda. They are never skipped silently, since an application that sets them means them.
2. `AWS_WEB_IDENTITY_TOKEN_FILE` set: refused; web identity (EKS IRSA) is not supported yet. EKS Pod Identity is.
3. `profile`: the shared credentials file, when it is configured or `~/.aws/credentials` exists.
4. `container`: the container credentials endpoint, when it is configured or the platform sets its variables: the
   ECS task role (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`) and EKS Pod Identity (`AWS_CONTAINER_CREDENTIALS_FULL_URI`
   with `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`). A token in `AWS_CONTAINER_AUTHORIZATION_TOKEN` is refused, for the
   same reason as keys in the environment.
5. `instance`: EC2 instance metadata, unless `AWS_EC2_METADATA_DISABLED` is `true`.

Nothing is fetched until the first request, so a missing source is reported then, before anything is sent to Secrets
Manager. Temporary credentials are fetched again five minutes before they expire.

- **Shared credentials file**, as `aws configure` writes it: `aws_access_key_id`, `aws_secret_access_key` and, for
  temporary keys, `aws_session_token`, in the profile's section. The file is read into guarded memory and parsed
  there; only the access key ID, which is an identifier, becomes a `String`. Long-term keys are kept; temporary ones
  are read from the file again every minute, so that a tool that renews them there, such as
  `aws configure export-credentials` or a SAML helper, is followed.
- **Container credentials endpoint.** The authorization token, if any, is read from its file into guarded memory on
  each fetch (the platform rotates it) and sent from there. The response is read and parsed in guarded memory: the
  secret access key and the session token are unescaped from it straight into their own guarded memory.
- **EC2 instance metadata**, IMDSv2 only: a session token from `PUT /latest/api/token`, kept in guarded memory and
  sent from there, then the instance profile's role and its credentials, parsed as above. IMDSv1, without a token, is
  never used.

## Versions and values

- `read(name)` and `read(name, "latest")` read the current version (`AWSCURRENT`).
- `read(name, version)` with a version ID reads that version; any other string is a staging label, such as
  `AWSPREVIOUS`. A custom staging label of 32 to 64 letters, digits and hyphens that does not start with `AWS` looks
  like a version ID, and is read as one.
- `addVersion(name, value)` adds a version as `AWSCURRENT`, the previous one becoming `AWSPREVIOUS`, and returns its
  version ID. If the secret does not exist, it is created with the value (with `secrets.kms-key-id` and
  `secrets.replica-regions`). Each request carries a new client request token, so a retried request never adds a
  second version.
- A value that is valid UTF-8 is written as `SecretString`, as other AWS tools expect, and any other value as
  `SecretBinary`. Both are read back as the same bytes.
- Names are 1 to 512 letters, digits and `/_+=.@-`, or a secret's ARN. Reading a name or version outside that rule is a
  `SecretNotFoundException`, and `addVersion` with such a name a `SecretManagerException`; neither sends a request.
  A missing secret or version is a `SecretNotFoundException`.
- Errors name the HTTP status, AWS's error type and message (such as `AccessDeniedException`), never the response
  body.

## Memory, signing and TLS

Each request is built in guarded memory: the body with the value (escaped for JSON, or Base64-encoded, in place), and
the `X-Amz-Security-Token` header. Signing works there too:

- the body is hashed with SHA-256 in place;
- the canonical request, which includes the session token, is built and hashed in guarded memory;
- the signing key is derived from the secret access key by HMAC-SHA256 (`AWS4` + key, the date, the region, the
  service, `aws4_request`) in guarded memory, anew for each request.

SHA-256 and HMAC-SHA256 go through OpenSSL's libcrypto, not the JDK: the JDK's `Mac` copies its key into a heap array,
and `MessageDigest` buffers through heap arrays. TLS goes through OpenSSL's libssl, as for the
[Google provider](google-secret-manager.md#memory-and-tls). Each response is read into guarded memory, and the value
unescaped or decoded from Base64 straight into the `Secret` that `read` returns.

## Testing

The tests run against `FakeAws`, a local server (http or https) that keeps secrets with versions and staging labels
as AWS does, and checks every request's signature with a separate SigV4 implementation on the JDK, which is itself
checked against AWS's published examples. They cover string and binary values, versions and stages, not-found,
create-on-write and its race, the KMS key and replicas, temporary credentials, a wrong key, errors, malformed
responses, timeouts, the credentials file, and the configuration. `FakeAws` also serves the container credentials
endpoint and IMDSv2, for `AwsCredentialsTest`. `AwsSecretsManagerCanaryTest` runs the canary gate: the canary is the
secret access key or the session token, the container authorization token or the IMDS session token, and the value
(as `SecretString` and as `SecretBinary`), read and written back, over http and TLS; the child JVM's heap dump must
not hold it. It also runs the default chain in a child JVM with an environment of its own: finding the container
endpoint, and refusing keys and tokens in the environment.

`AwsSecretsManagerLiveTest` runs against a real account when `SECRETS_AWS_TEST_REGION` is set (`just live-aws`),
with the profile in `SECRETS_AWS_TEST_PROFILE`. It adds versions to the secrets `secrets-client-live-test` and
`secrets-client-live-test-binary`, creating them if needed. It is not run in CI.
