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
`secrets.credentials-path` | the shared credentials file; else the file `AWS_SHARED_CREDENTIALS_FILE` names, else `~/.aws/credentials`
`secrets.aws-profile` | the profile in that file; else `AWS_PROFILE`, else `default`
`secrets.endpoint` | the API endpoint, default `https://secretsmanager.<region>.amazonaws.com`: a VPC or FIPS endpoint, or a test server; https, plain http only for a loopback address
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

This version reads credentials from the shared credentials file, as `aws configure` writes it: `aws_access_key_id`,
`aws_secret_access_key` and, for temporary keys, `aws_session_token`, in the profile's section. The file is read into
guarded memory and parsed there; only the access key ID, which is an identifier, becomes a `String`. The file is read
on the first request, so a missing file or profile is reported then, before anything is sent.

Not supported yet: the ECS container credentials endpoint, EC2 instance metadata (IMDSv2) and web identity (EKS
IRSA). Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) are not read: the JVM holds the
environment as `String`s on the heap.

## Versions and values

- `read(name)` and `read(name, "latest")` read the current version (`AWSCURRENT`).
- `read(name, version)` with a version ID reads that version; any other string is a staging label, such as
  `AWSPREVIOUS`.
- `addVersion(name, value)` adds a version as `AWSCURRENT`, the previous one becoming `AWSPREVIOUS`, and returns its
  version ID. If the secret does not exist, it is created with the value (with `secrets.kms-key-id` and
  `secrets.replica-regions`). Each request carries a new client request token, so a retried request never adds a
  second version.
- A value that is valid UTF-8 is written as `SecretString`, as other AWS tools expect, and any other value as
  `SecretBinary`. Both are read back as the same bytes.
- Names are 1 to 512 letters, digits and `/_+=.@-`, or an ARN. Reading a name or version outside that rule is a
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
responses, timeouts, the credentials file, and the configuration. `AwsSecretsManagerCanaryTest` runs the canary gate:
the canary is the secret access key or the session token, and the value, read and written back, over http and TLS;
the child JVM's heap dump must not hold it.

`AwsSecretsManagerLiveTest` runs against a real account when `SECRETS_AWS_TEST_REGION` is set (`just live-aws`),
with the profile in `SECRETS_AWS_TEST_PROFILE`. It adds versions to the secrets `secrets-client-live-test` and
`secrets-client-live-test-binary`, creating them if needed. It is not run in CI.
