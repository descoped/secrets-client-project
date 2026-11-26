# Provider: google-secret-manager

[Google Secret Manager](https://cloud.google.com/secret-manager), read and write, through its REST API. Authentication
by [google-auth](https://github.com/googleapis/google-auth-library-java); no gRPC and no Google Cloud client library.

- Maven: `io.descoped.secrets:secrets-provider-google-secret-manager`, scope `runtime`
- Provider name: `google-secret-manager`
- JPMS module: `io.descoped.secrets.provider.google`; only the initializer is public
- Depends on: [secrets-client-api](../api.md), google-auth, Jackson 3 `jackson-core`

## Configuration

Key | Description
---|---
`secrets.provider` | `google-secret-manager` (required)
`secrets.project-id` | the Google Cloud project id or number (required)
`secrets.service-account-key-path` | a service-account JSON key file; without it, Application Default Credentials are used
`secrets.replication-locations` | comma-separated locations, such as `europe-north1,europe-west1`, for secrets that `addVersion` creates (user-managed replication); automatic replication when absent
`secrets.endpoint` | the API endpoint, default `https://secretmanager.googleapis.com`; another host serving the same global API, such as a Private Service Connect endpoint or a test server. https only; plain http only for a loopback address
`secrets.connect-timeout` | ISO-8601 duration, default `PT10S`
`secrets.request-timeout` | ISO-8601 duration, default `PT30S`
`secrets.memory.guard`, `secrets.memory.lock` | the guarded memory that `read` returns secrets in, created by the first `read`; see [the API](../api.md#guarded-memory-secretmemory-and-secret)

`read` needs native access (`--enable-native-access=io.descoped.secrets.api`, `ALL-UNNAMED` on the class path) or
`secrets.memory.guard=off` (tests only). For now it reads the value as `readBytes` does and copies it into guarded
memory, so the value is on the heap on the way; the other methods need no native access.

```java
SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "google-secret-manager",
        "secrets.project-id", "my-project"));
```

## Credentials

Without `secrets.service-account-key-path`, the client uses
[Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials), in
this order: `GOOGLE_APPLICATION_CREDENTIALS`, the gcloud login (`gcloud auth application-default login`), and the
metadata server (Workload Identity on GKE, the attached service account on Cloud Run and Compute Engine). This is
what to use everywhere you can; **do not ship key files to a cluster.**

`secrets.service-account-key-path` must be a service-account key (`"type": "service_account"`). Other credential files,
such as `external_account` configurations, are refused: they can run programs or fetch URLs, which a file documented
as a key should not be able to do.

The access token is taken from the credentials on every request, so google-auth refreshes it before it expires.

## Permissions

The identity needs, on the project or on each secret:

Operation | Permission | Predefined role
---|---|---
`readBytes`, `readChars`, `readString` | `secretmanager.versions.access` | `roles/secretmanager.secretAccessor`
`addVersion` on an existing secret | `secretmanager.versions.add` | `roles/secretmanager.secretVersionAdder`
`addVersion` on a new secret (creates it, then adds the version) | `secretmanager.secrets.create` and `secretmanager.versions.add` | `roles/secretmanager.admin`

A missing permission is a `SecretManagerException` naming `PERMISSION_DENIED`.

## Behaviour

- Versions are Secret Manager's: `latest` or a version number. `addVersion` returns the new number.
- `addVersion` on a secret that does not exist creates it, with the configured replication, and then adds the
  version. A secret created at the same moment by someone else is accepted.
- Secret names follow Secret Manager's rule: 1 to 255 letters, digits, `-` and `_`. Reading another name, or a version
  that is neither `latest` nor a number, is `SecretNotFoundException`; `addVersion` with another name is a
  `SecretManagerException`. Neither sends a request.
- Secrets are global resources (`projects/<project>/secrets/<name>`), replicated as configured. Regional secrets
  (`projects/<project>/locations/<location>/secrets/<name>`, served by the regional endpoints) are not supported.
- Values travel as bytes with a CRC32C checksum, both ways. A response whose checksum does not match is an error.

Response | Result
---|---
`404 NOT_FOUND` when reading | `SecretNotFoundException`
`400 FAILED_PRECONDITION` (a disabled or destroyed version) | `SecretManagerException`: the version exists, so it is not "not found"
any other error status | `SecretManagerException` with the HTTP status and Google's error status and message
a malformed response | `SecretManagerException`

Error messages never contain the response body or the value.

## Runtime dependencies and JPMS

google-auth and google-http-client are not named modules, so on the module path they and their dependencies load as
automatic modules (`com.google.auth`, `com.google.auth.oauth2`, `com.google.api.client`, and so on). This means:

- Applications using this provider cannot be linked with `jlink`, which accepts named modules only.
- Apache HttpClient 4, httpcore, commons-codec and an empty `listenablefuture` jar are excluded: nothing in google-auth
  or google-http-client 2.x uses them. If a dependency of your own brings them back, they are harmless.

## Testing

The tests run against `FakeGoogle`, a local server that implements the Secret Manager REST calls this provider makes
and issues OAuth tokens for a generated service-account key. They cover reads, versions, not-found, errors,
create-on-write, replication, token refresh, malformed responses, timeouts, endpoint and credential checks.

`GoogleSecretManagerLiveTest` runs against a real project when `SECRETS_GOOGLE_TEST_PROJECT` is set (with
`SECRETS_GOOGLE_TEST_KEY_PATH` for a key file instead of Application Default Credentials). It is not run in CI.
Verification against real Google Cloud is tracked in
[issue #15](https://github.com/descoped/secrets-client-project/issues/15).
