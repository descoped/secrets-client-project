# Provider: google-secret-manager

[Google Secret Manager](https://cloud.google.com/secret-manager), read and write, through its REST API. The provider
for production. It has its own small HTTP/1.1 client, JSON reader and Base64 codec, all working on guarded memory:
values, the access token and the refresh token are never on the Java heap, from the network or the file to the
caller. No gRPC, no Google Cloud client library, no google-auth, no Jackson.

- Maven: `io.descoped.secrets:secrets-provider-google-secret-manager`, scope `runtime`
- Provider name: `google-secret-manager`
- JPMS module: `io.descoped.secrets.provider.google`; only the initializer is public
- Depends on: [secrets-client-api](../api.md) only
- Needs native access: `--enable-native-access=io.descoped.secrets.api` (`ALL-UNNAMED` on the class path)

## Configuration

Key | Description
---|---
`secrets.provider` | `google-secret-manager` (required)
`secrets.project-id` | the Google Cloud project id or number (required)
`secrets.credentials` | `application-default` (the default) or `metadata`; see [Credentials](#credentials)
`secrets.credentials-path` | an `authorized_user` credentials file, as `gcloud auth application-default login` writes it
`secrets.replication-locations` | comma-separated locations, such as `europe-north1,europe-west1`, for secrets that `addVersion` creates (user-managed replication); automatic replication when absent
`secrets.endpoint` | the API endpoint, default `https://secretmanager.googleapis.com`; another host serving the same global API, such as a Private Service Connect endpoint or a test server. https only; plain http only for a loopback address
`secrets.token-endpoint` | the OAuth token endpoint for `authorized_user` credentials, default `https://oauth2.googleapis.com/token`; https, plain http only for a loopback address
`secrets.metadata-endpoint` | the metadata server, default `http://metadata.google.internal`; `metadata.google.internal`, `169.254.169.254` or a loopback address
`secrets.connect-timeout` | ISO-8601 duration, default `PT10S`
`secrets.request-timeout` | ISO-8601 duration for a whole request, default `PT30S`
`secrets.tls.ca-file` | a PEM file of the only certificates to trust, such as a private CA; the system's trusted certificates when absent
`secrets.memory.guard`, `secrets.memory.lock` | the guarded memory; see [the API](../api.md#guarded-memory-secretmemory-and-secret)

```java
SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "google-secret-manager",
        "secrets.project-id", "my-project"));
```

## Credentials

With `secrets.credentials=application-default` (the default), the client looks for credentials the way
[Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials) do:

1. the file in `secrets.credentials-path`;
2. the file `GOOGLE_APPLICATION_CREDENTIALS` names;
3. the file `gcloud auth application-default login` writes (`$CLOUDSDK_CONFIG` or `~/.config/gcloud`,
   `application_default_credentials.json`), if it exists;
4. the metadata server: Workload Identity on GKE, the attached service account on Cloud Run and Compute Engine.

With `secrets.credentials=metadata`, only the metadata server is used: set it in production on Google Cloud, so that
no file on the machine is ever considered.

A credentials file must be of type `authorized_user`: a developer's own login, for local development. Its refresh
token is read with a `FileChannel` into guarded memory and exchanged for an access token at Google's OAuth endpoint.
**Service-account keys (`service_account`) and the other credential types are refused**: signing a token request with
a private key would put the key on the Java heap, since the JDK signs only with keys on the heap. Do not use keys
anyway; on Google Cloud, the metadata server gives the token of the attached service account.

The access token is fetched on the first request, held in guarded memory, and replaced when it has less than three
minutes left. The `secrets.service-account-key-path` key of 3.x is refused with a message.

## Permissions

The identity needs, on the project or on each secret:

Operation | Permission | Predefined role
---|---|---
`read` | `secretmanager.versions.access` | `roles/secretmanager.secretAccessor`
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
- Values travel with a CRC32C checksum, both ways. A response whose checksum does not match is an error.
- One connection per request (`Connection: close`). Responses are read up to 4 MiB; a value is at most 64 KiB.

Response | Result
---|---
`404 NOT_FOUND` when reading | `SecretNotFoundException`
`400 FAILED_PRECONDITION` (a disabled or destroyed version) | `SecretManagerException`: the version exists, so it is not "not found"
any other error status | `SecretManagerException` with the HTTP status and Google's error status and message
a malformed response, a timeout, a failed connection or TLS handshake | `SecretManagerException`

Error messages never contain the response body or the value.

## Memory and TLS

Each request is built in guarded memory (the access token in the `Authorization` header, the value Base64-encoded in
the body) and written to the socket from there; each response is read into guarded memory, its JSON parsed in place
and the value decoded from Base64 straight into the `Secret` that `read` returns.

TLS goes through the system's OpenSSL 3 (`libssl`), called through the Foreign Function & Memory API, not through
the JDK's `SSLEngine`, whose TLS and cipher code copies plaintext through heap arrays. OpenSSL encrypts straight out
of the guarded request and decrypts straight into the guarded response, so the access token, the refresh token and
the values are never on the Java heap, over TLS too. The canary tests prove it over plain HTTP and over TLS.

- TLS 1.3 or 1.2, with AES-GCM or ChaCha20-Poly1305 and ECDHE only; no renegotiation, no compression.
- The server's certificate must chain to a trusted root and match the host name (or the IP address); SNI is sent
  for host names. The trusted roots are the system's (OpenSSL's default locations), or, with `secrets.tls.ca-file`,
  only the certificates in that PEM file. `javax.net.ssl.trustStore` does not apply.
- OpenSSL 3 must be installed: `libssl.so.3` on Linux (Debian and Ubuntu: the `libssl3` package, which minimal and
  distroless images may lack); on macOS, `brew install openssl@3`. Without it, a client with an https endpoint
  cannot be created, and the error says so.
- While a record is decrypted, its plaintext is in OpenSSL's own buffers: native memory, not the Java heap. OpenSSL
  clears it once it is handed over and when the connection is freed (`SSL_OP_CLEANSE_PLAINTEXT`).

## Testing

The tests run against `FakeGoogle`, a local server (http or https) that implements the Secret Manager REST calls this
provider makes, the OAuth refresh-token grant and the metadata server's token. They cover reads, versions,
not-found, errors, create-on-write, replication, token refresh, both credential sources, chunked and large responses,
JSON escapes, malformed responses, timeouts, and endpoint and credential checks. Over TLS (`GoogleSecretManagerTlsTest`):
reads and writes, a host name with SNI, and the refusal of a certificate for another name, for another IP address,
signed by no trusted root, or expired, each before a byte of the request is sent.
`GoogleSecretManagerCanaryTest` runs the canary gate: the canary is the refresh token, the access token and the value
at once, read and written back, and the child JVM's heap dump must not hold it, over plain HTTP and over TLS.

`GoogleSecretManagerLiveTest` runs against a real project when `SECRETS_GOOGLE_TEST_PROJECT` is set, with
`SECRETS_GOOGLE_TEST_CREDENTIALS_PATH` for an `authorized_user` file instead of Application Default Credentials, or
`SECRETS_GOOGLE_TEST_CREDENTIALS=metadata` for the metadata server only, on Google Cloud. It writes a text value and a
60 KiB binary value to the secret `secrets-client-live-test`, reads them back by version and as `Secret`, reads a
missing secret, and afterwards destroys all enabled versions but the newest two (active versions are billed). It is
not run in CI. It passes against Google with `authorized_user` credentials, and on Cloud Run (second-generation
execution environment) with the metadata server, guarded memory locked as by default
([issue #15](https://github.com/descoped/secrets-client-project/issues/15)). `MountedSecretLiveTest` compares
a secret that Cloud Run mounts as a file with the same secret read here; see [mounted](mounted.md#testing).
