# Changelog

All notable changes. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). All modules share one version.

## [Unreleased]

4.0 keeps secrets off the Java heap; it is built in steps, and this section grows with them.

### Added

- `SecretMemory` and `Secret`: secret values in guarded off-heap memory (Foreign Function & Memory API), with guard
  pages, `mlock`, no access outside a callback, and on Linux no core dumps, nothing in a forked child, and
  `memfd_secret` memory (removed from the kernel's direct map) where the kernel offers it. Needs
  `--enable-native-access=io.descoped.secrets.api`. Configuration `secrets.memory.guard` and `secrets.memory.lock`.
- `SecretManagerClient.read(name)`/`read(name, version)` return a `Secret`, and `addVersion(name, Secret)` writes
  one. Closing the client closes the secrets it returned.
- safe-configuration reads, parses, holds and writes in guarded memory: no value is on the Java heap unless the caller
  makes a heap copy, proven by a canary heap-dump test.
- Google Secret Manager on guarded memory, with the library's own HTTP/1.1 client, JSON reader and Base64, and TLS through the
  system's OpenSSL 3 (FFM) instead of the JDK's `SSLEngine`, which copies plaintext through heap arrays: values, the
  access token and the refresh token are never on the Java heap, over TLS too (proven by canary tests over HTTP and
  TLS). TLS 1.3 or 1.2, AES-GCM or ChaCha20-Poly1305 with ECDHE, the certificate verified against the system's roots
  or `secrets.tls.ca-file`, and the host name or IP address. Needs OpenSSL 3 (`libssl.so.3`; `brew install
  openssl@3` on macOS); `javax.net.ssl.trustStore` does not apply. Credentials: an `authorized_user` file (`gcloud auth application-default
  login`), `GOOGLE_APPLICATION_CREDENTIALS`, gcloud's file, or the metadata server; `secrets.credentials=metadata`
  for the metadata server only. New keys `secrets.credentials`, `secrets.credentials-path`, `secrets.token-endpoint`,
  `secrets.metadata-endpoint`. Verified against real Google Cloud: with `authorized_user` credentials, and on Cloud
  Run (second-generation) with the metadata server and locked guarded memory.
- `SecretMemory.read(channel, maxLength)`: reads a channel to its end into guarded memory. On `memfd_secret` memory
  it goes through a small guarded buffer of ordinary pages. The kernel cannot pin `memfd_secret` pages, so a read from
  a FUSE or virtiofs file, such as Cloud Run's secret volumes, or with direct I/O failed with `EFAULT`. Every
  provider reads its files this way.
- Provider `mounted` (`secrets-provider-mounted`): read-only, for secrets the platform mounts as files (Cloud Run
  secret volumes, Kubernetes secret volumes, the Secrets Store CSI driver on GKE and EKS). Each `read` reads the file
  into guarded memory with a `FileChannel`, never cached, so rotated values are seen; no network code and no
  credential in the process. Names are paths under `secrets.mounted.directory`; links may not lead outside it.
  Proven by a canary heap-dump test, and verified on Cloud Run with a Secret Manager secret volume.
- Provider `aws-secrets-manager` (`secrets-provider-aws-secrets-manager`): AWS Secrets Manager through its JSON API,
  signed with SigV4, with no AWS SDK and no dependency but the API. The secret access key, the session token and the
  values stay in guarded memory: requests are built and signed there, with SHA-256 and HMAC-SHA256 through OpenSSL's
  libcrypto (the JDK's `Mac` copies its key to the heap), and TLS through OpenSSL. Reads by the current version,
  version ID or staging label; `addVersion` creates the secret if needed (`secrets.kms-key-id`,
  `secrets.replica-regions`). Credentials from the shared credentials file (`secrets.credentials-path`,
  `secrets.aws-profile`). Proven by canary heap-dump tests over http and TLS, against a fake that checks every
  signature.

### Changed

- Java 25 or later (was 17).
- `SecretManagerClient` reads and writes only `Secret`s: `read(name)`, `read(name, version)` and
  `addVersion(name, Secret)` are what is left besides `close()` and `create`. A provider implements `read(String,
  String)` and `addVersion(String, Secret)`. See [Migrating from 3.x](docs/migrating.md#migrating-from-3x-to-40).
- safe-configuration needs native access: `SecretManagerClient.create` fails without
  `--enable-native-access=io.descoped.secrets.api` (`ALL-UNNAMED` on the class path) unless
  `secrets.memory.guard=off`. Every provider needs it.
- safe-configuration is for local development and tests, not for production.
- Google Secret Manager: service-account keys are refused, and `secrets.service-account-key-path` is an error (signing
  with a key would put it on the Java heap); use the metadata server, or an `authorized_user` file for development.
  The provider needs native access to start.
- Google Secret Manager: `secrets.connect-timeout` and `secrets.request-timeout` include the host name lookup and are
  at most one hour.
- Closing a client inside a callback of a secret it returned throws `IllegalStateException`; a later `close()` wipes.

### Removed

- `readBytes`, `readChars`, `readString`, and `addVersion` with a `byte[]`, `char[]` or `String`: they put values on the
  Java heap. Use `read` with `Secret.withBytes`/`withChars`, and `SecretMemory.fromBytes`/`fromChars` to write.
- The dynamic-configuration provider (`secrets-provider-dynamic-configuration`): it held values as strings, which
  cannot be kept off the heap. Use safe-configuration for a local file, or `mounted` for a directory of secret files.
- google-auth (with google-http-client, Guava, Gson) and Jackson from the Google provider: it depends on the API
  module only.

## [3.0.0] - 2026-11-17

A breaking release: the four module repositories are now one, and every module is revised. The Maven coordinates
are unchanged. See [Migrating from 2.x](docs/migrating.md).

### Changed

- Java 17 or later (was 11). Every module is a named JPMS module with a new name, `io.descoped.secrets.api` and
  `io.descoped.secrets.provider.{safe,dynamic,google}`, and the provider packages are renamed to match.
- One contract for every provider: a missing secret or version is `SecretNotFoundException`, any other failure
  `SecretManagerException`, a read-only provider throws `UnsupportedOperationException` from `addVersion`, a closed
  client throws `IllegalStateException`. Messages never contain a value.
- Arrays returned by a client are new arrays the caller owns; arrays passed in are copied.
- `service-provider-api` 3.x: providers are named with `@ProviderName`.
- dynamic-configuration provider: renamed `dynamic-configuration` (was `dynamic-secret-configuration`), read-only, on
  dynamic-configuration 3.x, reading a properties file, a directory of secret files and inline values.
- Google provider: Application Default Credentials when `secrets.service-account-key-path` is not set (was Compute
  Engine only); the key file must be a service-account key, and other credential files (such as
  `external_account`) are refused. New secrets get automatic replication unless `secrets.replication-locations` is
  set (was always `europe-north1`). Jackson 3.
- Provider implementation classes are package-private; only the initializers are public.

### Added

- `secrets-client-bom`.
- `readChars`, decoding UTF-8 into an array that is wiped on every intermediate step; replaces
  `safeCharArrayAsUTF8`.
- Google provider: `secrets.endpoint`, `secrets.connect-timeout`, `secrets.request-timeout`,
  `secrets.replication-locations`; CRC32C checksums on values in both directions.
- Documentation in `docs/`.

### Fixed

- safe-configuration: `addVersion` rewrote the file with `java.util.Properties` escapes, corrupting every value that
  held `=`, `:`, `#`, `!` or non-Latin-1 characters on the next read. It now keeps the file's own format, replaces the
  file atomically, and makes it readable by its owner only.
- safe-configuration: returned its internal arrays, kept the caller's arrays, and was not thread-safe.
- dynamic-configuration: `addVersion` wrote Base64 to the file, which then read back as the Base64 text; without a
  file, the whole configuration (including `secrets.provider`) became readable as secrets.
- `readString` of a missing secret threw `NullPointerException`.
- `safeCharArrayAsUTF8` left the decoded value in an internal buffer.
- Google provider: the access token was never refreshed, so every call failed after about an hour; secret names went
  unvalidated into the request URL; there were no timeouts; error messages included the response body.
- A provider module on the module path was not found unless the application required it (the API module now
  declares `uses`).

### Removed

- Apache HttpClient 4, httpcore and commons-codec from the Google provider's dependencies (unused by google-auth).

[3.0.0]: https://github.com/descoped/secrets-client-project/compare/secrets-client-api/2.0.3...3.0.0
