# Changelog

All notable changes. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). All modules share one version.

## [Unreleased]

4.0 keeps secrets off the Java heap; it is built in steps, and this section grows with them.

### Changed

- Java 25 or later (was 17).

## [3.0.0] - 2026-11-17

A breaking release: the four module repositories are now one, and every module is revised. The Maven coordinates
are unchanged. See [Migrating from 2.x](docs/migrating-from-2.x.md).

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
