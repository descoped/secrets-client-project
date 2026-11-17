# Secrets Client

[![CI](https://github.com/descoped/secrets-client-project/actions/workflows/ci.yml/badge.svg)](https://github.com/descoped/secrets-client-project/actions/workflows/ci.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=descoped_secrets-client-project&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=descoped_secrets-client-project)

[SecretManagerClient](secrets-client-api/src/main/java/io/descoped/secrets/api/SecretManagerClient.java) is a
provider based API for reading and writing secrets, with providers for a local file, dynamic-configuration and Google
Secret Manager. Java 17 or later, on the module path or the class path.

Module | JPMS module | What it is
---|---|---
`secrets-client-api` | `io.descoped.secrets.api` | the API; compile against this
`secrets-provider-safe-configuration` | `io.descoped.secrets.provider.safe` | secrets in a local file, held as bytes
`secrets-provider-dynamic-configuration` | `io.descoped.secrets.provider.dynamic` | read-only, for tests and migration
`secrets-provider-google-secret-manager` | `io.descoped.secrets.provider.google` | Google Secret Manager
`secrets-client-bom` | | aligns the versions of the modules above

## Dependencies

All modules share one version. Import the BOM, compile against the API and add the providers you use at runtime:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>io.descoped.secrets</groupId>
            <artifactId>secrets-client-bom</artifactId>
            <version>3.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>io.descoped.secrets</groupId>
        <artifactId>secrets-client-api</artifactId>
    </dependency>
    <dependency>
        <groupId>io.descoped.secrets</groupId>
        <artifactId>secrets-provider-safe-configuration</artifactId>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.descoped.secrets</groupId>
        <artifactId>secrets-provider-google-secret-manager</artifactId>
        <scope>runtime</scope>
    </dependency>
</dependencies>
```

3.0.0 is not released yet. Until then, `3.0.0-SNAPSHOT` is published from `master` to the Central Portal snapshot
repository, `https://central.sonatype.com/repository/maven-snapshots/`.

An application module `requires io.descoped.secrets.api` only. Provider modules on the module path are found without
being required: the API module declares `uses` for the provider service.

## API

```java
interface SecretManagerClient extends AutoCloseable {

    byte[] readBytes(String secretName);                        // latest version
    byte[] readBytes(String secretName, String secretVersion);  // null version = latest
    char[] readChars(String secretName);                        // UTF-8, intermediate bytes wiped
    char[] readChars(String secretName, String secretVersion);
    String readString(String secretName);                       // a String cannot be wiped
    String readString(String secretName, String secretVersion);

    String addVersion(String secretName, byte[] secretValue);   // returns the new version id
    String addVersion(String secretName, char[] secretValue);
    String addVersion(String secretName, String secretValue);

    void close();                                               // idempotent, wipes what the client holds

    static SecretManagerClient create(Map<String, String> configuration);  // provider named by "secrets.provider"
}
```

Every provider follows the same contract:

- A secret or version that does not exist throws `SecretNotFoundException`; any other failure throws
  `SecretManagerException`. Messages name the secret, never its value.
- `readBytes` and `readChars` return new arrays that the caller owns and should wipe after use. The client never keeps
  a reference to them, nor to an array passed to `addVersion`.
- A read-only provider throws `UnsupportedOperationException` from `addVersion`.
- After `close()`, every other method throws `IllegalStateException`.

The JPMS module is `io.descoped.secrets.api`. It declares `uses` for the provider service, so provider modules on the
module path are found without the application requiring them.

## Supported providers

### Dynamic configuration

**For tests and migration only:** values are held as strings, which cannot be wiped. Read-only secrets from
[dynamic-configuration](https://github.com/descoped/dynamic-configuration). JPMS module
`io.descoped.secrets.provider.dynamic`.

Property                        | Description
--------------------------------|----------------------------------------------
secrets.provider                | dynamic-configuration (required)
secrets.property-resource-path  | a properties file, which must exist
secrets.directory               | a directory of secret files, one file per secret (Kubernetes secret volumes, Docker secrets), which must exist
secrets.values.&lt;name&gt;     | a secret given inline, for tests

At least one source is required. They are layered in that order, a later one overriding an earlier one. The
properties file follows dynamic-configuration's rules: `java.util.Properties` escapes, and `${key}` references between
values (`$${` for a literal `${`). Values from the directory are taken literally, except that one trailing LF or CRLF
is removed; hidden entries, such as Kubernetes' `..data`, are skipped. The sources are read once, when the client is
created. The only version is `latest`; `addVersion` throws `UnsupportedOperationException`.

### Safe configuration

Secrets in a local file, held in memory as bytes and wiped on `close()`. JPMS module
`io.descoped.secrets.provider.safe`.

Property                        | Description
--------------------------------|----------------------------------------------
secrets.provider                | safe-configuration (required)
secrets.property-resource-path  | path of the secrets file (required)

File format:

- UTF-8 (a leading byte-order mark is skipped), lines end with LF or CRLF.
- One `key=value` per line. The first `=` separates key and value; blanks (space, tab, form feed, vertical tab)
  around the key are removed, the value is taken byte for byte, including surrounding blanks and further `=`. There
  are no escapes, so a value cannot contain a line break.
- Empty lines, lines of blanks and lines whose first non-blank character is `#` are ignored.
- A line without `=`, an empty key and a duplicate key are errors, reported with the line number (never the value).
- This is not the `java.util.Properties` format: `\`, `:` and `!` have no special meaning.

The file is read once, when the client is created. The only version is `latest`. `addVersion` replaces the key's line
in place, or appends one, and keeps every other line, comment and line ending. The file (the target of a symbolic
link) is replaced atomically by a new file, owned by the writing user and readable and writable by that user only
(on file systems with POSIX permissions). **A file that a group or others could read is not readable by them after a
write.** An unwritable file, a file system that cannot move atomically, a name the format cannot hold and a value with
a line break are `SecretManagerException`s.

### Google Secret Manager

[Google Secret Manager](https://cloud.google.com/secret-manager) through its REST API, authenticated with
google-auth. JPMS module `io.descoped.secrets.provider.google`.

Property                         | Description
---------------------------------|----------------------------------------------
secrets.provider                 | google-secret-manager (required)
secrets.project-id               | the Google Cloud project id or number (required)
secrets.service-account-key-path | a service-account JSON key file. Without it, Application Default Credentials are used: Workload Identity, the metadata server, `GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login`. **Do not use key files on a cluster.**
secrets.replication-locations    | comma-separated locations, such as `europe-north1`, for secrets that `addVersion` creates (user-managed replication); automatic replication when absent
secrets.endpoint                 | the API endpoint, default `https://secretmanager.googleapis.com` (for example a regional endpoint); https only, plain http only for a loopback address
secrets.connect-timeout          | ISO-8601 duration, default `PT10S`
secrets.request-timeout          | ISO-8601 duration, default `PT30S`

- The access token is taken from the credentials on every request, so google-auth refreshes it before it expires.
- Versions are Secret Manager's: `latest` or a version number. `addVersion` returns the new number, and creates the
  secret first if it does not exist.
- Secret names follow Secret Manager's rule (1 to 255 letters, digits, `-` and `_`). Reading another name or an
  invalid version is `SecretNotFoundException`, `addVersion` with another name a `SecretManagerException`; neither
  sends a request.
- A disabled or destroyed version exists, so reading it is a `SecretManagerException` (`FAILED_PRECONDITION`), not
  `SecretNotFoundException`.
- `secrets.service-account-key-path` must be a service-account key; other credential files (such as
  `external_account`) are refused.
- Values travel as bytes with a CRC32C checksum both ways, and a mismatch is an error.
- Error messages carry the HTTP status and Google's error status and message, never the response body.

## Example

```java
Map<String, String> configuration = Map.of(
        "secrets.provider", "google-secret-manager",
        "secrets.project-id", "my-project");   // Application Default Credentials

try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
    char[] password = client.readChars("db-password");
    try {
        connect(password);
    } finally {
        Arrays.fill(password, '\0');
    }
}
```

The provider tests run against a local fake of Google. A live test,
[GoogleSecretManagerLiveTest](secrets-provider-google-secret-manager/src/test/java/io/descoped/secrets/provider/google/test/GoogleSecretManagerLiveTest.java),
runs when `SECRETS_GOOGLE_TEST_PROJECT` names a project.

## Migrating from 2.x

3.0.0 is a breaking release. The Maven coordinates are unchanged.

What changed | 2.x | 3.0
---|---|---
Java | 11 | 17
API module | `io.descoped.secrets.client.api` | `io.descoped.secrets.api` (package unchanged)
safe-configuration | package `io.descoped.secrets.secure.configuration` | module and package `io.descoped.secrets.provider.safe`
dynamic-configuration | provider `dynamic-secret-configuration`, package `io.descoped.secrets.dynamic.configuration` | provider `dynamic-configuration`, module and package `io.descoped.secrets.provider.dynamic`
google-secret-manager | module `io.descoped.secrets.provider.google.rest.api`, package `...google.secretmanager.restapi` | module and package `io.descoped.secrets.provider.google`
Missing secret or version | `null` (safe, dynamic) or `RuntimeException` (Google) | `SecretNotFoundException`
Other failures | `RuntimeException` | `SecretManagerException`
Returned arrays | safe-configuration returned its own array | always a new array the caller owns
`safeCharArrayAsUTF8(bytes)` | static helper | `readChars(name)`
dynamic-configuration | read and write, Base64 in the file | read-only; file, secret directory or inline values
dynamic-configuration library | 2.x | 3.x
Google credentials | Compute Engine or a key file | Application Default Credentials or a key file
Google replication of new secrets | `europe-north1` | automatic, or `secrets.replication-locations`
Provider implementation classes | public | package-private; only the initializers are public
`service-provider-api` | 2.x | 3.x (`providerId()` is gone; the `@ProviderName` annotation names a provider)

safe-configuration files written by 2.x `addVersion` went through `java.util.Properties.store`, which escapes `=`,
`:`, `#` and `!` (for example `https\://host`). 3.0 reads values verbatim, so remove those backslashes once.

## Building

```sh
./mvnw verify                    # compile with -Xlint:all -Werror, tests (JUnit 6)
./mvnw verify javadoc:javadoc    # plus Javadoc with doclint, warnings fail the build
src/it/consumer/run.sh           # JPMS smoke test: an application module on the module path and the class path
```
