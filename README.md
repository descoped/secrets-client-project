# Secret Manager Client

[SecretManagerClient](secrets-client-api/src/main/java/io/descoped/secrets/api/SecretManagerClient.java)
is a provider based API for reading secrets.

## Dependencies

Add `secrets-client-api` as a compile time dependency and choose the provider(s) you want to use.

```xml
<dependency>
    <groupId>io.descoped.secrets</groupId>
    <artifactId>secrets-client-api</artifactId>
    <version>2.0.0</version>
</dependency>

<dependency>
<groupId>io.descoped.secrets</groupId>
<artifactId>secrets-provider-safe-configuration</artifactId>
<version>2.0.0</version>
    <scope>runtime</scope>
</dependency>

<dependency>
<groupId>io.descoped.secrets</groupId>
<artifactId>secrets-provider-google-secret-manager</artifactId>
<version>2.0.0</version>
    <scope>runtime</scope>
</dependency>

<!-- dynamic-configuration holds values as strings: for tests and migration only -->
<dependency>
<groupId>io.descoped.secrets</groupId>
<artifactId>secrets-provider-dynamic-configuration</artifactId>
<version>2.0.0</version>
    <scope>runtime</scope>
</dependency>
```

From 3.0.0, all modules share one version, and `secrets-client-bom` aligns them:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>io.descoped.secrets</groupId>
            <artifactId>secrets-client-bom</artifactId>
            <version>${secrets-client.version}</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

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
secrets.endpoint                 | the API endpoint, default `https://secretmanager.googleapis.com` (for example a regional endpoint)
secrets.connect-timeout          | ISO-8601 duration, default `PT10S`
secrets.request-timeout          | ISO-8601 duration, default `PT30S`

- The access token is taken from the credentials on every request, so google-auth refreshes it before it expires.
- Versions are Secret Manager's: `latest` or a version number. `addVersion` returns the new number, and creates the
  secret first if it does not exist.
- Secret names must follow Secret Manager's rule (1 to 255 letters, digits, `-` and `_`); other names are rejected
  before any request.
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
