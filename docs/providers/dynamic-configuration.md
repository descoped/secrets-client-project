# Provider: dynamic-configuration

Read-only secrets from [dynamic-configuration](https://github.com/descoped/dynamic-configuration): a properties file,
a directory of secret files, or values given inline.

**For tests and migration.** dynamic-configuration holds values as `String`s, which cannot be wiped from memory. For
production secrets, use [safe-configuration](safe-configuration.md) or
[Google Secret Manager](google-secret-manager.md).

- Maven: `io.descoped.secrets:secrets-provider-dynamic-configuration`, scope `runtime` (or `test`)
- Provider name: `dynamic-configuration`
- JPMS module: `io.descoped.secrets.provider.dynamic`; only the initializer is public
- Depends on: [secrets-client-api](../api.md), dynamic-configuration 3.x

## Configuration

Key | Description
---|---
`secrets.provider` | `dynamic-configuration` (required)
`secrets.property-resource-path` | a properties file; it must exist
`secrets.directory` | a directory of secret files, one file per secret; it must exist
`secrets.values.<name>` | the secret `<name>`, given inline
`secrets.memory.guard`, `secrets.memory.lock` | the guarded memory that `read` returns secrets in, created by the first `read`; see [the API](../api.md#guarded-memory-secretmemory-and-secret)

At least one source is required. They are layered in the order of the table: a secret in the directory overrides the
same name in the file, and an inline value overrides both. All sources are read once, when the client is created.

`read` needs native access (`--enable-native-access=io.descoped.secrets.api`, `ALL-UNNAMED` on the class path) or
`secrets.memory.guard=off` (tests only). The values are strings in dynamic-configuration, so they are on the heap
whatever `read` does.

## Sources

**Properties file.** dynamic-configuration's rules apply: `java.util.Properties` syntax and escapes, and `${key}`
references between values (`$${` for a literal `${`). A reference to a key that does not exist is an error when the
client is created; the error never contains the value.

**Directory of secret files.** The file name is the secret name and the content is the value, taken literally except
that one trailing LF or CRLF is removed. Hidden entries (names starting with `.`) are skipped. This is the layout of a
Kubernetes secret volume (where `..data` and the timestamped directories are hidden) and of Docker secrets:

```java
SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "dynamic-configuration",
        "secrets.directory", "/run/secrets"));          // /run/secrets/db-password -> "db-password"
```

**Inline values.** Handy in tests:

```java
SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "dynamic-configuration",
        "secrets.values.db-password", "test-password"));
```

## Behaviour

- The only version is `latest`; any other version, and a name no source has, is `SecretNotFoundException`.
- `addVersion` throws `UnsupportedOperationException`: this provider is read-only.
- A missing file or directory, and a properties file that cannot be read or resolved, are `SecretManagerException`s
  when the client is created.
