# Getting started

## Dependencies

All modules share one version, aligned by the BOM `secrets-client-bom`. Import it, compile against the API, and add
the providers you use at runtime:

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
        <artifactId>secrets-provider-google-secret-manager</artifactId>
        <scope>runtime</scope>
    </dependency>
</dependencies>
```

Gradle: `implementation(platform("io.descoped.secrets:secrets-client-bom:3.0.0"))`, then the modules without a
version.

The BOM manages the secrets modules only. Third-party versions (google-auth, Jackson, dynamic-configuration) come
through the modules' own dependencies.

Releases are on Maven Central. **No SNAPSHOT goes to Maven Central.** SNAPSHOTs of `master`, and of a branch when
run by hand (`X.Y.Z-<branch>-SNAPSHOT`), are published by CI to `https://maven.descoped.io/` after a green build;
releases never go there. To use one:

```xml
<repository>
    <id>descoped-snapshots-public</id>
    <url>https://maven.descoped.io/</url>
    <releases><enabled>false</enabled></releases>
    <snapshots><enabled>true</enabled></snapshots>
</repository>
```

The id is `descoped-snapshots-public`, not `descoped-snapshots`: a server with that id holds the publishing token,
and Maven would send it to this URL. A SNAPSHOT keeps only its newest build for long; depend on `X.Y.Z-SNAPSHOT`,
never on a timestamped build.

## Modules

Artifact | JPMS module | Documentation
---|---|---
`secrets-client-api` | `io.descoped.secrets.api` | [The API](api.md)
`secrets-provider-safe-configuration` | `io.descoped.secrets.provider.safe` | [safe-configuration](providers/safe-configuration.md)
`secrets-provider-dynamic-configuration` | `io.descoped.secrets.provider.dynamic` | [dynamic-configuration](providers/dynamic-configuration.md)
`secrets-provider-google-secret-manager` | `io.descoped.secrets.provider.google` | [google-secret-manager](providers/google-secret-manager.md)
`secrets-client-bom` | | the BOM above

## A first client

```java
Map<String, String> configuration = Map.of(
        "secrets.provider", "google-secret-manager",
        "secrets.project-id", "my-project");          // Application Default Credentials

try (SecretManagerClient client = SecretManagerClient.create(configuration);
     Secret password = client.read("db-password")) {
    password.withChars(chars -> {
        connect(chars);
        return null;
    });
}
```

`read` keeps the value in guarded native memory, which needs native access: start the JVM with
`--enable-native-access=io.descoped.secrets.api` (`--enable-native-access=ALL-UNNAMED` on the class path). The
safe-configuration provider needs it to start at all. See [guarded memory](api.md#guarded-memory-secretmemory-and-secret).

On the module path, the application module `requires io.descoped.secrets.api` only; provider modules are found
without being required. On the class path, providers are found through `META-INF/services`.

## Choosing a provider

Provider | Reads | Writes | Holds values as | Use it for
---|---|---|---|---
`safe-configuration` | a local `key=value` file | yes, atomically, owner-only | guarded memory | local development and tests
`dynamic-configuration` | a properties file, a secret directory, inline values | no | strings | tests, migration from property files
`google-secret-manager` | Google Secret Manager | yes, creating secrets as needed | bytes, wiped | production on Google Cloud

Every provider follows the same contract, so switching is a configuration change; see
[The API](api.md#the-contract).
