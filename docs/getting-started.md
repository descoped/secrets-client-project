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

3.0.0 is not released yet. Until then, `3.0.0-SNAPSHOT` is published from `master` to the Central Portal snapshot
repository, `https://central.sonatype.com/repository/maven-snapshots/`.

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

try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
    char[] password = client.readChars("db-password");
    try {
        connect(password);
    } finally {
        Arrays.fill(password, '\0');
    }
}
```

On the module path, the application module `requires io.descoped.secrets.api` only; provider modules are found
without being required. On the class path, providers are found through `META-INF/services`.

## Choosing a provider

Provider | Reads | Writes | Holds values as | Use it for
---|---|---|---|---
`safe-configuration` | a local `key=value` file | yes, atomically, owner-only | bytes, wiped | development, VMs, containers with a mounted secret file
`dynamic-configuration` | a properties file, a secret directory, inline values | no | strings | tests, migration from property files
`google-secret-manager` | Google Secret Manager | yes, creating secrets as needed | bytes, wiped | production on Google Cloud

Every provider follows the same contract, so switching is a configuration change; see
[The API](api.md#the-contract).
