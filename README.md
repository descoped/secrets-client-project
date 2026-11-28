# Secrets Client

[![CI](https://github.com/descoped/secrets-client-project/actions/workflows/ci.yml/badge.svg)](https://github.com/descoped/secrets-client-project/actions/workflows/ci.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=descoped_secrets-client-project&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=descoped_secrets-client-project)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Secrets that never touch the Java heap. One API reads and writes secrets in Google Secret Manager, AWS Secrets
Manager, files the platform mounts, or a local file. Values and the credentials that grant access to them are held in
guarded native memory, sent over TLS through the system's OpenSSL, and wiped when you are done.

- **One API, any backend.** The provider is chosen by configuration; the same code runs on a laptop and in production.
- **Off the heap.** Guarded pages, closed outside a callback, never swapped, and on Linux out of core dumps.
- **No third-party dependencies.** No cloud SDK, gRPC, Netty or Jackson; the network stack is the library's own.
- **Proven.** Every read, write and credential path has a test that dumps the heap and finds no copy of the secret.

**Documentation: [ssc.descoped.io](https://ssc.descoped.io)** (also in [docs/](docs/README.md)).

## Requirements

- Java 25 or later, on Linux or macOS (x86_64 or aarch64)
- The JVM flag `--enable-native-access=io.descoped.secrets.api` (`ALL-UNNAMED` on the class path)
- OpenSSL 3 for the Google and AWS providers (`libssl3` on Debian and Ubuntu, `brew install openssl@3` on macOS)

## Getting started

Add the API, and the provider you use at runtime:

```xml
<dependency>
    <groupId>io.descoped.secrets</groupId>
    <artifactId>secrets-client-api</artifactId>
    <version>4.0.0-SNAPSHOT</version>
</dependency>
<dependency>
    <groupId>io.descoped.secrets</groupId>
    <artifactId>secrets-provider-google-secret-manager</artifactId>
    <version>4.0.0-SNAPSHOT</version>
    <scope>runtime</scope>
</dependency>
```

Releases are on Maven Central; 3.0.0 there has the earlier API. 4.0 is published as `4.0.0-SNAPSHOT`.
SNAPSHOTs are never on Maven Central. CI publishes them to `https://maven.descoped.io/`: `X.Y.Z-SNAPSHOT` from
`master`, and `X.Y.Z-<branch>-SNAPSHOT` from a branch when run by hand. To use one, add the repository:

```xml
<repository>
    <id>descoped-snapshots-public</id>
    <url>https://maven.descoped.io/</url>
    <releases><enabled>false</enabled></releases>
    <snapshots><enabled>true</enabled></snapshots>
</repository>
```

Keep the id `descoped-snapshots-public`, and depend on `X.Y.Z-SNAPSHOT`, never on a timestamped build;
[Getting started](docs/getting-started.md) says why, and has the BOM, which aligns the versions of every module.

Read a secret:

```java
try (SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "google-secret-manager",
        "secrets.project-id", "my-project"));
     Secret password = client.read("db-password")) {
    password.withChars(chars -> {                    // a heap copy, zeroed when the call returns
        connect(chars);
        return null;
    });
}
```

Run with native access:

```sh
java --enable-native-access=io.descoped.secrets.api -m my.app/my.app.Main
```

## Providers

| Provider | `secrets.provider` | Reads | Writes |
|---|---|---|---|
| [Google Secret Manager](docs/providers/google-secret-manager.md) | `google-secret-manager` | yes | yes |
| [AWS Secrets Manager](docs/providers/aws-secrets-manager.md) | `aws-secrets-manager` | yes | yes |
| [Mounted files](docs/providers/mounted.md) (Kubernetes, Cloud Run) | `mounted` | yes | no |
| [Local file](docs/providers/safe-configuration.md) (development and tests) | `safe-configuration` | yes | yes |

## Build and test

Requires JDK 25; the Maven Wrapper brings Maven. The [`justfile`](justfile) holds the regular tasks
([just](https://just.systems)):

```sh
just build                       # compile with -Xlint:all -Werror, run every test
just check                       # what CI runs: build, Javadoc, the JPMS smoke test
just test <module> [pattern]     # one module, optionally some tests
just linux                       # the tests on Linux in Docker, where memfd_secret is in use
just coverage [module]           # JaCoCo reports
```

Without just: `./mvnw verify`, `./mvnw verify javadoc:javadoc`, `src/it/consumer/run.sh`.

The Google and AWS providers are tested against local fakes of their APIs and credential endpoints. The live tests
run against real accounts only when their variables are set: `just live-google`, `just live-aws`.

## Project layout

```
secrets-client-api/                       the API, guarded memory, and the network stack
secrets-provider-google-secret-manager/   Google Secret Manager
secrets-provider-aws-secrets-manager/     AWS Secrets Manager
secrets-provider-mounted/                 mounted files, read-only
secrets-provider-safe-configuration/      a local key=value file
secrets-client-bom/                       the BOM
secrets-test-support/                     the heap-dump test harness (not published)
src/it/consumer/                          JPMS smoke test
docs/                                     documentation, published at ssc.descoped.io
site/                                     the documentation site
```

## Contributing

Pull requests run CI and an automated review. [CHANGELOG.md](CHANGELOG.md) lists the changes by version, and
[RELEASING.md](RELEASING.md) describes how a version is released.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). What the library protects, and where that ends, is in
[the security model](docs/security.md).

## License

[Apache License 2.0](LICENSE)
