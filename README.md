# Secrets Client

[![CI](https://github.com/descoped/secrets-client-project/actions/workflows/ci.yml/badge.svg)](https://github.com/descoped/secrets-client-project/actions/workflows/ci.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=descoped_secrets-client-project&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=descoped_secrets-client-project)

A Java library for reading and writing secrets through one API, with the backend chosen by configuration: a local
file, Google Secret Manager, AWS Secrets Manager, or secrets the platform mounts as files. Values, and the tokens and
keys that grant access to them, are held in guarded memory off the Java heap, over TLS too, wiped when no longer
needed, and never appear in exception messages. Every path is proven by heap-dump tests. Java 25 or later, on Linux
or macOS, on the module path or the class path.

**[Documentation](docs/README.md)**: getting started, the API, [the security model](docs/security.md), each
provider, and migrating from earlier versions.

Changes by version are in the [changelog](CHANGELOG.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## How it works

An application compiles against `secrets-client-api` and creates a client from a configuration map:

```java
try (SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "google-secret-manager",
        "secrets.project-id", "my-project"));
     Secret password = client.read("db-password")) {
    password.withChars(chars -> {                    // a heap copy, wiped when the call returns
        connect(chars);
        return null;
    });
}
```

`secrets.provider` names the provider, which is found with `ServiceLoader` among the provider modules on the module
path or class path. Every provider follows the same contract, so moving from a local file in development to Google
Secret Manager or AWS Secrets Manager in production is a configuration change. The JVM needs
`--enable-native-access=io.descoped.secrets.api` (`ALL-UNNAMED` on the class path) for guarded memory, and the
network providers need the system's OpenSSL 3.

## Working with the code

One Maven reactor; every module shares the version of the root POM.

```
secrets-client-api/                        the API and the provider service
secrets-provider-safe-configuration/       provider: a local key=value file, for development and tests
secrets-provider-google-secret-manager/    provider: Google Secret Manager (REST, no dependency but the API)
secrets-provider-mounted/                  provider: secrets the platform mounts as files, read-only
secrets-provider-aws-secrets-manager/      provider: AWS Secrets Manager (JSON API with SigV4, no dependency but the API)
secrets-client-bom/                        BOM of the modules above
secrets-test-support/                      test support: the canary heap-dump harness (never published)
src/it/consumer/                           JPMS smoke test: an application using every provider
docs/                                      user documentation
```

Requires JDK 25 or later; the Maven Wrapper brings Maven. The [`justfile`](justfile) holds the regular tasks
([just](https://just.systems)); `just` lists them:

```sh
just build                       # compile with -Xlint:all -Werror, run the tests (JUnit 6)
just check                       # what CI checks: build, Javadoc with doclint, the JPMS smoke test
just test <module> [pattern]     # one module, optionally some tests
just coverage [module]           # JaCoCo report per module in <module>/target/site/jacoco
just linux                       # the tests on Linux in Docker, where memfd_secret is in use
```

Without just, the same with Maven: `./mvnw verify`, `./mvnw verify javadoc:javadoc`, `src/it/consumer/run.sh`,
`./mvnw verify -P coverage`.

- Each module's tests are a separate named module (`src/test/java/module-info.java`) and reach the providers only
  through `SecretManagerClient.create`, as an application does.
- Every path that reads or writes a secret has a canary test: a child JVM handles a random canary through that
  path and dumps its heap, which must hold no copy of it in any encoding.
- The Google provider's tests run against `FakeGoogle`, and the AWS provider's against `FakeAws`, local fakes of the
  APIs and of the credential endpoints. The live tests (`just live-google`, `just live-aws`) run against real
  accounts only when their variables are set, never in CI.
- Pull requests run CI (build, tests, Javadoc, smoke test) and an automated review; SonarCloud analyses pushes and
  pull requests from this repository, without gating the build. Releases are
  published to Maven Central by hand ([releasing](docs/releasing.md)). SNAPSHOTs of `master`, and of a branch when run by hand
  (`X.Y.Z-<branch>-SNAPSHOT`), are published by CI to `https://maven.descoped.io/`, never to Maven Central (see [getting started](docs/getting-started.md)).

## License

[Apache License 2.0](LICENSE)
