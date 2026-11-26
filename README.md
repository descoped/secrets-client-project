# Secrets Client

[![CI](https://github.com/descoped/secrets-client-project/actions/workflows/ci.yml/badge.svg)](https://github.com/descoped/secrets-client-project/actions/workflows/ci.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=descoped_secrets-client-project&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=descoped_secrets-client-project)

A Java library for reading and writing secrets through one API, with the backend chosen by configuration: a local
file, dynamic-configuration, or Google Secret Manager. Values are handled as bytes and wiped when no longer needed,
and never appear in exception messages. Java 25 or later, on the module path or the class path.

**[Documentation](docs/README.md)**: getting started, the API, each provider, and migrating from 2.x.

Changes by version are in the [changelog](CHANGELOG.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## How it works

An application compiles against `secrets-client-api` and creates a client from a configuration map:

```java
try (SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "google-secret-manager",
        "secrets.project-id", "my-project"))) {
    char[] password = client.readChars("db-password");
    // use it, then wipe it: Arrays.fill(password, '\0')
}
```

`secrets.provider` names the provider, which is found with `ServiceLoader` among the provider modules on the module
path or class path. Every provider follows the same contract, so moving from a local file in development to Google
Secret Manager in production is a configuration change.

## Working with the code

One Maven reactor; every module shares the version of the root POM.

```
secrets-client-api/                        the API and the provider service
secrets-provider-safe-configuration/       provider: a local key=value file
secrets-provider-dynamic-configuration/    provider: dynamic-configuration, read-only
secrets-provider-google-secret-manager/    provider: Google Secret Manager (REST, google-auth)
secrets-client-bom/                        BOM of the modules above
secrets-test-support/                      test support: the canary heap-dump harness (never published)
src/it/consumer/                           JPMS smoke test: an application using every provider
docs/                                      user documentation
```

Requires JDK 25 or later; the Maven Wrapper brings Maven.

```sh
./mvnw verify                    # compile with -Xlint:all -Werror, run the tests (JUnit 6)
./mvnw verify javadoc:javadoc    # plus Javadoc with doclint; warnings fail the build
src/it/consumer/run.sh           # JPMS smoke test on the module path and the class path
./mvnw verify -P coverage        # JaCoCo report per module in <module>/target/site/jacoco
```

- Each module's tests are a separate named module (`src/test/java/module-info.java`) and reach the providers only
  through `SecretManagerClient.create`, as an application does.
- The Google provider's tests run against `FakeGoogle`, a local fake of the Secret Manager API and Google's token
  endpoint. `GoogleSecretManagerLiveTest` runs against a real project only when `SECRETS_GOOGLE_TEST_PROJECT` is set.
- Pull requests run CI (build, tests, Javadoc, smoke test, SonarCloud) and an automated review. Releases are
  published to Maven Central by hand. SNAPSHOTs of `master`, and of a branch when run by hand
  (`X.Y.Z-<branch>-SNAPSHOT`), are published by CI to `https://maven.descoped.io/`, never to Maven Central (see [getting started](docs/getting-started.md)).

## License

[Apache License 2.0](LICENSE)
