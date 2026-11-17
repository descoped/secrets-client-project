# CLAUDE.md

Guidance for Claude Code in this repository.

## What this is

The Descoped secrets client: `SecretManagerClient`, a provider based API for reading and writing secrets, and its
providers. One Maven reactor, group `io.descoped.secrets`, owned by Descoped. `README.md` is the user documentation
and must stay true when behaviour changes.

| Module | JPMS module | Role |
|---|---|---|
| `secrets-client-project` (root) | n/a | parent and aggregator |
| `secrets-client-bom` | n/a | BOM of the modules below |
| `secrets-client-api` | `io.descoped.secrets.client.api` | `SecretManagerClient`, `SecretManagerClientInitializer` (the provider service, on `io.descoped.spi:service-provider-api`) |
| `secrets-provider-safe-configuration` | `io.descoped.secrets.provider.safe.configuration` | local `key=value` file, values as byte arrays |
| `secrets-provider-dynamic-configuration` | `io.descoped.secrets.provider.dynamic.configuration` | `io.descoped.config:dynamic-configuration`, for tests and migration |
| `secrets-provider-google-secret-manager` | `io.descoped.secrets.provider.google.rest.api` | Google Secret Manager REST API with google-auth |

Until 2026-11 every module was a repository of its own; their histories were imported here with `git filter-repo`
(old tags prefixed with the module name, e.g. `secrets-client-api/2.0.3`). The 3.0.0 revision is in progress: module
and package names, the API and the providers change in it.

## Invariants (never violate)

- **Java 17 baseline** (`maven.compiler.release` 17): every class file is Java 17 whatever JDK builds it. CI builds
  and tests on JDK 17 only (`ci.yml`). Nothing above Java 17 in main or test code.
- **One reactor, one version.** Every module inherits the root POM and is released with it; modules depend on each
  other with `${project.version}`. Dependency versions are properties in the root POM, not `dependencyManagement`, so
  the BOM manages the secrets modules only.
- **JPMS.** Every module is a named module. A module whose exported API exposes another module's types `requires
  transitive` it. Providers are registered both with `provides` in `module-info.java` and in `META-INF/services`, so
  they work on the module path and the class path.
- **Secrets stay secret.** Secret values are never logged, never put in exception messages, `toString` or test
  output. Byte and char arrays handed to or returned by a client are copies; the client wipes its own copies when it
  no longer needs them and on `close()`.
- **One contract for every provider.** A missing secret, a closed client and a write the provider cannot do are
  reported the same way by every provider.
- **Always the latest stable version** of every library, plugin and action. Pre-releases only on request. Old and
  outdated code and configuration is removed, not carried along.
- **Nothing is published to Maven Central until the 3.0.0 plan is complete** (owner's decision, 2026-11-17): the
  "Publish SNAPSHOT" step in `ci.yml` is `if: false`, and no deploy or release is run by hand. Do not turn it on
  without the owner's go-ahead.
- **Publishing**, once turned on. Merges to `master` publish SNAPSHOTs of every module to the Central Portal snapshot repository
  (`ci.yml`, step "Publish SNAPSHOT") with the secrets `CENTRAL_TOKEN_USER` / `CENTRAL_TOKEN_PASSWORD`; the step fails
  when they are missing. Releases go through the Central Portal (profiles `central,sign`), only with the owner's
  approval. CI never publishes a release. Maven 3.10 sends a server's credentials only to the hosts it knows for that
  id, and the id `central` is bound to Maven Central, so the server `central` must list `https://central.sonatype.com`
  in `repositoryOrigins`: in `.github/maven-settings.xml` for CI, and in `~/.m2/settings.xml` for deploys by hand.
- **SonarCloud**: one project, `descoped_secrets-client-project`, for the whole reactor.

## Testing

- JUnit 6. Tests must not touch fixed paths such as `/tmp/...`; use `@TempDir`.
- The Google Secret Manager tests that call Google need a service account and are not run in CI.
- The test sources still sit in the modules' own packages; the root POM relaxes `-Xlint:exports` and
  `missing-explicit-ctor` for test compilation only until they move to test modules of their own.

## Maven Wrapper

- `./mvnw` pins Maven (`.mvn/wrapper/maven-wrapper.properties`, type `only-script`, so no jar in the repository) and
  checks the download against `distributionSha256Sum`. CI runs `./mvnw`. When Maven is bumped, by Renovate or by hand,
  set `distributionSha256Sum` to the SHA-256 of the new `apache-maven-<version>-bin.zip`, after checking that zip
  against the `.sha512` Maven publishes next to it. A stale checksum fails the build, it never skips the check.

## Commands

```sh
./mvnw verify                    # compile with -Xlint:all -Werror, tests (JUnit 6)
./mvnw verify javadoc:javadoc    # plus Javadoc with doclint, warnings fail the build
./mvnw verify -P coverage        # JaCoCo report per module in <module>/target/site/jacoco
./mvnw deploy -P central,secrets # SNAPSHOT to the Central Portal by hand (the token comes from ~/.mavenrc;
                                 # ~/.m2/settings.xml lists https://central.sonatype.com in repositoryOrigins)
```
