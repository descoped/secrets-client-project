# CLAUDE.md

Guidance for Claude Code in this repository.

## What this is

The Descoped secrets client: `SecretManagerClient`, a provider based API for reading and writing secrets, and its
providers. One Maven reactor, group `io.descoped.secrets`, owned by Descoped. `README.md` is the short
introduction (what it is, how it works, working with the code); `docs/` is the user documentation. Both must stay
true when behaviour changes.

| Module | JPMS module | Role |
|---|---|---|
| `secrets-client-project` (root) | n/a | parent and aggregator |
| `secrets-client-bom` | n/a | BOM of the modules below |
| `secrets-client-api` | `io.descoped.secrets.api` | `SecretManagerClient`, `SecretManagerClientInitializer` (the provider service, on `io.descoped.spi:service-provider-api`) |
| `secrets-provider-safe-configuration` | `io.descoped.secrets.provider.safe` | local `key=value` file, for development and tests; read, parsed, held and written in guarded memory |
| `secrets-provider-dynamic-configuration` | `io.descoped.secrets.provider.dynamic` | read-only, on `io.descoped.config:dynamic-configuration` 3.x, for tests and migration |
| `secrets-provider-google-secret-manager` | `io.descoped.secrets.provider.google` | Google Secret Manager REST API, google-auth (Application Default Credentials), Jackson 3 `jackson-core` |

Until 2026-11 every module was a repository of its own; their histories were imported here with `git filter-repo`
(old tags prefixed with the module name, e.g. `secrets-client-api/2.0.3`). 3.0.0 (2026-11-17) is the first release
from this repository, with new module and package names, a revised API and revised providers; `CHANGELOG.md` and
`docs/migrating-from-2.x.md` describe the changes. From 3.0.0 on, versions follow semantic versioning: a breaking
change to the API or to a provider's documented behaviour needs a new major version.

## Invariants (never violate)

- **Java 25 baseline** (`java.version` 25 in the root POM, the same number in `.java-version`): every class file is
  Java 25 whatever JDK builds it. CI and the Claude workflow set up the JDK from `.java-version`, and the JPMS smoke
  test compiles with it. Change the baseline in both files together.
- **One reactor, one version.** Every module inherits the root POM and is released with it; modules depend on each
  other with `${project.version}`. Dependency versions are properties in the root POM, not `dependencyManagement`, so
  the BOM manages the secrets modules only.
- **JPMS.** Every module is a named module. A module whose exported API exposes another module's types `requires
  transitive` it. Providers are registered both with `provides` in `module-info.java` and in `META-INF/services`, so
  they work on the module path and the class path.
- **Secrets stay secret.** Secret values are never logged, never put in exception messages, `toString` or test
  output. Byte and char arrays handed to or returned by a client are copies; the client wipes its own copies when it
  no longer needs them and on `close()`.
- **No secret on the Java heap (4.0, being built).** Library code keeps secret values, and credentials that grant
  access to secrets (access and refresh tokens), only in guarded native memory (FFM, `java.lang.foreign`): never in a
  heap array, a `String` or a heap `ByteBuffer`, except the hand-over copy a caller asks for, wiped when its callback
  returns. No runtime dependency that holds them on the heap. A canary heap-dump test proves each read and write path.
  Code from 3.x does not meet this yet; new code must. Accepted interim exceptions, until the plan removes them:
  `read` in the Google provider (rebuilt in phase 4) and in dynamic-configuration (removed in phase 6) copies
  `readBytes` into guarded memory, and the default `addVersion(String, Secret)` hands a wiped heap copy to
  `addVersion(String, byte[])`.
- **One contract for every provider.** A missing secret, a closed client and a write the provider cannot do are
  reported the same way by every provider.
- **Always the latest stable version** of every library, plugin and action. Pre-releases only on request. Old and
  outdated code and configuration is removed, not carried along.
- **Releases only with the owner's go-ahead.** A release (`release:prepare`/`release:perform`, an upload to the
  Central Portal) is made by the owner or on his explicit word, and `CHANGELOG.md` gets its entry first.
- **Publishing.** Releases go only to Maven Central, by hand, through the Central Portal (profiles `central,sign`);
  the `central` profile's enforcer refuses a SNAPSHOT version or a SNAPSHOT dependency. CI publishes nothing to
  Maven Central. Maven 3.10 sends a server's credentials only to the hosts it knows for that id, and the id `central`
  is bound to Maven Central, so the server `central` in `~/.m2/settings.xml` must list `https://central.sonatype.com`
  in `repositoryOrigins`.
- **SNAPSHOTs** go only to maven.descoped.io (Descoped's AWS CodeArtifact), from CI's `snapshot` job: on a push to
  master, or by `workflow_dispatch` on a branch as `X.Y.Z-<branch>-SNAPSHOT`. The job names the target on its
  command line (`-DaltSnapshotDeploymentRepository`), and the POM has no `distributionManagement` at all: that is
  what makes a release version fail to deploy there. Never add one. No AWS account ID or CodeArtifact endpoint in
  any public file (POM, workflow, deployed POM, CI log).
- **SonarCloud**: one project, `descoped_secrets-client-project`, for the whole reactor.

## Testing

- JUnit 6. Tests must not touch fixed paths such as `/tmp/...`; use `@TempDir`.
- Guarded memory (`SecretMemory`, native code in the unexported package `io.descoped.secrets.api.internal`): surefire
  runs with `--enable-native-access=io.descoped.secrets.api` (root POM). What can fault, such as reading a guard page
  or a page outside a callback, is tested in a child JVM (`GuardPageTest` runs `GuardProbe`), never in the test JVM.
- **The canary gate.** Every path that reads or writes a secret (a provider's read, `addVersion`, token handling) has
  a `HeapCanary` test (`secrets-test-support`): a child JVM reads a random canary only through that path, uses it,
  and dumps its heap; the dump must hold no copy of the canary in any encoding (`assertClean`). A path is not done
  until its canary test passes. The harness proves itself in its own tests (guarded memory is clean, a leak in each
  encoding is found). `secrets-test-support` is never published (`maven.deploy.skip`, `skipPublishing`) and is not in
  the BOM.
- The Google Secret Manager tests run against `FakeGoogle`, a local server that also issues OAuth tokens for a
  generated service-account key. `GoogleSecretManagerLiveTest` calls Google only when `SECRETS_GOOGLE_TEST_PROJECT`
  is set; it is not run in CI.
- Each module's tests are a named module of their own, `<module>.test` (`src/test/java/module-info.java`), in package
  `<package>.test`. They require `io.descoped.secrets.api` and reach a provider only through
  `SecretManagerClient.create` and `ServiceLoader`, as an application does (the API module's `uses` resolves the
  provider module). Never put tests in a module's own package (a split package) or test providers in
  `META-INF/services` (a named module ignores it).

## Maven Wrapper

- `./mvnw` pins Maven (`.mvn/wrapper/maven-wrapper.properties`, type `only-script`, so no jar in the repository) and
  checks the download against `distributionSha256Sum`. CI runs `./mvnw`. When Maven is bumped, by Renovate or by hand,
  set `distributionSha256Sum` to the SHA-256 of the new `apache-maven-<version>-bin.zip`, after checking that zip
  against the `.sha512` Maven publishes next to it. A stale checksum fails the build, it never skips the check.

## Commands

```sh
./mvnw verify                    # compile with -Xlint:all -Werror, tests (JUnit 6)
./mvnw verify javadoc:javadoc    # plus Javadoc with doclint, warnings fail the build
src/it/consumer/run.sh           # JPMS smoke test: an application that requires only the API, against every
                                 # provider, on the module path (Google's dependencies as automatic modules) and
                                 # the class path; jdeps --check on the modules with named dependencies only
./mvnw verify -P coverage        # JaCoCo report per module in <module>/target/site/jacoco
```
