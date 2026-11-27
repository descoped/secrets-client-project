# Releasing

Releases are made **only by the owner, or on his explicit word**, and go only to Maven Central. A SNAPSHOT never goes
to Central: the Portal limits monthly publishing, and the `central` profile refuses a SNAPSHOT version or a SNAPSHOT
dependency.

SNAPSHOTs go only to Descoped's AWS CodeArtifact repository, read publicly at `https://maven.descoped.io/`, for
development across repositories. CI's `snapshot` job publishes them after a green build:

- a push to master publishes the current `X.Y.Z-SNAPSHOT`;
- a run by hand on another branch (`gh workflow run ci.yml --ref <branch>`) publishes `X.Y.Z-<branch>-SNAPSHOT`, so
  it never replaces master's;
- a pull request or a tag publishes nothing.

The POM has no `<distributionManagement>`, so `deploy` without a target fails, and a release version can never go to
maven.descoped.io. The job names the target on its command line (`-DaltSnapshotDeploymentRepository`, SNAPSHOTs
only). The publishing endpoint is in no file of this repository.

All modules share one version, and a release publishes seven artifacts: the parent `secrets-client-project`, the BOM
`secrets-client-bom`, `secrets-client-api`, and the providers `secrets-provider-safe-configuration`,
`secrets-provider-google-secret-manager`, `secrets-provider-mounted` and `secrets-provider-aws-secrets-manager`.
`secrets-test-support` and `secrets-coverage` are never published. The tag is the version with a `v`: `v4.0.0`.
Releases up to 3.0.0 were tagged without the `v` (`3.0.0`), and the modules' older tags carry their module's name
(`secrets-client-api/2.0.3`); those tags stay.

## Before a release

- `master` is green: CI (build, tests, Javadoc, the JPMS smoke test), SonarCloud with no open issues, and the
  automated review triaged.
- `just linux` passes: the tests on Linux, where `memfd_secret` is in use.
- The live tests passed on the code being released, or on code whose network and credential paths are the same:
  Google Secret Manager (`just live-google`, and on Cloud Run with the metadata server) and AWS Secrets Manager
  (`just live-aws`, and on ECS and EC2 with role credentials). CI cannot make these.
- `CHANGELOG.md` has a section `## [<version>] - <date>`, with the compare link at the bottom, merged in a pull
  request. The GitHub release takes its notes from it. The links use the tags as they are: 4.0.0's is
  `compare/3.0.0...v4.0.0` (3.0.0 has no `v`), and from then on `compare/v4.0.0...v4.0.1` and so on.
- `~/.m2/settings.xml` has the server `central` with the Central Portal token and
  `<repositoryOrigins>https://central.sonatype.com</repositoryOrigins>`. Maven 3.10 only sends a server's credentials
  to the hosts it knows for that id.
- GPG signs with its default key, and the key's public part is on a key server Central checks
  (`keys.openpgp.org` or `keyserver.ubuntu.com`).

## The steps

### 1. Prepare and perform

```sh
java -version                     # 25, the JDK of .java-version, as CI builds
./mvnw release:prepare release:perform -P secrets
```

Run it on JDK 25: the build is reproducible (`project.build.outputTimestamp`), and another JDK writes another
`Build-Jdk-Spec` into the jars, so they would no longer be the bytes a rebuild of the tag gives.

`release:prepare` asks for the release version (`4.0.0`), the tag (`v4.0.0`) and the next development version
(`4.0.1-SNAPSHOT`). It builds and tests, commits the release version, tags it, commits the next SNAPSHOT and pushes
both commits and the tag. The tag push runs CI on the tag.

`release:perform` checks out the tag into `target/checkout` and runs `deploy -P central,sign`: every artifact is
signed with the GPG key (gpg-agent asks for the passphrase) and the bundle is uploaded to the Central Portal. It is
not published: `autoPublish=false`, and the upload waits until the Portal has validated it. The log ends with the
deployment id and `has been validated`. `-P secrets` is not a profile of this POM: it makes the owner's Maven setup
load the Portal token for this one run, so Maven's warning that the profile `secrets` could not be activated is
expected.

### 2. Publish on Central

In the Central Portal, under Deployments, check the deployment (the seven artifacts, their signatures, the POMs) and
press Publish. Publishing is final: a version on Central can never be changed or removed. It is on
`repo1.maven.org` after it is synced, usually within half an hour.

### 3. Publish the GitHub release

Once the version is on `repo1.maven.org`:

```sh
gh release create v4.0.0 --verify-tag --title 4.0.0 --notes-file <the CHANGELOG section for 4.0.0>
```

The links in the notes must be absolute (`https://github.com/descoped/secrets-client-project/blob/v4.0.0/docs/...`),
since relative links do not resolve on the release page. Then, in a pull request, set the version in
[getting started](getting-started.md) to the new release.

## If something goes wrong

- **`release:prepare` fails before it pushes**: `./mvnw release:rollback`, then `./mvnw release:clean`, fix, and
  prepare again.
- **`release:perform` fails, or the Portal rejects the deployment**: drop the deployment in the Portal, if there is
  one, fix, and run `./mvnw release:perform -P secrets` again. `release.properties` still points at the tag, so it
  builds the same tag; without it, name the tag: `-Dtag=v<version>`. The tag was tested by `release:prepare`, so a
  rerun can skip the tests: `-Darguments=-DskipTests`. Nothing is public until Publish is pressed.
- **The upload fails with `401`**: the token was not sent. Check the `central` server and its `repositoryOrigins` in
  `settings.xml`, `-P secrets`, and that the token is still valid.
- **A tag was pushed but nothing is published**: fix forward, or delete the tag and revert the release commits, only
  while nothing for the version is on Central.
