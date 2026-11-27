---
title: Migrating
description: Move to 4.0 from 3.x, from 2.x, or from the 0.x versions of the secrets client.
order: 11
---

# Migrating

## Migrating from 3.x to 4.0

4.0 keeps values, and the credentials that grant access to them, off the Java heap, so the client hands values over
only as a `Secret`, in guarded memory. [The security model](security.md) says what that protects and where it ends.
The Maven coordinates are unchanged.

### The platform

3.x | 4.0
---|---
Java 17 | Java 25 or later
No JVM flags | `--enable-native-access=io.descoped.secrets.api` (`ALL-UNNAMED` on the class path); without it a client refuses to start
Any operating system | Linux or macOS, on x86_64 or aarch64; elsewhere, including Windows, a client refuses to start (tests can set `secrets.memory.guard=off`)
No memory limits | secrets are locked in memory (`mlock`): a container whose locked-memory limit is too small fails with "Cannot lock". Raise the limit (`docker run --ulimit memlock=...`, the `ulimits` of an ECS task definition), or set `secrets.memory.lock=preferred` to accept swap. Cloud Run, ECS on Fargate and Docker on EC2 work with their defaults
The JDK's TLS | the Google and AWS providers need OpenSSL 3: `libssl3` on Debian and Ubuntu (minimal and distroless images may lack it), `brew install openssl@3` on macOS
A seccomp profile that allows the JDK | it must also allow the calls guarded memory makes ([the list](security.md#what-the-platform-must-provide)), including `memfd_secret` to hide secrets from the kernel

### The API and the providers

3.x | 4.0
---|---
`char[] password = client.readChars(name)`, then `Arrays.fill` | `try (Secret password = client.read(name)) { password.withChars(chars -> ...); }`, the copy wiped when the callback returns
`client.readBytes(name)` | `password.withBytes(bytes -> ...)`, or `withSegment` to stay off the heap
`client.readString(name)` | `secret.withChars(String::new)`, if a `String` is really needed
`client.addVersion(name, chars)` (or `byte[]`, `String`) | `try (SecretMemory memory = SecretMemory.create(Map.of()); Secret value = memory.fromChars(chars)) { client.addVersion(name, value); }`; `fromChars`/`fromBytes` wipe the array
provider `dynamic-configuration`, a properties file | removed: safe-configuration reads a local `key=value` file
provider `dynamic-configuration`, a directory of secret files | `mounted`, one file per secret. dynamic-configuration removed one trailing LF or CRLF; `mounted` keeps the file's bytes exactly, so write the files without a final line break (`printf '%s' "$value"`), or a password gains a `\n` and authentication fails
provider `dynamic-configuration`, inline `secrets.values.<name>` in tests | a temporary safe-configuration file, or a `@TempDir` directory with `mounted`
Google Secret Manager with a service-account key file (`secrets.service-account-key-path`, or `GOOGLE_APPLICATION_CREDENTIALS` naming one) | refused: signing with a key would put it on the heap. On Google Cloud use the metadata server (the attached service account, GKE Workload Identity) and pin it with `secrets.credentials=metadata`; for development, `gcloud auth application-default login` ([credentials](providers/google-secret-manager.md#credentials))
Google Secret Manager trusts a private CA or TLS proxy through `javax.net.ssl.trustStore` | `secrets.tls.ca-file`, a PEM file of the certificates to trust: TLS goes through OpenSSL 3 now (`libssl3` on Linux, `brew install openssl@3` on macOS), and the JDK's trust store does not apply
A provider implements `readBytes` and `addVersion(String, byte[])` | it implements `read(String, String)` and `addVersion(String, Secret)`; see [Writing a provider](writing-a-provider.md)

## Migrating from 2.x

3.0.0 is a breaking release. The Maven coordinates are unchanged.

What changed | 2.x | 3.0
---|---|---
Java | 11 | 17
API module | `io.descoped.secrets.client.api` | `io.descoped.secrets.api` (package unchanged)
safe-configuration | package `io.descoped.secrets.secure.configuration` | module and package `io.descoped.secrets.provider.safe`
dynamic-configuration | provider `dynamic-secret-configuration`, package `io.descoped.secrets.dynamic.configuration` | provider `dynamic-configuration`, module and package `io.descoped.secrets.provider.dynamic`
google-secret-manager | module `io.descoped.secrets.provider.google.rest.api`, package `...google.secretmanager.restapi` | module and package `io.descoped.secrets.provider.google`
Missing secret or version | `null` (safe, dynamic) or `RuntimeException` (Google) | `SecretNotFoundException`
Other failures | `RuntimeException` | `SecretManagerException`
Returned arrays | safe-configuration returned its own array | always a new array the caller owns
`safeCharArrayAsUTF8(bytes)` | static helper | `readChars(name)`
dynamic-configuration | read and write, Base64 in the file | read-only; file, secret directory or inline values
dynamic-configuration library | 2.x | 3.x
Google credentials | Compute Engine or a key file | Application Default Credentials or a service-account key file
Google replication of new secrets | `europe-north1` | automatic, or `secrets.replication-locations`
Provider implementation classes | public | package-private; only the initializers are public
`service-provider-api` | 2.x | 3.x (`providerId()` is gone; the `@ProviderName` annotation names a provider)

### safe-configuration files written by 2.x

Files written by 2.x `addVersion` went through `java.util.Properties.store(OutputStream, ..)`, which escapes values:
`\\` for `\`, `\=`, `\:`, `\#`, `\!`, `\t`, `\n`, `\r`, `\f`, `\ ` for a leading space, and `\uXXXX` for every
character outside ISO-8859-1 (for example `https\://host`, `blå`). 3.0 reads values verbatim (see
[the file format](providers/safe-configuration.md#file-format)), so undo every one of these escapes once, in every line
of such a file.

## Migrating from `no.ssb.dapla.secrets`

Before 2.0, this library was published with the Maven group `no.ssb.dapla.secrets` (artifacts
`dapla-secrets-client-api` and `dapla-secrets-provider-*`, versions 0.x, packages `no.ssb.dapla.secrets.*`). Since 2.0
it is `io.descoped.secrets`. To upgrade from 0.x, change the group, the artifact names (drop the `dapla-` prefix) and
the packages to `io.descoped.secrets`, then apply the 2.x → 3.0 changes above. The history of those versions is kept
in this repository.
