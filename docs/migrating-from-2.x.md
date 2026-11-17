# Migrating from 2.x

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

## safe-configuration files written by 2.x

Files written by 2.x `addVersion` went through `java.util.Properties.store(OutputStream, ..)`, which escapes values:
`\\` for `\`, `\=`, `\:`, `\#`, `\!`, `\t`, `\n`, `\r`, `\f`, `\ ` for a leading space, and `\uXXXX` for every
character outside ISO-8859-1 (for example `https\://host`, `blå`). 3.0 reads values verbatim (see
[the file format](providers/safe-configuration.md#file-format)), so undo every one of these escapes once, in every line
of such a file.
