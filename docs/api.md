# The API

`secrets-client-api` is what every application compiles against: `SecretManagerClient`, its exceptions, and the
service that providers implement. It has no provider of its own; add one or more provider modules at runtime.

- Maven: `io.descoped.secrets:secrets-client-api` (version from the BOM, see [Getting started](getting-started.md))
- JPMS module: `io.descoped.secrets.api`, package `io.descoped.secrets.api`
- Depends on: [service-provider-api](https://github.com/descoped/service-provider-api) 3.x (`requires transitive`)

## Creating a client

```java
try (SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "safe-configuration",
        "secrets.property-resource-path", "/run/secrets/app.properties"));
     Secret password = client.read("db.password")) {
    password.withChars(chars -> {
        connect(chars);
        return null;
    });
}
```

`SecretManagerClient.create(Map<String, String>)` picks the provider named by `secrets.provider` and hands it the
whole map. Each provider documents the other keys it reads:

Provider name | Module
---|---
`safe-configuration` | [secrets-provider-safe-configuration](providers/safe-configuration.md)
`google-secret-manager` | [secrets-provider-google-secret-manager](providers/google-secret-manager.md)
`mounted` | [secrets-provider-mounted](providers/mounted.md)

Because the provider is chosen by configuration, the application code stays the same in every environment: a local
file on a laptop, Google Secret Manager in production. Build the map from whatever configuration the application
already has. For example from environment variables, naming each key explicitly (the keys contain `-` and `.`, so
no mechanical renaming of `SECRETS_PROJECT_ID` gives `secrets.project-id`):

```java
Map<String, String> keys = Map.of(
        "SECRETS_PROVIDER", "secrets.provider",
        "SECRETS_PROJECT_ID", "secrets.project-id",
        "SECRETS_PROPERTY_RESOURCE_PATH", "secrets.property-resource-path");
Map<String, String> configuration = new HashMap<>();
keys.forEach((variable, key) -> {
    String value = System.getenv(variable);
    if (value != null) {
        configuration.put(key, value);
    }
});
```

`create` throws:

Exception | When
---|---
`IllegalArgumentException` | `secrets.provider` is missing or blank, a key the provider requires is missing, or a value is invalid (for example a malformed project id, an endpoint that is not https, or a timeout that is not positive)
`io.descoped.service.provider.api.ProviderException` | no provider, or more than one, has that name
`SecretManagerException` | the provider cannot start (for example its file cannot be read)
`NullPointerException` | the map, or a key or value in it, is `null`

## The API

```java
public interface SecretManagerClient extends AutoCloseable {

    Secret read(String secretName, String secretVersion);       // into guarded memory; null version = latest
    Secret read(String secretName);                             // latest
    String addVersion(String secretName, Secret secretValue);   // from guarded memory; returns the new version id

    void close();

    static SecretManagerClient create(Map<String, String> configuration);
}
```

What a version id looks like depends on the provider: the file-based providers have only `latest`; Google Secret
Manager has `latest` and version numbers.

Values go in and out only as a `Secret`. To write a value the application holds as characters or bytes, copy it into
guarded memory first; `fromChars` and `fromBytes` wipe the array they are given:

```java
try (SecretMemory memory = SecretMemory.create(Map.of());
     Secret value = memory.fromChars(password)) {     // password is wiped
    client.addVersion("db.password", value);
}
```

## The contract

Every provider behaves the same way, so an application can switch providers without changing its error handling:

Situation | Result
---|---
The secret or the version does not exist | `SecretNotFoundException` (a `SecretManagerException`), with `secretName()` and `secretVersion()`
Any other failure: I/O, permissions, a remote error | `SecretManagerException`
The provider cannot write (a read-only provider) | `UnsupportedOperationException` from `addVersion`
Any method after `close()`, except `close()` | `IllegalStateException`
A `null` name or value | `NullPointerException`

- Exception messages name the secret, never its value, and neither do `toString()` or the cause chain.
- `read` returns a new `Secret` that the caller owns and closes; closing the client closes it too. The client keeps
  no reference to it, nor to a `Secret` passed to `addVersion`, which stays the caller's to close.
- `close()` is idempotent and wipes what the client holds in memory. A call already running when `close()` is called
  either completes normally or throws `IllegalStateException`; it never fails in any other way or returns a partial
  value.
- Clients are thread-safe.

## Keeping secrets out of memory

A Java `String` is immutable: it stays in the heap until the garbage collector reclaims it, and it cannot be wiped.
That is why the client hands values over only as a `Secret`, in guarded memory (see below):

- Use the value inside `withSegment`, or with `withBytes`/`withChars`, whose heap copy is wiped when the callback
  returns. `withChars` decodes strict UTF-8: invalid UTF-8 is an error, never replaced with `?`.
- A provider that reads files (safe-configuration, mounted) never puts the value on the Java heap on the way, and
  neither does safe-configuration's `addVersion`. Google Secret Manager keeps it off the heap over the network too:
  TLS goes through OpenSSL, not the JDK ([details](providers/google-secret-manager.md#memory-and-tls)).
- A value that has to end up in a `String` (a library that only accepts strings) can be made one inside the callback:
  `secret.withChars(String::new)`. The `String` is then on the heap for as long as it lives, outside what this
  library can wipe.

## Guarded memory: `SecretMemory` and `Secret`

`SecretMemory` holds secret values off the Java heap, in memory the garbage collector never sees, moves or copies, and
that is not in heap dumps. A `Secret` is one value in it.

```java
try (SecretMemory memory = SecretMemory.create(configuration);
     Secret password = memory.fromChars(chars)) {          // copies into guarded memory, wipes chars
    password.withChars(value -> {                          // a heap copy, wiped when the call returns
        dataSource.setPassword(value);
        return null;
    });
}                                                          // wiped, unlocked, unmapped
```

- **Pages of their own.** Secrets share slabs of whole pages with a guard page before and after each slab. The guard
  pages are never accessible, so reading or writing past either end faults instead of reaching other memory.
- **Accessible only while used.** A slab's pages are `PROT_NONE` unless a secret on them is being read, written or
  wiped.
- **Never swapped.** The pages are locked with `mlock`. With `secrets.memory.lock=required` (the default) memory that
  cannot be locked is an error: raise the locked-memory limit (`ulimit -l`, `docker run --ulimit memlock=...`), or
  set `secrets.memory.lock=preferred` to use it unlocked, which is logged once.
- **Not in core dumps, not in a forked child** (Linux): `MADV_DONTDUMP`, and `MADV_WIPEONFORK` (or `MADV_DONTFORK`
  for `memfd_secret` memory).
- **Hidden from the kernel** (Linux 5.14 and later): where the kernel offers `memfd_secret` (on by default since 6.5,
  unless a seccomp filter blocks it), the pages come from it and are removed from the kernel's direct map, so not even
  the kernel reaches them by accident. Otherwise anonymous pages are used, and that is logged once.
  `SecretMemory.isHiddenFromKernel()` says which. While any `memfd_secret` memory exists, Linux refuses to hibernate
  (suspend to disk), which matters on a desktop or laptop. The kernel cannot pin `memfd_secret` pages either, so a
  read that pins its destination fails on them with `EFAULT` ("Bad address"). Such reads include a file served through
  FUSE or virtiofs (Cloud Run's secret volumes) and direct I/O. Read files and other channels with
  `SecretMemory.read(channel, maxLength)`, which reads such memory through a small buffer of guarded, locked, ordinary
  pages, wiped and unmapped before it returns. Every provider reads its files this way.
- **Wiped** when a secret is closed, and wiped and unmapped when the memory is closed. A secret that becomes
  unreachable without being closed is wiped when the garbage collector finds it, and that is logged.

The value is reached only inside a callback:

- `withSegment` hands over the value itself as a read-only `MemorySegment`, with no copy at all, valid only during the
  call and only in the calling thread;
- `withBytes` and `withChars` hand over a copy on the heap, wiped when the call returns. `withChars` decodes strict
  UTF-8 itself, without the JDK's charset decoders, which keep heap buffers of their own.

The hand-over is where the library's reach ends: a consumer that keeps its own copy of the array, or makes a `String`
of it, keeps the value on the heap.

**Native access.** Guarded memory calls the C library (`mmap`, `mprotect`, `mlock`, `munlock`, `munmap`, `madvise`,
`getpagesize`; on Linux also `ftruncate`, `close`, and `syscall` for `memfd_secret` and `getrandom`, which a seccomp
profile must allow) through the Foreign Function & Memory API, so the JVM must be started with `--enable-native-access=io.descoped.secrets.api` (or
`--enable-native-access=ALL-UNNAMED` on the class path). Without it, `SecretMemory.create` refuses. It runs on Linux
and macOS, on x86_64 and aarch64; elsewhere it refuses too. `secrets.memory.guard=off` gives plain off-heap memory
without any of the protection above and without native access; it is meant for tests.

## JPMS

An application module `requires io.descoped.secrets.api` and nothing else. The API module declares
`uses io.descoped.secrets.api.SecretManagerClientInitializer`, so a provider module that is on the module path is
resolved at startup without the application requiring it. On the class path, providers are found through
`META-INF/services`.

To add a backend of your own, see [Writing a provider](writing-a-provider.md).
