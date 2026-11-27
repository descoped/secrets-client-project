# Provider: safe-configuration

Secrets in a local file, read, parsed, held and written in guarded memory: no value is ever on the Java heap unless
the caller asks for a heap copy. Reads and writes. **For local development and tests, not for production**: a file
of secrets on disk is only as safe as the disk and its permissions. In production, use
[Google Secret Manager](google-secret-manager.md).

- Maven: `io.descoped.secrets:secrets-provider-safe-configuration`, scope `runtime`
- Provider name: `safe-configuration`
- JPMS module: `io.descoped.secrets.provider.safe`; only the initializer is public, the client is reached through
  `SecretManagerClient.create`
- Depends on: [secrets-client-api](../api.md) only

## Configuration

Key | Description
---|---
`secrets.provider` | `safe-configuration` (required)
`secrets.property-resource-path` | path of the secrets file (required); it must exist
`secrets.memory.guard`, `secrets.memory.lock` | the guarded memory, see [the API](../api.md#guarded-memory-secretmemory-and-secret)

The JVM needs `--enable-native-access=io.descoped.secrets.api` (`ALL-UNNAMED` on the class path), or
`secrets.memory.guard=off` (tests only).

```java
SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "safe-configuration",
        "secrets.property-resource-path", "/run/secrets/app.secrets"));
```

## File format

```
# Database
db.password=s3cr3t=with=equals
api.token = abc def
```

- UTF-8; a leading byte-order mark is skipped. Lines end with LF or CRLF; both may appear in one file.
- One `key=value` per line. The first `=` splits key and value.
- Blanks (space, tab, form feed, vertical tab) around the key are removed. The value is taken byte for byte,
  including surrounding blanks and further `=` signs: above, `api.token` is ` abc def`.
- There are no escapes, so a value cannot contain a line break.
- Empty lines, lines of blanks and lines whose first non-blank character is `#` are ignored.
- A line without `=`, an empty key and a duplicate key are errors. The error names the file and the line number,
  never the value.

This is **not** the `java.util.Properties` format: `\`, `:` and `!` have no special meaning, and non-ASCII characters
are written as UTF-8, not `\uXXXX`. Files written by 2.x need converting; see
[Migrating from 2.x](../migrating.md).

## Reading

The file is read once, when the client is created; later changes to the file are not seen by that client. The only
version is `latest`: any other version is `SecretNotFoundException`, as is a key the file does not have.

## Writing

`addVersion(name, Secret)` updates the file and the client's view of it, and returns `latest`:

- The file is read again from disk, the line holding the key is replaced in place (or a line is appended), and every
  other line, comment and line ending is kept byte for byte. Edits made to other keys since the client started are
  therefore preserved in the file, but the client's in-memory view of those keys is not refreshed.
- The new content goes to a temporary file in the same directory, is flushed to disk, and then atomically replaces the
  file. A file system that cannot move atomically is an error; there is no non-atomic fallback. If the path is a
  symbolic link, its target is replaced and the link is kept.
- On file systems with POSIX permissions, the new file is owned by the writing user and readable and writable by that
  user only (`rw-------`). **A file that a group or others could read is no longer readable by them after a write.**
- Errors, all `SecretManagerException`: a file that cannot be written, a name the format cannot hold (empty, starting
  or ending with a blank, starting with `#`, containing `=` or a line break, not valid UTF-8), a value containing a
  line break.

Writes within one client are serialised by a lock. There is no locking between clients or processes: two writers at
the same time can lose one of the updates. Use one writer per file.

## Memory

The file is read with a `FileChannel` into guarded memory (through
[`SecretMemory.read`](../api.md#guarded-memory-secretmemory-and-secret), which handles `memfd_secret` memory) and
parsed there; each value is copied into a
`Secret` of its own, and the file's content is wiped. `addVersion` reads the file again into guarded memory, builds
the new content there and writes it from there. Only the keys, which are not secret, are ever on the Java heap.

- `read` returns a copy in guarded memory, which the caller closes; `close()` of the client closes it too.
- `addVersion(name, Secret)` copies the value; the caller still owns the `Secret`.
- A heap copy the caller makes (`withBytes`, `withChars`) is wiped when its callback returns; one the caller keeps is
  outside the guarantee.
- Replaced values are wiped; `close()` wipes and unmaps everything.

A canary test proves it: a child JVM reads a random value through the provider, writes it, and dumps its heap, which
must not hold the value in any encoding.
