# Provider: mounted

Secrets that the platform mounts as files, read-only. The process holds no credential and has no network code for
its secrets: the platform fetches them and mounts them. Where the platform offers it, this is the strongest option:

- **Cloud Run** mounts Secret Manager secrets as a volume.
- **GKE and EKS** have the Secrets Store CSI driver, with the Google Secret Manager and AWS Secrets Manager providers.
- **Kubernetes** mounts its own secrets as a volume.

Each `read` opens the file and reads it with a `FileChannel` straight into guarded memory: the value is never on the
Java heap unless the caller asks for a heap copy (`readBytes`, `readChars`, `readString`).

- Maven: `io.descoped.secrets:secrets-provider-mounted`, scope `runtime`
- Provider name: `mounted`
- JPMS module: `io.descoped.secrets.provider.mounted`; only the initializer is public
- Depends on: [secrets-client-api](../api.md) only
- Needs native access: `--enable-native-access=io.descoped.secrets.api` (`ALL-UNNAMED` on the class path)

## Configuration

Key | Description
---|---
`secrets.provider` | `mounted` (required)
`secrets.mounted.directory` | the directory the secrets are mounted under (required); it must exist when the client is created
`secrets.memory.guard`, `secrets.memory.lock` | the guarded memory; see [the API](../api.md#guarded-memory-secretmemory-and-secret)

```java
SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "mounted",
        "secrets.mounted.directory", "/secrets"));
try (Secret password = client.read("db-password")) {
    password.withChars(chars -> {
        connect(chars);
        return null;
    });
}
```

## Names and files

- A secret's name is its file's path relative to the directory: `api-key` is `<directory>/api-key`, `db/password` is
  `<directory>/db/password`.
- Each segment of a name starts with a letter, a digit or `_`, and goes on with letters, digits, `_`, `-` and `.`. A
  name of another form (`..`, an absolute path, an empty segment, a hidden file) is `SecretNotFoundException`.
- Symbolic links are followed, as Kubernetes links each key into its `..data` directory, but the file they lead to
  must be inside the directory. A link out of it is a `SecretManagerException`.
- A value is the file's bytes exactly. A trailing line break, if the file has one, is part of the value.
- A file is read to its end whatever size it reports. A file larger than 4 MiB is an error.

## Behaviour

- The only version is `latest` (or `null`): the platform chooses the version when it mounts the volume. Another
  version, a missing file and a directory are `SecretNotFoundException`.
- Files are read on every `read`, never cached. A value the platform rotates in place, as Kubernetes does, is seen at
  the next read. A read that races a rotation, and finds the file it resolved already removed, resolves the name again,
  up to three times in all, before it reports the secret as missing.
- The file is opened without following a link, after its real path was checked to be inside the directory.
- A file that does not end (a FIFO without a writer, a mount that hangs) blocks the read, and `close()` waits for
  reads in progress.
- `addVersion` throws `UnsupportedOperationException`: the platform owns the files.
- Closing the client closes every `Secret` it returned. The client holds no value between reads.
- Error messages name the secret, never its value.

## Platforms

**Cloud Run.** Cloud Run mounts each secret volume at a directory of its own, so give each secret its own
directory under one parent and point `secrets.mounted.directory` at the parent: with
`--set-secrets=/secrets/db/password=db-password:latest,/secrets/api/key=api-key:latest`, the secrets are read as
`db/password` and `api/key` with `secrets.mounted.directory=/secrets`. Do not also mount a secret at the parent
directory itself.

**Kubernetes and the Secrets Store CSI driver.** Point `secrets.mounted.directory` at the volume's `mountPath`; each
key or object alias is a file there.

## Testing

`MountedClientTest` covers:
- reads, rotation, reads racing Kubernetes-style rotations, binary values, values of 3 MiB and the 4 MiB limit;
- a file of unknown size (a FIFO);
- nested names and Kubernetes-style links, and a link out of the directory;
- invalid names, versions, writes, closing and configuration.

`MountedCanaryTest` runs the canary gate: a child JVM reads the canary through the provider, also from a FIFO
through the buffer that grows, and its heap dump must not hold it.

`MountedSecretLiveTest`, in the Google Secret Manager provider's tests, is the live test on Cloud Run. Its job is
not run in CI, and its infrastructure lives outside this repository. The job mounts a Secret Manager secret as
`latest` and runs only this class. The test reads the file through this provider and the same secret from Secret
Manager, then compares the two. Its settings:
- `SECRETS_MOUNTED_TEST_DIRECTORY`: the mount's parent directory;
- `SECRETS_MOUNTED_TEST_NAME`: the path under it, default `live/value`;
- `SECRETS_MOUNTED_TEST_SECRET`: the secret, default `secrets-client-live-test`;
- the Google live test's project and credentials variables.
