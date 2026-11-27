# Security model

What this library protects, where its protection ends, and what it needs from the platform. To report a
vulnerability, see [SECURITY.md](../SECURITY.md).

## The promise

From the moment a provider reads a secret until the caller takes it, the value is never on the Java heap. It is in
guarded native memory ([`SecretMemory`](api.md#guarded-memory-secretmemory-and-secret)) and leaves it only when the
caller asks. The same holds for the credentials that grant access to secrets: Google's access and refresh tokens,
AWS's secret access key and session token, the container authorization token and the IMDS session token. Requests
are built in guarded memory, signed there, and encrypted and decrypted by OpenSSL straight out of and into it.

Values and credentials never appear in an exception message, a `toString`, a cause chain or a log.

## What it protects against

Threat | Protection
---|---
A heap dump (`jmap`, `-XX:+HeapDumpOnOutOfMemoryError`, a diagnostic agent) | The value is never on the heap, so it is not in the dump. Proven by the canary tests (below).
The garbage collector leaving copies of moved objects behind | Off-heap memory is never moved or copied by the collector.
Swap | Pages are locked with `mlock`; by default, memory that cannot be locked is an error (`secrets.memory.lock=required`).
Core dumps (Linux) | `MADV_DONTDUMP`.
A forked child process (Linux) | `MADV_WIPEONFORK`, or `MADV_DONTFORK` for `memfd_secret` memory.
The kernel reading the pages by accident, or through its direct map (Linux 5.14+) | `memfd_secret` where the kernel offers it: the pages are removed from the kernel's direct map.
A read or write past the end of a value | Guard pages before and after each slab fault.
Code touching a value outside its use | Slab pages are `PROT_NONE` except while a value on them is read, written or wiped.
A value left behind after use | Wiped when its `Secret` is closed, when the client closes, or, if it was never closed, when the garbage collector finds it unreachable (logged).
The JDK's TLS copying plaintext through heap arrays | TLS through the system's OpenSSL 3 instead of `SSLEngine`.
The JDK's `Mac` copying its key to the heap | SHA-256 and HMAC-SHA256 through OpenSSL's libcrypto.
A secret in an error | Messages name the secret, the HTTP status or the error type, never a value or a response body.
A header injected through a token | A secret header value with a control character (CR, LF and others) is refused before it is sent.

## Where it ends

- **The hand-over.** `withBytes` and `withChars` give the caller a heap copy, wiped when the callback returns.
  `withSegment` gives the value itself, with no copy. Whatever the caller does inside the callback is outside the
  library: a copy it keeps, a `String` it makes (`withChars(String::new)`), or a library it passes the value to that
  keeps one. Prefer `withSegment` or a short `withChars` that hands the array to an API that does not keep it.
- **Code running in the process.** An attacker who can run code in the JVM, attach a debugger or agent, or read the
  process's memory as its user or as root can read a value while it is mapped. Guarded memory makes accidents and
  dumps safe. It is not a sandbox against code that already runs inside the process.
- **Transient copies outside the heap.** While a value is used, it passes through CPU registers and native stack
  frames, which are not wiped. While a TLS record is decrypted, its plaintext is in OpenSSL's own buffers: native
  memory, cleared by OpenSSL once handed over and when the connection is freed (`SSL_OP_CLEANSE_PLAINTEXT`).
- **Side channels** such as Spectre-class attacks are out of scope.
- **The environment.** The JVM holds its environment variables as `String`s on the heap for its whole life. That is
  why the AWS provider refuses keys in the environment unless `secrets.credentials=environment` is set, and the
  container authorization token is read only from a file.
- **Without `memfd_secret`,** the pages are locked, guarded and kept out of dumps, but remain in the kernel's direct
  map. `SecretMemory.isHiddenFromKernel()` tells which, and a fallback is logged once.
- **`secrets.memory.guard=off`** turns all of this off. It is meant for tests.

## Credentials

Provider | Accepted | Refused
---|---|---
Google Secret Manager | an `authorized_user` file (`gcloud auth application-default login`) for development; the metadata server (GKE Workload Identity, Cloud Run, Compute Engine) in production | service-account key files, since signing with a key would put it on the heap
AWS Secrets Manager | the shared credentials file for development; the ECS task role and EKS Pod Identity (container endpoint); EC2 instance profiles (IMDSv2 only) | keys in environment variables (unless `secrets.credentials=environment`, outside the guarantee, for AWS Lambda); a container token in an environment variable; web identity (EKS IRSA), not supported yet
mounted | no credential in the process: the platform mounts the files | n/a
safe-configuration | no credential: a local file, for development and tests | n/a

In production, pin the source (`secrets.credentials=metadata` on Google Cloud, `container` or `instance` on AWS), so
the client never falls back to something else. Every token and key a source returns is parsed in guarded memory, and
temporary credentials are fetched again before they expire.

## What the platform must provide

- **Native access.** Start the JVM with `--enable-native-access=io.descoped.secrets.api`
  (`--enable-native-access=ALL-UNNAMED` on the class path). Without it, a client refuses to start rather than run
  unguarded. The JPMS smoke test checks this on the module path and the class path.
- **Linux or macOS, on x86_64 or aarch64.** Elsewhere, including Windows, a client refuses to start.
- **OpenSSL 3** for the Google and AWS providers: `libssl.so.3` and `libcrypto.so.3` on Linux (Debian and Ubuntu: the
  `libssl3` package, which minimal and distroless images may lack); `brew install openssl@3` on macOS.
- **A locked-memory limit** large enough for the secrets in use. Memory is taken in slabs of whole pages. If the
  limit is too low, a client fails with "Cannot lock". Raise the limit (`ulimit -l`, `docker run --ulimit
  memlock=...`, the `ulimits` of an ECS task definition) or, accepting swap as a leak path,
  `secrets.memory.lock=preferred`.
- **A seccomp profile** that allows `memfd_secret`, `mlock`, `madvise`, `mprotect` and `getrandom`, if the platform
  filters system calls. If `memfd_secret` is blocked, guarded memory falls back to anonymous pages.

Verified on real platforms:

Platform | `mlock` (default limit) | `memfd_secret`
---|---|---
Google Cloud Run, second generation | works | in use
AWS ECS on Fargate (arm64) | works | blocked; anonymous pages
AWS EC2, Amazon Linux 2023 (kernel 6.18), Docker (arm64) | works (unlimited in the container) | in use
macOS | works | not available on macOS

## What the canary tests prove

Every path that reads or writes a secret or a credential has a canary test. A child JVM gets a random 48-character
canary only through that path, uses it as the provider would (reads it, writes it back, signs and sends with it, over
http and TLS), closes everything and dumps its heap. The test fails if the dump holds any 24-byte fragment of the
canary in ASCII or UTF-8, UTF-16 (either byte order), hex (lower or upper case), Base64 or Base64url. The harness
proves itself too: a canary kept on the heap is found in each encoding.

What the tests prove: no copy on the Java heap, the part of memory a heap dump, the garbage collector or a heap
inspector reaches. What they do not prove: anything about native memory outside guarded memory (OpenSSL's buffers,
the stack), which a heap dump does not contain.
