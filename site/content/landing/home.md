---
title: "Secrets Client"
description: >-
  A Java library that reads and writes secrets from Google Secret Manager, AWS Secrets Manager, mounted files or a
  local file through one API, and keeps every value and every credential off the Java heap, proven by heap dumps.
eyebrow: "Secrets for Java 25, off the heap, with no third-party dependencies"
headline: "Your secrets never touch the Java heap"
subline: >-
  Read a password from Google Secret Manager, AWS Secrets Manager or a file the platform mounts, through one small
  API. The value lives in guarded native memory, travels over TLS without a heap copy, and is wiped when you are done.
  A heap dump finds nothing.
primary-label: "Get started"
primary-href: "/docs/getting-started/"
secondary-label: "Read the security model"
secondary-href: "/docs/security/"
---

## The problem

A password read the usual way is a `String` or a `byte[]` on the Java heap. It cannot be wiped, the garbage
collector copies it as it moves objects around, and it stays there long after you stopped needing it. A heap dump, a
diagnostic agent or a crash file then shows it in plain text.

The cloud SDKs make it worse. The JDK's TLS decrypts through heap arrays, its `Mac` copies the signing key to the
heap, and JSON libraries turn the response into Strings. The access token, the session token and the secret value all
end up where a heap dump can read them. And every secret store has its own client, its own errors and its own way of
handing values over.

## How the secrets client solves it

One interface, `SecretManagerClient`, reads and writes secrets in every store, and hands values over only as a
`Secret`: a value held in guarded native memory, outside the heap, that you use inside a callback and close when you
are done.

Underneath, the library brings its own small network stack that works on that memory: TLS, SHA-256 and HMAC through
the system's OpenSSL 3, HTTP/1.1, JSON and Base64. Tokens and keys get the same treatment as values, and a credential
source that would put a key on the heap is refused. [The security model](/docs/security/)

## Your secret lives in guarded memory

Each value sits in pages of native memory that the garbage collector never sees. Guard pages before and after each
slab fault on an overrun. The pages are closed to every access (`PROT_NONE`) except while your callback runs, locked
so they are never written to swap, and left out of core dumps and forked child processes. On Linux 5.14 and later they
are taken out of the kernel's own direct map with `memfd_secret`. A `Secret` is wiped when you close it, when its
client closes, and, if you forget it, when the garbage collector finds it unreachable.
[Guarded memory](/docs/api/#guarded-memory-secretmemory-and-secret)

## Use the value, then it is gone

You reach the value only inside a callback. `withSegment` gives the native memory itself, read-only, with no copy.
`withChars` and `withBytes` give a copy on the heap for APIs that need an array, and zero it the moment the callback
returns. Outside the callback, the pages are closed again.
[The API](/docs/api/)

<!-- label: Hand the value to an API that does not keep it -->
```java
try (Secret password = client.read("keystore-password")) {
    password.withChars(chars -> {                   // a heap copy, zeroed on return
        keyStore.load(input, chars);
        return null;
    });
}                                                   // the Secret is wiped here
```

<!-- label: Or use the native memory itself, with no copy -->
```java
int crc = key.withSegment(segment -> checksum(segment));
```

## TLS that never touches the heap

The Google and AWS providers speak HTTPS through the system's OpenSSL 3, called through Java's Foreign Function and
Memory API, not through the JDK's `SSLEngine`. Each request is built in guarded memory, with the access token in its
header, and OpenSSL encrypts straight out of it. Each response is decrypted straight into guarded memory, its JSON read
in place, and the value decoded from Base64 into the `Secret` you get back. AWS's SigV4 signature is computed there
too, with HMAC-SHA256 from libcrypto. [Protocols](/docs/protocols/)

## Credentials get the same care

The tokens and keys that grant access to your secrets are held in guarded memory, refreshed before they expire, and
wiped when the client closes. They come from where the platform gives them: Google's metadata server on Cloud Run,
GKE and Compute Engine; the task role on ECS, EKS Pod Identity, or IMDSv2 on EC2; a developer's own login on a
laptop. A source the JVM would keep as a heap `String` for its whole life, such as AWS keys in environment variables,
is refused at startup with a message that says why. [Deployment models](/docs/deployment/)

<!-- label: On ECS: the task role, and nothing else -->
```java
SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "aws-secrets-manager",
        "secrets.region", "eu-north-1",
        "secrets.credentials", "container"));
```

## One API, the backend you choose

The provider is picked by configuration, so the same code reads a local file on your laptop and a cloud secret
manager in production. A missing secret, a closed client and a write the store cannot do are reported the same way by
every provider. [Choosing a provider](/docs/getting-started/#choosing-a-provider)

### Google Secret Manager

Read and write over the REST API, with a CRC32C checksum both ways, and create a secret on its first write. The
metadata server's token in production, your `gcloud` login in development; service-account keys are refused.
[The provider](/docs/providers/google-secret-manager/)

### AWS Secrets Manager

Read and write over the JSON API, signed with SigV4, by version ID or staging label. Credentials from ECS, EKS Pod
Identity, EC2 or a shared credentials profile. No AWS SDK on your class path.
[The provider](/docs/providers/aws-secrets-manager/)

### Mounted files

Read secrets that Cloud Run, Kubernetes or the Secrets Store CSI driver mount as files. No credential and no network
code in your process, and a rotated file is seen at the next read. [The provider](/docs/providers/mounted/)

### A local file

A `key=value` file for development and tests, read, parsed and rewritten in guarded memory, written back atomically
and readable only by you. [The provider](/docs/providers/safe-configuration/)

## Nothing else on your class path

The secrets client depends on no third-party library. No AWS SDK, no Google Cloud client, no gRPC, no Netty, no
Jackson, no Bouncy Castle. TLS, HTTP/1.1, JSON, Base64, SigV4 and the OAuth and metadata calls are the library's own
code, on the JDK and the system's OpenSSL 3. Your application gets the API, the provider it uses, and Descoped's
9 KB [service-provider-api](https://github.com/descoped/service-provider-api): nothing to patch when a transitive dependency has a CVE, and nothing that keeps a secret
on the heap behind your back. [Architecture](/docs/architecture/)

<!-- label: mvn dependency:tree, the AWS provider at runtime -->
```text
io.descoped.secrets:secrets-provider-aws-secrets-manager:jar
\- io.descoped.secrets:secrets-client-api:jar
   \- io.descoped.spi:service-provider-api:jar
```

## Proven by dumping the heap

Every path that reads or writes a secret or a credential has a canary test. A separate JVM receives a random canary
only through the public API, uses it as an application would, and dumps its whole heap. The dump is searched for the
canary in seven encodings, from ASCII to Base64url, and one hit fails the build. The harness proves itself as well: a
canary deliberately left on the heap is found in every encoding. The live tests pass on Google Cloud Run, AWS ECS on
Fargate and AWS EC2. [What the canary tests prove](/docs/security/#what-the-canary-tests-prove)

## Add it to your project

Import the BOM, compile against the API, and add the providers you use at runtime: they are found by `ServiceLoader`
on the module path and the class path. Start the JVM with native access for the API module; without it, a client
refuses to start rather than run unguarded. The modules below take their version from the BOM, whose import and
current version are in [Getting started](/docs/getting-started/).

<!-- label: pom.xml -->
```xml
<dependency>
    <groupId>io.descoped.secrets</groupId>
    <artifactId>secrets-client-api</artifactId>
</dependency>
<dependency>
    <groupId>io.descoped.secrets</groupId>
    <artifactId>secrets-provider-google-secret-manager</artifactId>
    <scope>runtime</scope>
</dependency>
```

<!-- label: The JVM -->
```sh
java --enable-native-access=io.descoped.secrets.api -m my.app/my.app.Main
```

## Read your first secret

Create a client from a map, read a secret, use it, and close both. The `try` closes the `Secret`, which wipes it, and
then the client, which wipes everything it still holds. Change `secrets.provider` and its keys, and the same code reads
from another store.

<!-- label: Read a secret from Google Secret Manager -->
```java
try (SecretManagerClient client = SecretManagerClient.create(Map.of(
        "secrets.provider", "google-secret-manager",
        "secrets.project-id", "my-project"));
     Secret apiKey = client.read("payments-api-key")) {
    apiKey.withChars(chars -> {
        payments.authenticate(chars);
        return null;
    });
}
```

## Learn how it works

The documentation follows a secret from your configuration to the wire and back.
[The documentation](/docs/)

### Architecture and protocols

The modules and their layers, where a secret lives in each, and the TLS, HTTP, SigV4, OAuth and metadata protocols
as the library speaks them. [Architecture](/docs/architecture/) · [Protocols](/docs/protocols/)

### Topology and deployment

What the process talks to on Google Cloud and AWS, what crosses the network, and how to run it on a laptop, Cloud
Run, GKE, ECS, EKS and EC2. [Topology](/docs/topology/) · [Deployment models](/docs/deployment/)

### Sequence flows

Every read, write and credential fetch step by step, with where the secret is at each step.
[Sequence flows](/docs/sequence-flows/)
