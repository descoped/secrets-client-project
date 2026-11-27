---
title: Overview
description: The documentation of the Descoped secrets client, a Java library that keeps secrets and the credentials to them off the Java heap.
order: 1
---

# Documentation

The secrets client reads and writes secrets through one API, `SecretManagerClient`, from Google Secret Manager, AWS
Secrets Manager, files the platform mounts or a local file. Every value, and every token and key that grants access
to one, is kept in guarded native memory, never on the Java heap, and a heap-dump test proves it for every path.

Start here:

- [Getting started](getting-started.md): dependencies, the modules, a first client, choosing a provider
- [The API](api.md): `SecretManagerClient`, configuration, the contract every provider follows, keeping secrets out
  of memory, guarded memory (`SecretMemory`, `Secret`), JPMS

How it works:

- [Architecture](architecture.md): the modules, the layers inside the API module, and where a secret lives in each
- [Protocols](protocols.md): TLS, HTTP/1.1, the Google and AWS APIs, SigV4, OAuth and the credential endpoints, as
  the library speaks them
- [Topology](topology.md): what the process talks to for each provider, what crosses the network, trust boundaries
- [Deployment models](deployment.md): running on a laptop, Cloud Run, GKE, ECS, EKS, EC2 and in tests
- [Sequence flows](sequence-flows.md): every read, write and credential fetch step by step
- [The security model](security.md): what is protected and where protection ends, credentials, what the platform
  must provide, what the canary tests prove

Providers:

- [google-secret-manager](providers/google-secret-manager.md): Google Secret Manager, read and write
- [aws-secrets-manager](providers/aws-secrets-manager.md): AWS Secrets Manager, read and write
- [mounted](providers/mounted.md): secrets the platform mounts as files, read-only
- [safe-configuration](providers/safe-configuration.md): secrets in a local file, read and write

More:

- [Writing a provider](writing-a-provider.md): adding a backend of your own
- [Migrating](migrating.md): from 3.x to 4.0, from 2.x, and from the 0.x versions
- [Roadmap](roadmap.md): what is planned but not done
- [Releasing](releasing.md): how a version is released, for maintainers
