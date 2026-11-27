# Documentation

- [Getting started](getting-started.md): dependencies, the modules, a first client, choosing a provider
- [The API](api.md): `SecretManagerClient`, configuration, the contract every provider follows, keeping secrets out
  of memory, guarded memory (`SecretMemory`, `Secret`), JPMS
- [The security model](security.md): what is protected and where protection ends, credentials, what the platform
  must provide, what the canary tests prove
- Providers:
  - [safe-configuration](providers/safe-configuration.md): secrets in a local file, read and write
  - [google-secret-manager](providers/google-secret-manager.md): Google Secret Manager, read and write
  - [mounted](providers/mounted.md): secrets the platform mounts as files, read-only
  - [aws-secrets-manager](providers/aws-secrets-manager.md): AWS Secrets Manager, read and write
- [Writing a provider](writing-a-provider.md): adding a backend of your own
- [Releasing](releasing.md): how a version is released, for maintainers
- [Migrating](migrating.md): from 3.x to 4.0, from 2.x, and from the 0.x versions
