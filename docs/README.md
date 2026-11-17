# Documentation

- [Getting started](getting-started.md): dependencies, the modules, a first client, choosing a provider
- [The API](api.md): `SecretManagerClient`, configuration, the contract every provider follows, keeping secrets out
  of memory, JPMS
- Providers:
  - [safe-configuration](providers/safe-configuration.md): secrets in a local file, read and write
  - [dynamic-configuration](providers/dynamic-configuration.md): read-only, for tests and migration
  - [google-secret-manager](providers/google-secret-manager.md): Google Secret Manager, read and write
- [Writing a provider](writing-a-provider.md): adding a backend of your own
- [Migrating from 2.x](migrating-from-2.x.md), and from the 0.x versions
