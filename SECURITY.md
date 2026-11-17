# Security

This library handles secrets, so a flaw in it can expose them. Please report a vulnerability privately.

## Reporting

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/descoped/secrets-client-project/security/advisories/new). Do not open a
public issue or pull request for it.

Include the version, the provider, what a secret could leak to or how it could be changed, and how to reproduce it.
You will get an answer as soon as possible, and the fix is published with an advisory that credits you, unless you
prefer otherwise.

## What counts

Anything that breaks the library's promises about secrets, for example:

- a secret value in an exception message, `toString`, a cause chain or a log;
- a secret left in memory that the library says it wipes, or an array the caller owns that the library keeps or
  changes;
- a secret file written with wider permissions than documented, or not replaced atomically;
- a request to Google sent anywhere other than the configured https endpoint, or a credential loaded from something
  other than what the configuration names;
- a vulnerability in a dependency that is reachable through this library.

## Supported versions

Version | Supported
---|---
3.x | yes
2.x and older | no; upgrade to 3.x ([migration guide](docs/migrating-from-2.x.md))
