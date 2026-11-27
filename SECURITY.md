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

Anything that breaks the library's promises about secrets ([the security model](docs/security.md)), for example:

- a secret value, or a credential that grants access to secrets (a token or key), on the Java heap on a path the
  library handles, before the caller asks for a copy;
- a secret value in an exception message, `toString`, a cause chain or a log;
- a secret left in memory that the library says it wipes, or an array the caller owns that the library keeps or
  changes;
- guarded memory that is readable outside a callback, swapped, in a core dump or in a forked child where the library
  says it is not;
- a secret file written with wider permissions than documented, or not replaced atomically;
- a request to Google or AWS sent anywhere other than the configured endpoint, a TLS certificate accepted that
  should not be, a plain http request to anything but a loopback address or a documented platform address, or a
  credential loaded from something other than what the configuration and the documented chain name;
- a vulnerability in a dependency that is reachable through this library, including the system's OpenSSL as the
  library uses it.

## Supported versions

Version | Supported
---|---
4.x | yes, from 4.0.0
3.x | yes
2.x and older | no; upgrade ([migration guide](docs/migrating.md))
