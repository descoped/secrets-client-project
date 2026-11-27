# Roadmap

Work that is planned but not done. Each item keeps the library's promise: no secret or credential on the Java heap,
proven by a canary test, with the same contract for every provider.

## AWS

- **Web identity (EKS IRSA).** Credentials from STS `AssumeRoleWithWebIdentity`, with the token read from
  `AWS_WEB_IDENTITY_TOKEN_FILE` and the response parsed in guarded memory, like the other sources. Today the default
  chain refuses `AWS_WEB_IDENTITY_TOKEN_FILE` and points to EKS Pod Identity, which is supported.
- **The shared credentials file against real AWS.** The container endpoint (ECS) and instance metadata (EC2, IMDSv2)
  have passed the live test on AWS. The shared credentials file has been tested only against `FakeAws`; one
  `just live-aws` run with a profile covers it.
- **A live run on EKS.** EKS Pod Identity (the container endpoint with an authorization token file) and the
  `mounted` provider through the Secrets Store CSI driver have been tested only locally, not on a real cluster.

## Later

- A cache with a time-to-live, holding `Secret`s in guarded memory.
- A HashiCorp Vault provider, only if there is a use for it.
