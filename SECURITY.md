# Security Policy

## Reporting a Vulnerability

If you discover a potential security issue in this project, we ask that you
notify AWS/Amazon Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/)
or directly via email to aws-security@amazon.com.

Please do **not** create a public GitHub issue for security vulnerabilities.

## Threat Model

[THREAT-MODEL.md](THREAT-MODEL.md) documents the trust boundaries, the threats
considered, and which are mitigated in code versus accepted and documented. Read
it before running this tool against a production tenant or account, and update it
when changing credential handling, resource provisioning, or the MCP surface.

## How This Tool Handles Credentials

This is an administrative tool, so it necessarily touches sensitive material.
Knowing how it handles that material is part of using it safely.

**It is more privileged than a typical AWS sample.** A single `setup` run
registers an application in your Microsoft Entra tenant, grants it tenant-wide
read permissions with admin consent, generates private key material, and creates
IAM roles. The caller needs `iam:CreateRole` and `iam:PutRolePolicy`, which
together are enough to escalate within the account. Run it as a human operator
with an SSO session, using the
[scoped caller policy](IDENTITY-AND-PERMISSIONS.md#what-the-caller-needs) — not as a long-lived
access key and not as a role other workloads can assume.

Secrets at rest live in AWS Secrets Manager, not on disk. The tool writes
connector credentials (client secrets, certificate passwords, refresh tokens,
API tokens) to AWS Secrets Manager. The state file (`kb-connector.state.json`)
stores only non-secret identifiers: KB IDs, data source IDs, role ARNs, secret
ARNs, and app IDs. No secret values are written to state — that is structural,
since only declared dataclass fields are serialized and credential material is
held on attributes that never reach the file.

By default the secret uses the AWS-managed `aws/secretsmanager` key. That means
**any principal in the account with `secretsmanager:GetSecretValue` on the secret
can read the connector's source-system credentials**, which for SharePoint and
OneDrive is a tenant-wide read identity. Pass `--kms-key-arn` to add a
customer-managed key whose key policy is evaluated in addition to IAM. The
secret's field layout is set by the Bedrock connector contract, so splitting key
material across separate secrets is not available to us.

For certificate-based connectors, the tool generates a PKCS#12 bundle, uploads
it to an S3 bucket with server-side encryption and a public-access block, and
references it by `certificateS3Path`. If those protections cannot be applied,
setup stops rather than uploading the private key anyway. The private key
material exists transiently in memory during setup and in the S3 object. The
certificate password is stored in Secrets Manager.

Files the tool writes are mode `0600` — the config file, state, handoff
documents, and probe artifacts. None contain secret values, but together they map
your environment (tenant ID, application IDs, AWS account IDs, ARNs), and probe
artifacts also hold data-source configuration and retrieved document excerpts.
Treat a handoff file like a credential in transit and delete it after use.

The config file may contain environment-specific identifiers like tenant IDs and
resource names. Both `kb-connector.toml` and `kb-connector.state.json` are
gitignored by default. Do not commit them.

IAM roles follow least privilege. The KB service role the tool provisions is
scoped to the specific secret, certificate object, and CloudWatch namespace it
needs, mirroring the AWS console-created role rather than a broad policy. Two
details worth knowing: its trust policy conditions on `aws:SourceAccount` and
`aws:SourceArn` with an `ArnLike` on `knowledge-base/*`, so any knowledge base in
the same account and Region can assume it (this matches the console-created role);
and for the S3 connector the content-bucket grant is narrowed to
`inclusion_prefixes` when you set them.

Resources the tool creates are tagged `ManagedBy=kb-connector` and
`KbConnectorName=<connector>`. Those tags are how it proves ownership before
modifying an existing role, secret, or bucket, and how `teardown` decides what is
safe to delete. Where the caller lacks the tagging permissions, the resource is
created untagged and recorded as such in state, which a later run uses to
recognize it; a resource carrying another connector's tag is never reclaimed that
way. Resources the tool adopted rather than created are recorded as external and
are not deleted unless you pass `--include-adopted`.

Endpoints come from your AWS SDK configuration, not from tool-specific
settings. Every request is SigV4-signed with your live credentials, so
whichever host the SDK resolves receives a replayable authorization header —
treat `AWS_ENDPOINT_URL` and `endpoint_url` in `~/.aws/config` as
security-relevant settings.

Diagnostics output may contain identifiers. When sharing the output of
`diagnose` or `validate`, including `--json`, scrub tenant IDs, account IDs, and
resource ARNs as appropriate for your environment. Document paths in
`diagnose --logs` are redacted by default for this reason.

For the full identity and trust model per connector, see the
[IDENTITY-AND-PERMISSIONS.md](IDENTITY-AND-PERMISSIONS.md).
