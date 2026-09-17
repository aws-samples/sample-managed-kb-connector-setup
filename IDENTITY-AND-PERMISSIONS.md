# Identity and permissions

This tool provisions identity and access resources. Know what it creates and how
credentials flow before you run it against a real environment.

## Where credentials live

Secrets go to AWS Secrets Manager, never to disk. Client secrets, certificate
passwords, refresh tokens, and API tokens are written to a Secrets Manager
secret that the Knowledge Base role reads at crawl time.

By default that secret is encrypted with the AWS-managed
`aws/secretsmanager` key, which costs nothing and needs no key administration.
Be clear about what that implies: **any principal in the account holding
`secretsmanager:GetSecretValue` on the secret can read the connector's
source-system credentials** — and for SharePoint or OneDrive those credentials
are a tenant-wide read identity. If you want a second authorization gate, pass
`--kms-key-arn` (or set `kms_key_arn` in config) to use a customer-managed key,
whose key policy is then evaluated in addition to IAM. See
[Using a customer-managed key](#using-a-customer-managed-key).

The secret's field layout (`privateKey` and `certificatePassword` in the same
secret) is set by the Bedrock connector contract, not by this tool, so splitting
key material across two secrets isn't available. Least privilege on the secret,
plus optionally a CMK, is the control that matters here.

The state file holds only non-secret identifiers. `kb-connector.state.json`
records KB and data source IDs, role and secret ARNs, and app IDs. No secret
values — that's structural, since only declared fields are serialized and
credential material is held on attributes that never reach the file.

Files the tool writes are mode `0600`. That covers `kb-connector.toml`,
`kb-connector.state.json`, `<connector>.handoff.json`, and probe run artifacts.
None contain secrets, but together they map your environment (tenant ID, app ID,
AWS account IDs, ARNs), and probe output additionally holds data-source
configuration and retrieved document excerpts. Treat a handoff file like a
credential in transit.

For certificate-based SharePoint and OneDrive, the tool generates a self-signed
certificate and RSA key, packages them as a password-protected PKCS#12 bundle,
and uploads it to an S3 bucket with server-side encryption and a public-access
block. If either control can't be applied, setup stops rather than uploading the
private key into a bucket that isn't protected — override with
`--allow-unhardened-cert-bucket` only when equivalent controls are enforced
elsewhere. The certificate password lives in Secrets Manager, and the bucket
holds the only artifact that carries the private key.

## Using a customer-managed key

`--kms-key-arn` (or `kms_key_arn` in config) points the tool at one existing
KMS key. It applies to three things: the connector secret in Secrets Manager,
the PKCS#12 certificate object in S3, and the knowledge base itself.

Bring your own key. The tool never creates, aliases, or deletes a KMS key, and
that is deliberate: a key cannot be deleted immediately, since
`ScheduleKeyDeletion` enforces a waiting period of 7 to 30 days, so a tool that
created one could not honestly clean it up in `teardown`. Create the key
yourself and pass its ARN. Give the ARN of a single key; a wildcard is
rejected, because it would widen the role's grant to every key the allowed
services can reach.

The tool grants the knowledge base role `kms:Decrypt`, `kms:DescribeKey`, and
`kms:GenerateDataKey` on that one key, conditioned on `kms:ViaService` so the
grant only applies when the request arrives through Secrets Manager, S3, or
Bedrock — never as a standalone `Decrypt`. `GenerateDataKey` is there because
encrypting the knowledge base needs the write side of the key, not just the
read side that an encrypted secret needs.

**What the tool does not do is edit your key policy.** A KMS key policy is
authoritative: an IAM grant alone is not enough if the key policy doesn't also
allow the principal. So the key needs a statement for the knowledge base role,
which is named `kb-connector-<connector>-role` unless you set `resource_prefix`
or pass `--kb-role-arn`. Because the role is created during `setup`, the usual
order is to create the key with a policy covering the account root, run
`setup`, then scope the statement to the role ARN it printed:

```json
{
  "Sid": "AllowKbConnectorRole",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::111122223333:role/kb-connector-engineering-sp-role"
  },
  "Action": ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"],
  "Resource": "*"
}
```

`Resource: "*"` inside a key policy means "this key", not every key.

The operator running `setup` needs the key too, since setup writes the
encrypted secret and uploads the encrypted certificate. This is the KMS
statement the scoped caller policy below refers to:

```json
{
  "Sid": "ConnectorKmsKey",
  "Effect": "Allow",
  "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
  "Resource": "arn:aws:kms:us-west-2:111122223333:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

If the key policy is missing the role, the failure shows up as an authorization
error when the knowledge base is created or when a crawl first reads the
secret, not as a configuration error at startup — the tool cannot tell in
advance whether a key policy will admit a role that does not exist yet.

## Endpoints come from your AWS configuration

The tool has no endpoint settings of its own. Every call resolves the endpoint
the way any AWS SDK client does — from the region, and from the standard SDK
configuration if you have set it: `AWS_ENDPOINT_URL`,
`AWS_ENDPOINT_URL_BEDROCK_AGENT`, or `endpoint_url` in your `~/.aws/config`
profile. That is what makes FIPS endpoints, VPC endpoints, and pre-production
testing work without this tool inventing a parallel mechanism.

Worth understanding what that means: every request carries a SigV4 signature
computed from your live credentials, so whatever host the SDK resolves receives
a replayable `Authorization` header along with the request body. That is true
of every client here, not just Bedrock — including Secrets Manager, whose
signed `GetSecretValue` is the one that would expose the connector's source
credentials. Treat your SDK endpoint configuration as security-relevant, and
don't set a global `AWS_ENDPOINT_URL` in a shell profile or CI config for
reasons you can't name.

## What the caller needs

This is an administrative tool. It creates IAM roles and writes IAM policies, so
the identity you run it as is necessarily privileged — `iam:CreateRole` plus
`iam:PutRolePolicy` is enough to escalate to anything the account can do. Run it
as a human operator with an SSO session, not as a long-lived access key, and
don't attach this policy to a service role that other workloads assume.

The permissions below are the full set across every subcommand. `diagnose`,
`monitor`, and `validate` need only the read-only entries.

| Service | Actions | Used by |
|---|---|---|
| STS | `GetCallerIdentity` | all |
| Bedrock Agent | `CreateKnowledgeBase`, `GetKnowledgeBase`, `DeleteKnowledgeBase`, `CreateDataSource`, `GetDataSource`, `DeleteDataSource`, `StartIngestionJob`, `GetIngestionJob`, `ListIngestionJobs`, `StopIngestionJob`, `Retrieve` | setup, monitor, validate, teardown |
| IAM | `GetRole`, `CreateRole`, `TagRole`, `ListRoleTags`, `UpdateAssumeRolePolicy`, `PutRolePolicy`, `GetRolePolicy`, `ListRolePolicies`, `ListAttachedRolePolicies`, `DeleteRolePolicy`, `DeleteRole`, `PassRole` | setup, teardown |
| Secrets Manager | `CreateSecret`, `UpdateSecret`, `DescribeSecret`, `TagResource`, `GetSecretValue`, `DeleteSecret` | setup, diagnose, teardown |
| S3 (cert mode) | `CreateBucket`, `ListBucket`, `GetBucketTagging`, `PutBucketTagging`, `PutBucketPublicAccessBlock`, `PutBucketEncryption`, `PutObject`, `PutObjectTagging`, `DeleteObject` | setup, teardown |
| CloudTrail | `LookupEvents` | diagnose |
| CloudWatch Logs | `FilterLogEvents` | `diagnose --logs` |
| KMS (only with `--kms-key-arn`) | `GenerateDataKey`, `Decrypt`, `DescribeKey` | setup, diagnose |

Three of these are worth explaining, because a narrower policy fails in
confusing ways:

- **`iam:TagRole` / `secretsmanager:TagResource`.** Ownership tags are how the
  tool proves it created a resource before modifying it, and how `teardown`
  decides what is safe to delete. Without these the tool still works — it
  creates resources untagged, warns, and records them in state so later runs
  still recognize them. The cost is that ownership then rests on the state
  file: lose it and reusing those resources needs
  `--adopt-existing-resources`.
- **`secretsmanager:DescribeSecret`.** Read before write: without it the tool
  can't tell whether a secret with the derived name is one of its own, so it
  refuses to overwrite rather than guessing.
- **`s3:GetBucketTagging` and the two bucket-hardening actions.** The
  certificate bucket receives a PKCS#12 file containing a private key. If public
  access can't be blocked and default encryption can't be applied, setup stops
  instead of uploading the key anyway.

<details>
<summary>Scoped caller policy (JSON)</summary>

Replace `<ACCOUNT>` and `<REGION>`. The IAM statements are scoped by role-name
path so the caller can only touch roles this tool names, which is what keeps
`iam:PutRolePolicy` from being a general escalation primitive. Add the KMS
statement only if you use `--kms-key-arn`, and drop the `Delete*` actions if the
operator shouldn't run `teardown`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Identity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    },
    {
      "Sid": "BedrockKnowledgeBaseLifecycle",
      "Effect": "Allow",
      "Action": [
        "bedrock:CreateKnowledgeBase",
        "bedrock:GetKnowledgeBase",
        "bedrock:DeleteKnowledgeBase",
        "bedrock:CreateDataSource",
        "bedrock:GetDataSource",
        "bedrock:DeleteDataSource",
        "bedrock:StartIngestionJob",
        "bedrock:GetIngestionJob",
        "bedrock:ListIngestionJobs",
        "bedrock:StopIngestionJob",
        "bedrock:Retrieve"
      ],
      "Resource": "arn:aws:bedrock:<REGION>:<ACCOUNT>:knowledge-base/*"
    },
    {
      "Sid": "ManageOnlyThisToolsRoles",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "iam:CreateRole",
        "iam:TagRole",
        "iam:ListRoleTags",
        "iam:UpdateAssumeRolePolicy",
        "iam:PutRolePolicy",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "iam:DeleteRolePolicy",
        "iam:DeleteRole"
      ],
      "Resource": "arn:aws:iam::<ACCOUNT>:role/kb-connector-*"
    },
    {
      "Sid": "PassRoleToBedrockOnly",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::<ACCOUNT>:role/kb-connector-*",
      "Condition": {
        "StringEquals": {"iam:PassedToService": "bedrock.amazonaws.com"}
      }
    },
    {
      "Sid": "ConnectorSecrets",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:UpdateSecret",
        "secretsmanager:DescribeSecret",
        "secretsmanager:TagResource",
        "secretsmanager:GetSecretValue",
        "secretsmanager:DeleteSecret"
      ],
      "Resource": "arn:aws:secretsmanager:<REGION>:<ACCOUNT>:secret:kb-connector/*"
    },
    {
      "Sid": "CertificateBucket",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:ListBucket",
        "s3:GetBucketTagging",
        "s3:PutBucketTagging",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketEncryption",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::kb-connector-certs-<ACCOUNT>-<REGION>",
        "arn:aws:s3:::kb-connector-certs-<ACCOUNT>-<REGION>/*"
      ]
    },
    {
      "Sid": "Diagnostics",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

If you use the S3 connector, add `s3:ListBucket` and `s3:GetObject` on the
content bucket. If you point `--cert-s3-bucket` somewhere other than the default
name, adjust the `CertificateBucket` resources to match.

</details>

## The IAM role it creates

The Knowledge Base service role mirrors the least-privilege role the Bedrock
console creates rather than a broad policy:

- Trust limited to `bedrock.amazonaws.com` with `aws:SourceAccount` and an
  `ArnLike` condition on `knowledge-base/*`. Note the wildcard: any knowledge
  base in the same account and Region can assume this role. That matches what
  the console creates, and it means the role is scoped to the account, not to
  one specific KB.
- `cloudwatch:PutMetricData` scoped to the `AWS/Bedrock/KnowledgeBases`
  namespace. (`PutMetricData` takes no resource ARNs, so the namespace
  condition is the scoping mechanism.)
- `secretsmanager:GetSecretValue` on the **specific** secret only.
- (cert mode) `s3:GetObject` and `s3:ListBucket` scoped to the certificate
  object and its bucket, conditioned on your account.
- (S3 connector) `s3:GetObject` on the content bucket, narrowed to
  `inclusion_prefixes` when you set them.
- (with `--kms-key-arn`) `kms:Decrypt` and `kms:DescribeKey` on that key,
  conditioned on `kms:ViaService` for Secrets Manager and S3.

When you attach a connector to an *existing* Knowledge Base, the tool extends
that KB's existing role policy to cover the new secret and certificate rather
than creating a redundant role. It only ever *adds* resource ARNs to statements
it recognizes by `Sid`, and never widens an action. If it finds no statement it
recognizes, it attaches a separate policy named
`kb-connector-supplemental-access` instead of editing one it didn't author, so
you can see exactly what was added.

## Resource ownership and reuse

Resource names are derived from the connector name (`kb-connector-<name>-role`,
`kb-connector/<name>-credentials`), which is predictable — and more than one
person may run this tool in the same account. So every resource the tool creates
is tagged:

```
ManagedBy       = kb-connector
KbConnectorName = <connector name>
```

Before modifying anything that already exists, the tool reads those tags. A role
or secret tagged for *this* connector is updated in place. One that is untagged,
or tagged for a different connector, is left alone and the run stops with an
explanation — overwriting it could replace a trust policy or a credential that
something else depends on. Your options at that point are to pick a different
name (`--kb-role-name`, `--secret-name`), set `resource_prefix` for the
connector in config so all its derived names are distinct, or pass
`--adopt-existing-resources` to take it over deliberately.

One exception: if the tagging permissions were missing when the resource was
created, the tool wrote it untagged and noted that in state. An untagged
resource the state file attributes to this connector is reused rather than
refused, so a missing `iam:TagRole` doesn't strand a resource the tool made
itself. A resource carrying *another* connector's tag is never reclaimed this
way — a tag that is present is stronger evidence than a local file.

That same record decides what `teardown` will delete. Resources the tool created
are marked `tool`, or `tool-untagged` if it couldn't tag them; both are in
teardown's scope. Resources it adopted — an existing KB passed via `--kb`, that
KB's own role, anything taken over with `--adopt-existing-resources` — are marked
`external` and are skipped, listed as "kept", unless you pass
`--include-adopted`. `teardown` also only removes inline policies it authored
(`kb-connector*`), and refuses to delete a role that has managed policies
attached, since that role is being used for something beyond this connector.

`--no-tags` turns tagging off entirely. Setup still works, but it opts out of
the ownership mechanism rather than degrading it: a run that also passes
`--no-tags` reads no tags and so can't attribute anything, and will refuse to
reuse those resources without `--adopt-existing-resources`. A later run
*without* `--no-tags` can still reclaim them from state.

## Per-connector identity model

| Connector | Auth to source | Notes |
|-----------|----------------|-------|
| SharePoint | Entra app (client-credentials) with a certificate | App-only auth requires a certificate (`client_secret` is not usable). ACL crawling requires certificate auth and broader SharePoint permissions. `Sites.Selected` is supported for least-privilege per-site access. The connector also accepts ROPC (a delegated username/password flow), but automating it is out of scope for this tool — see [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md). |
| OneDrive | Entra app (client-credentials): certificate, client secret, or OAuth2 refresh | The connector crawls every user's drive in the tenant, so the app holds `Files.Read.All` across all users. ACL filtering keeps content scoped per-user at retrieve time, but the app token's blast radius is tenant-wide. |
| S3 | None (IAM only) | ACL is a declarative sidecar file in S3. Document-level access control cannot be disabled after the data source is created. |
| Web crawler | None (NO_AUTH) or Basic auth | Crawls public or basic-auth-protected sites. |
| Confluence | Atlassian OAuth2 or Basic (API token) | OAuth2 is not supported with ACL. Use Basic auth for ACL-enabled sources. |
| Google Drive | Google OAuth2 or service account | OAuth2 is not supported with ACL. Use a service account for ACL-enabled sources. |

## Credentials you need (and only when you need them)

You only need credentials for the stage you're running. Stage 1 (source-side)
needs a Microsoft Graph token, and Stage 2 (AWS-side) needs AWS credentials. The
split-admin workflow exists so neither admin needs the other's credentials. If a
token expires mid-run, the tool fails clearly and your progress is saved, so you
can re-authenticate and re-run.

For vulnerability reporting, see [SECURITY.md](SECURITY.md).

