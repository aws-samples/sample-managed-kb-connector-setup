# KB Connector Helper

A command-line tool for setting up, monitoring, validating, and diagnosing
**Amazon Bedrock Knowledge Base** data source connectors across every supported
managed connector type.

Setting up a managed Knowledge Base connector by hand means wiring together an
identity provider (Entra, Google Workspace, Atlassian), a Secrets Manager
secret, an S3 certificate, an IAM role with exactly the right policy, and a
Knowledge Base and data source whose `connectorParameters` shape has to be
exactly right. This tool does that for you. It also tells you why a connector is
failing when one does, which is usually the harder problem.

> **Status:** This is an AWS sample, not a managed service. See
> [What's supported](#whats-supported) and
> [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) for what's exercised and what
> still has rough edges.

---

## What it does

Five commands cover the connector lifecycle, and each works across every
supported connector:

| Verb | What it does |
|------|--------------|
| **setup** | Configures the source-side identity provider where possible, then creates the AWS resources: secret, certificate, IAM role, Knowledge Base, and data source. |
| **monitor** | Starts an ingestion job and polls it to completion, reporting full document statistics. |
| **validate** | Confirms a connector actually works. For ACL-enabled connectors runs an authorized / denied / no-user retrieve trio against the knowledge base. For non-ACL connectors, a single retrieve. |
| **diagnose** | Explains why a failing connector is failing: ingestion log analysis, CloudTrail permission checks, secret validation, certificate expiry. |
| **teardown** | Cleans up the resources the tool created, conservatively and with a dry-run. |

There's also **init** (interactive config builder) and **handoff** (for
split-admin workflows where the identity admin and the AWS admin are different
people).

## What's supported

**Connectors**

| Connector | Source-side setup | AWS-side setup |
|-----------|-------------------|----------------|
| SharePoint | Automated (Microsoft Entra) | Automated |
| OneDrive | Automated (Microsoft Entra) | Automated |
| S3 | None needed | Automated |
| Web crawler | None needed (NO_AUTH) / secret (BASIC_AUTH) | Automated |
| Confluence | Guided (Atlassian) | Automated |
| Google Drive | Guided (Google Workspace) | Automated |

**Targets** (`target` in config, or `--target`):

| Target | What it does | Status |
|--------|--------------|--------|
| `bmkb` (default) | Amazon Bedrock managed Knowledge Bases. Full setup through to an ingestion job | Complete |
| `quick` | Amazon Quick. Service credentials for SharePoint and OneDrive | Partial, see [Amazon Quick target](#amazon-quick-target) |

Everything below assumes the default `bmkb` target unless it says otherwise.

---

## Install

Requires **Python 3.11+**.

```bash
pip install -e .
# or, for development (tests, linting):
pip install -e ".[dev]"
# add the MCP server (optional):
pip install -e ".[mcp]"
```

`[dev]` and `[mcp]` are pip *optional-dependency groups* (extras), not paths —
the `.` is the current project and the bracketed name selects the extra to
install alongside it. The quotes keep your shell from interpreting the brackets.

This installs the `kb-connector` command, plus `kb-connector-mcp` if you
included the `mcp` extra:

```bash
kb-connector --help
kb-connector --version
kb-connector-mcp           # starts a stdio MCP server (see below)
```

You need AWS credentials configured (via `~/.aws/config`, environment, or an
SSO/assumed-role session) for the account where your Knowledge Base lives. This
tool creates IAM roles and writes IAM policies, so the caller needs more than
read access — see [What the caller needs](#what-the-caller-needs) for the exact
permission set and a ready-to-use scoped policy. For SharePoint and OneDrive you
also authenticate to Microsoft Graph, either by borrowing your Azure CLI session
or using a device-code flow.

For the Azure CLI flow, install `az` if you don't have it (macOS:
`brew install azure-cli`; other platforms: see [Microsoft's install
guide](https://learn.microsoft.com/cli/azure/install-azure-cli)).
Authenticate once with `az login`. If you can't or don't want to install
`az`, pass `--auth-method device_code` to `setup` (and `teardown`); the
tool prints a URL and code to authenticate through your browser instead.

Stage 1 against Microsoft Entra requires a directory role that can register
applications and grant admin consent for application permissions. **Global
Administrator** is the simplest; **Application Administrator** or **Cloud
Application Administrator** also work. Without one of these roles, app
creation or admin consent will return a 403 from Graph. The same roles are
sufficient for `teardown`'s app deletion.

---

## Quick start

This walkthrough uses the **web crawler**, which has the fewest prerequisites:
it needs only AWS credentials and a public URL — no external identity provider,
no `az login`, no S3 bucket to prepare. SharePoint and OneDrive (which require a
Microsoft Entra tenant) are shown as a follow-on under
[Configuration](#configuration).

```bash
# 1. Create a config. Either run the interactive builder, or copy the
#    example file and edit it (often faster).
kb-connector init                       # interactive
# or
cp kb-connector.example.toml kb-connector.toml

# 2. Edit the 'docs-site' connector in your new kb-connector.toml and point
#    seed_urls at a site you own or may crawl. The shipped value is a
#    placeholder, so skipping this indexes nothing.

# 3. Set up the connector and start the first ingestion in one go.
kb-connector setup docs-site --sync

# 4. Confirm it works (single retrieve for non-ACL connectors).
kb-connector validate docs-site

# 5. If something's wrong, find out why.
kb-connector diagnose docs-site
```

The `docs-site` connector the commands above refer to is the one section the
example config leaves uncommented, so a fresh copy resolves it:

```toml
[defaults]
region = "us-west-2"

[connectors.docs-site]
type = "web"
seed_urls = ["https://docs.example.com"]
crawl_depth = 2
# sync_scope controls how far the crawler follows links. Valid values:
#   PATH_SPECIFIC, SUB_DOMAINS, ALL_DOMAINS, DOMAINS_ONLY
# sync_scope = "SUB_DOMAINS"
```

Once the web crawler works, the SharePoint example below adds the
identity-provider pieces.

`--sync` is opt-in. Without it, `setup` stops after the data source becomes
available and prints a hint pointing at `kb-connector monitor <name>` for the
ingestion run. You'd skip `--sync` if you wanted to tweak inclusion or
exclusion filters before the first crawl.

To diagnose a connector someone else set up, pass the resource IDs directly. No
config file required:

```bash
kb-connector diagnose --kb ABCD1234 --ds XYZ5678 --region us-west-2
```

---

## Configuration

Configuration is **TOML-first**. One file holds all your connectors and shared
defaults. Copy [`kb-connector.example.toml`](kb-connector.example.toml) to
`./kb-connector.toml`, or run `kb-connector init`.

```toml
[defaults]
region = "us-west-2"

[defaults.microsoft]
tenant_id = "xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx"

[connectors.engineering-sp]
type = "sharepoint"
credential = "cert"
acl = true
sharepoint_host = "contoso.sharepoint.com"
site_urls = ["https://contoso.sharepoint.com/sites/engineering"]
# Least-privilege alternative to the default tenant-wide grant: the app can
# only reach sites you explicitly grant it. Off by default because each site
# needs its own grant, including any you add later.
sites_selected = false

# Optional. validate uses these to drive the ACL retrieve trio.
[connectors.engineering-sp.validation]
query = "team roadmap"
authorized_user = "alice@example.com"
unauthorized_user = "outsider@example.com"
```

> **SharePoint `site_urls` must be `/sites/<name>` paths**, not the tenant root
> URL. `https://contoso.sharepoint.com` (the root communication site) resolves
> fine in Graph but the connector rejects it — ingestion fails with "URLs
> provided for sync is/are invalid". Use
> `https://contoso.sharepoint.com/sites/<name>` for each site you want crawled.

> **SharePoint requires `credential = "cert"`.** The connector requires a
> certificate for app-only auth, so `client_secret` is not a usable SharePoint
> mode.

Two optional keys matter when more than one person uses this tool in the same
AWS account, or when you want stricter encryption:

```toml
[connectors.engineering-sp]
# Prefix every derived resource name (role, secret, KB, data source) so two
# teams can both have a connector called "engineering-sp" without colliding on
# `kb-connector-engineering-sp-role`.
resource_prefix = "platform"

# Encrypt the connector secret and certificate object with your own KMS key
# instead of the AWS-managed one. Adds a key-policy gate on top of IAM; the KB
# role is granted kms:Decrypt on it automatically. Costs a monthly key charge.
kms_key_arn = "arn:aws:kms:us-west-2:111122223333:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Note that the web connector's `username` / `password` keys still work but now
warn: `setup` prompts for the password with `getpass` when it isn't in config,
which keeps a live credential out of a plaintext file sitting in your project
directory. Omit `password` unless you're running unattended.

**Resolution precedence** (highest wins):

```
CLI flag  >  [connectors.<name>]  >  [defaults]  >  environment variable
```

A value in your TOML always beats the matching environment variable, so the two
never conflict. Environment variables are an optional, low-priority fallback
that's handy in CI. See [`.env.example`](.env.example) for the variables
honored.

The tool looks for your config in three places, in order: an explicit
`--config <path>`, then `./kb-connector.toml` (the primary, expected location),
then `~/.config/kb-connector/config.toml` for user-global defaults.

### Your own tags, and sharing an account

Every resource the tool creates carries `ManagedBy=kb-connector` and
`KbConnectorName=<connector>`. That's how a later run knows whether it created
the role or secret it's about to modify, and how `teardown` knows what is safe
to delete.

If your organization mandates its own tags — and especially if a service control
policy or tag policy *denies* creates that lack them — add a `[tags]` table.
These are applied to every resource the tool creates, and merge across
`[defaults.tags]` and `[connectors.<name>.tags]` with the connector winning
per key:

```toml
[defaults.tags]
CostCenter = "1234"
Owner = "platform-team"

[connectors.engineering-sp.tags]
Owner = "alice"          # overrides the default for this connector
DataClassification = "internal"
```

`ManagedBy` and `KbConnectorName` are reserved — setting them is rejected rather
than ignored, since a config file must not be able to forge the ownership
record. Tag keys using the `aws:` prefix are rejected too.

Two related knobs:

- **`resource_prefix`** prefixes the derived secret and role names. If several
  people or teams run this tool in one account, give each a distinct prefix so
  `kb-connector-<name>-role` can't collide. This is the right control when you
  *can't* tag at all, because it removes the collision rather than detecting it
  afterwards. Note it applies to the secret and role, not to the shared
  certificate bucket (which is per-account/region by design).
- **`--no-tags`** skips tagging entirely. It doesn't skip the ownership *check* —
  with no tags to read, later runs can't verify ownership and will refuse to
  reuse what they find unless you also pass `--adopt-existing-resources`. If
  tagging isn't available to you, prefer `resource_prefix`.

### Config vs. state

The config is your intent, the thing you want set up. A separate
`kb-connector.state.json` records what was actually created (KB IDs, data source
IDs, role and secret ARNs), like Terraform state. `teardown` reads it to know
what to remove, and `monitor`, `validate`, and `diagnose` read it so you don't
have to re-type resource IDs. Both files are gitignored by default.

---

## Commands

Every command accepts a connector name (resolved from your config) or explicit
resource IDs, and supports `--json` for machine-readable output.

### `setup`

Setup runs in two stages. It's idempotent and resumable, so re-running picks up
where it left off and skips completed steps.

Stage 1 (source-side) configures the identity provider. For SharePoint and
OneDrive this is fully automated against Microsoft Graph: app registration,
permissions and admin consent, certificate, and optional `Sites.Selected`
per-site grants. The running user needs a directory role that can register
apps and grant admin consent (Global Administrator, Application Administrator,
or Cloud Application Administrator). For Confluence and Google Drive Stage 1
is guided, meaning the tool tells you exactly what to create in the provider
console and then collects the credentials.

Stage 2 (AWS-side) is always automated. It writes the secret, uploads the
certificate, creates or extends the IAM role, creates the Knowledge Base and
data source, and waits for them to become active.

When both stages run together, setup runs an **ownership preflight** first: a
read-only check of whether it owns the AWS resources it's about to touch, which
stops the run before any Entra work if it doesn't. Registering an app and
consenting its permissions can't be undone, so a run that would be refused on the
AWS side shouldn't leave those behind. You'll see every conflicting resource at
once, each with the reason and the ways forward. A standalone `--stage 1` skips
the preflight, since it has no AWS credentials by design — and for SharePoint and
OneDrive it is refused outright, because the credential Stage 1 creates cannot
reach Stage 2 in another process.

If `cert_s3_bucket` isn't set in your config, setup derives a default name
from the AWS account and region (`kb-connector-certs-<account>-<region>`),
creates the bucket if it's missing, and applies SSE plus a public-access block
since the bucket holds the private key. Setting an explicit bucket overrides
the default.

For connector parameters the curated builder doesn't surface (SharePoint
`filterConfiguration`, OneDrive `inclusionPatterns`, anything advanced),
add a `[connectors.<name>.connector_params_overrides]` table; the dict
deep-merges onto the built params before the data source is created. See
[KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) for the full discussion.

```bash
kb-connector setup engineering-sp                 # both stages
kb-connector setup engineering-sp --sync          # plus first ingestion
kb-connector setup engineering-sp --rotate-cert    # issue a new certificate
kb-connector setup engineering-sp --kb EPS06WSNZU # attach to an existing KB

# Encrypt the secret + certificate with your own KMS key instead of the
# AWS-managed one (adds a key-policy gate; the KB role gets kms:Decrypt on it):
kb-connector setup engineering-sp --kms-key-arn arn:aws:kms:us-east-1:111122223333:key/abc

# Take over a pre-existing role/secret whose ownership can't be verified:
kb-connector setup engineering-sp --adopt-existing-resources
```

Created resources are tagged `ManagedBy=kb-connector` and
`KbConnectorName=<name>`. Setup refuses to modify an existing role, secret, or
certificate bucket that those tags don't attribute to this connector — see
[Resource ownership and reuse](#resource-ownership-and-reuse). If several people
run this tool in one account, set `resource_prefix` per connector so derived
names can't collide.

### `monitor`

```bash
kb-connector monitor engineering-sp               # start a sync + poll to done
kb-connector monitor engineering-sp --no-start    # poll the latest job
```

Reports scanned, indexed, failed, and skipped counts. It flags the common case
where ACL is enabled but the connector app can't read item-level permissions,
which shows up as documents scanned but skipped instead of indexed.

### `validate`

For non-ACL connectors, validate runs a single retrieve check against the
knowledge base.

For ACL-enabled connectors, validate runs three retrieves to confirm the access
filter is actually doing its job:

| Check | userContext | Expected result |
|-------|-------------|-----------------|
| `retrieve_authorized` | the authorized user | non-zero (proves indexing + ACL allow path) |
| `retrieve_denied` | a user with no access | zero (proves ACL deny path) |
| `retrieve_no_user` | none | zero (proves ACL is enforced when no user is supplied) |

Test inputs come from an optional `[validation]` block on the connector:

```toml
[connectors.engineering-sp.validation]
query = "team roadmap"
authorized_user = "alice@example.com"
unauthorized_user = "outsider@example.com"
```

CLI flags `--query`, `--user-id`, and `--unauthorized-user-id` override.

```bash
kb-connector validate engineering-sp
kb-connector validate --all                       # every connector in config
kb-connector validate engineering-sp --query "compensation policy"
```

### `diagnose`

```bash
kb-connector diagnose engineering-sp
kb-connector diagnose engineering-sp --json | jq  # for CI / tickets
kb-connector diagnose engineering-sp --logs       # + per-document log analysis
```

Runs the shared diagnostic checks: a CloudTrail `AccessDenied` scan, secret
validation, and certificate expiry. Results are attributed to a side, source or
AWS, so each admin knows whose problem it is.

`--logs` adds ingestion log analysis, which is what explains a
scanned-vs-indexed gap: it reads the knowledge base's per-document
`APPLICATION_LOGS` events from CloudWatch and groups them by status and reason,
so "scanned 400, indexed 40" becomes a short list of causes. It's opt-in because
it needs vended log delivery configured on the knowledge base plus
`logs:FilterLogEvents`. The log group defaults to
`/aws/bedrock/knowledgebases/<kb-id>`; override with `--log-group`.

Document paths in that output are redacted, because diagnose output gets pasted
into tickets. Filenames are replaced with `<redacted>.<ext>`, query strings and
any userinfo are dropped, and deep paths are elided to the host plus one leading
segment. The service-supplied failure reasons are scrubbed the same way, since
they routinely embed the document URL and also feed the "actionable issues"
lines. `--no-redact` shows everything in full for local use; the MCP tool always
redacts.

An identifier with no file extension and no URL form — a bare document ID, or a
title carried as prose in a service message — can't be recognized in free text
and isn't redacted. Give any log excerpt a read before sharing it.

### `teardown`

```bash
kb-connector teardown engineering-sp --dry-run    # show what would be deleted
kb-connector teardown engineering-sp              # prompts for confirmation
kb-connector teardown engineering-sp --only ds    # just the data source
kb-connector teardown engineering-sp --force      # stop in-progress sync first
```

Conservative by default: it only deletes resources recorded in state, and it
prompts before each destructive action unless you pass `--yes`. If an
ingestion job is in progress on the data source, teardown refuses (rather
than yanking credentials out from under a running crawl). `--force` calls
`StopIngestionJob` first, waits briefly for a terminal state, then proceeds.
If the data-source or knowledge-base delete fails, teardown stops before
deleting the upstream credentials so the resources can be cleaned up on a
later pass.

Resources the tool *adopted* rather than created are skipped and listed as
"kept". That's what protects a knowledge base you attached to with `--kb`, and
the IAM role that KB already had, from being deleted along with the connector.
Pass `--include-adopted` to delete them too. On a role, teardown removes only the
inline policies it authored (`kb-connector*`) and refuses outright if managed
policies are attached, since that means something else is using the role.

Note that secrets are deleted with `ForceDeleteWithoutRecovery`, so there's no
7-day recovery window. That's deliberate — it lets you re-run `setup` under the
same connector name immediately — but don't use `teardown` if you want the
secret recoverable.

---

## Split-admin workflow (`handoff`)

Many enterprises separate the identity admin (Microsoft, Atlassian, Google) from
the AWS admin, and the tool supports that split directly.

```bash
# Identity admin runs Stage 1, then exports for the AWS admin:
kb-connector setup engineering-confluence --stage 1
kb-connector handoff engineering-confluence --to aws   # writes the handoff JSON

# AWS admin imports it and runs Stage 2:
kb-connector setup engineering-confluence --from-handoff ./engineering-confluence.handoff.json --stage 2

# Reverse direction (AWS admin shares KB/DS IDs back so the identity admin can validate):
kb-connector handoff engineering-confluence --to source
```

The handoff file carries only what the next person needs, the IDs and non-secret
configuration. It never pulls secrets out of AWS, and it never carries a
credential.

That last point bounds where the split applies. It works for connectors whose
credential is supplied to Stage 2 directly — Confluence, Google Drive, and web
basic auth, where the AWS admin enters the token or password when Stage 2 prompts
for it.

It does not complete the setup for SharePoint or OneDrive in any credential mode.
Stage 1 creates the credential there — a certificate private key, or a client
secret — and holds it only in memory, so Stage 2 in a second process has nothing
to store in Secrets Manager. `setup --stage 1` is refused for those connectors
rather than left to half-run; use `--stage both` in one process, where the
credential passes between stages in memory. See KNOWN-LIMITATIONS.md for what to
do when the two roles must be different people.

`handoff` is still worth running for SharePoint and OneDrive for what it does
carry: tenant and app IDs out to the AWS admin, and knowledge base and data
source IDs back, so each side can configure and validate without holding the
other's credentials.

---

## Amazon Quick target

Everything above targets Amazon Bedrock managed Knowledge Bases. Setting
`target = "quick"` on a SharePoint or OneDrive connector points the same
source-side setup at Amazon Quick instead, following Quick's admin-managed
pattern where the credential is an AWS KMS key rather than a stored private key.

```toml
[connectors.engineering-quick]
type = "sharepoint"          # or "onedrive"
target = "quick"
credential = "cert"          # required: the credential is a KMS key pair
region = "us-east-1"         # must match your Quick instance's Region
acl = true
sharepoint_domain = "https://contoso.sharepoint.com"   # SharePoint only
site_urls = ["https://contoso.sharepoint.com/sites/engineering"]
```

Setup creates the KMS asymmetric signing key, builds an X.509 certificate over
that key's public half, registers the Entra app with the documented permissions
and admin consent, then prints the values the Quick console asks for: five for
SharePoint, four for OneDrive, which has no domain field.

The private key is generated inside KMS and never exported, so unlike the Bedrock
path there is no PKCS#12 in S3, no secret in Secrets Manager, and no knowledge
base service role. Quick signs the Entra client assertion through `kms:Sign` at
crawl time. The certificate is signed by that same KMS key, so its signature
verifies against its own embedded public key, which the OpenSSL `-force_pubkey`
recipe in the AWS setup guide does not produce.

### Where it stops, and the two manual steps

Setup finishes at the credentials and does not create the knowledge base, because
the Quick API cannot express this connection yet: `CreateDataSource` has no field
for a KMS signing key or a certificate thumbprint. See KNOWN-LIMITATIONS.md for
the evidence. Two steps remain in the Quick console, needing different Quick
roles, so they are often done by different people:

| Step | Who | What |
|---|---|---|
| 1 | Quick administrator (**Admin Pro**) | Authorize the signing key: Manage account, Permissions, AWS resources, AWS Key Management Service, then add the printed KMS key ARN. Until this is done the knowledge base can be created but every sync fails to authenticate. |
| 2 | Knowledge base owner (**Author Pro or Admin Pro**) | Create the KB: Knowledge, the connector, "Connect with service credentials", then paste the printed values. |

Setup prints both steps with the values filled in and a link to the matching AWS
docs page, so its output is the handoff. Re-run it any time to reprint them,
since it reuses the key, app and certificate rather than reissuing. Quick starts
the first sync itself once the knowledge base exists, so `monitor` and `--sync`
do not apply to this target.

### SharePoint and OneDrive differ

The tool requests the documented permission set for each, and they are not the
same. OneDrive needs `Group.Read.All`, which the Bedrock connector never asks
for, and needs no SharePoint REST permission at all. It always enforces
document-level access control, so `acl = false` is reported and overridden. There
is no `Sites.Selected` equivalent for OneDrive either, so its app necessarily
holds tenant-wide read across every user's drive; `sites_selected` warns and has
no effect. SharePoint supports `Sites.Selected` exactly as it does for `bmkb`.

### Signing key options

By default each connector gets its own key, aliased
`kb-connector-<connector>-signing`. Point several connectors at one key with
`signing_key_arn` instead, which also skips creating one:

```toml
signing_key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc-123"
```

A key supplied that way is recorded as external, so `teardown` reports it and
leaves it alone. A key the tool created is never deleted automatically either:
KMS only supports scheduled deletion, 7 to 30 days, and one key can back several
Quick knowledge bases. `teardown` prints the ARN and the command to schedule it.

`cert_valid_days` sets the certificate lifetime, defaulting to 365. Reissuing
with `--rotate-cert` uses the same KMS key, so only the Entra upload and the
thumbprint change, not the key ARN.

Full step detail lives in the AWS docs rather than here, so it cannot drift:
[SharePoint](https://docs.aws.amazon.com/quick/latest/userguide/sharepoint-kb-admin-config.html)
and
[OneDrive](https://docs.aws.amazon.com/quick/latest/userguide/onedrive-kb-admin-config.html).

---

## Security and identity model

This tool provisions identity and access resources. Know what it creates and how
credentials flow before you run it against a real environment.

### Where credentials live

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

### Using a customer-managed key

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
  "Resource": "arn:aws:kms:us-west-2:111122223333:key/abcd1234-..."
}
```

If the key policy is missing the role, the failure shows up as an authorization
error when the knowledge base is created or when a crawl first reads the
secret, not as a configuration error at startup — the tool cannot tell in
advance whether a key policy will admit a role that does not exist yet.

### Endpoints come from your AWS configuration

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

### What the caller needs

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

### The IAM role it creates

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

### Resource ownership and reuse

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

### Per-connector identity model

| Connector | Auth to source | Notes |
|-----------|----------------|-------|
| SharePoint | Entra app (client-credentials) with a certificate | App-only auth requires a certificate (`client_secret` is not usable). ACL crawling requires certificate auth and broader SharePoint permissions. `Sites.Selected` is supported for least-privilege per-site access. The connector also accepts ROPC (a delegated username/password flow), but automating it is out of scope for this tool — see [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md). |
| OneDrive | Entra app (client-credentials): certificate, client secret, or OAuth2 refresh | The connector crawls every user's drive in the tenant, so the app holds `Files.Read.All` across all users. ACL filtering keeps content scoped per-user at retrieve time, but the app token's blast radius is tenant-wide. |
| S3 | None (IAM only) | ACL is a declarative sidecar file in S3. Document-level access control cannot be disabled after the data source is created. |
| Web crawler | None (NO_AUTH) or Basic auth | Crawls public or basic-auth-protected sites. |
| Confluence | Atlassian OAuth2 or Basic (API token) | OAuth2 is not supported with ACL. Use Basic auth for ACL-enabled sources. |
| Google Drive | Google OAuth2 or service account | OAuth2 is not supported with ACL. Use a service account for ACL-enabled sources. |

### Credentials you need (and only when you need them)

You only need credentials for the stage you're running. Stage 1 (source-side)
needs a Microsoft Graph token, and Stage 2 (AWS-side) needs AWS credentials. The
split-admin workflow exists so neither admin needs the other's credentials. If a
token expires mid-run, the tool fails clearly and your progress is saved, so you
can re-authenticate and re-run.

For vulnerability reporting, see [SECURITY.md](SECURITY.md).

---

## How it works

The core of the tool is a Python library that returns structured results. The
CLI is a thin layer over it that renders those results for a terminal, pretty by
default and `--json` for raw. The same separation lets the MCP server wrap those
functions for AI agents. No business logic lives in the presentation layers.

```
┌─────────────────────────────────────┐
│  CLI (argparse + pretty rendering)  │  ← you, in a terminal
├─────────────────────────────────────┤
│  MCP server (read-only tools)       │  ← AI agents (Kiro, Claude Desktop)
├─────────────────────────────────────┤
│         Core Python library         │  ← structured dataclass results
│  setup · monitor · validate ·       │
│  diagnose · teardown · handoff      │
├─────────────────────────────────────┤
│      Target (control-plane API)     │  ← Bedrock managed KB (today)
└─────────────────────────────────────┘
```

Each connector implements an open-ended `ConnectorSpec` interface that declares
its own config fields, auth modes, setup steps, and parameter builder. Adding a
field or a new connector touches that one file, not the core.

---

## MCP server

The MCP server exposes a narrow subset of the tool to MCP clients (Kiro, Claude
Desktop, anything that speaks the protocol). Five tools, all read-only against
AWS except `kb_connector_monitor` with `start=true`:

| Tool | What it does |
|------|--------------|
| `kb_connector_list` | Summary of every configured connector and its tracked state. |
| `kb_connector_diagnose` | Runs the secret, certificate, and CloudTrail checks. |
| `kb_connector_monitor` | Polls an ingestion job and returns stats. Poll-only by default; pass `start=true` to begin a new job. |
| `kb_connector_validate` | Runs the validate trio for ACL connectors (authorized / denied / no-user retrieve) or a single retrieve for non-ACL connectors. |
| `kb_connector_handoff` | Builds a handoff document for split-admin workflows. |

`kb_connector_monitor(start=true)` is the one write on this surface: it starts a
real ingestion job, which re-crawls the source and incurs embedding cost. It
defaults to off, and the server's instructions name it so the model treats it as
privileged — but there is no confirmation step.

`setup` and `teardown` are intentionally not exposed. They're write-heavy or
destructive, and the right confirmation semantics for an agent context still
need design.

Two things to keep in mind when wiring this up. The stdio transport has no
authentication of its own and inherits the credentials of the shell that launched
it, so the server holds whatever authority that shell holds. And the agent
controls `profile`, `config_path`, and `state_path`, so it chooses which AWS
credential and which local files are used.

Install the extra and run the server:

```bash
pip install -e ".[mcp]"
kb-connector-mcp           # stdio transport
```

Wire it into your MCP client the way you would any other stdio server. For
example, in a Kiro `mcp.json`:

```json
{
  "mcpServers": {
    "kb-connector": {
      "command": "kb-connector-mcp"
    }
  }
}
```

---

## Development

```bash
pip install -e ".[dev]"
python -m pyflakes src/ tests/
python -m pytest
```

The committed suite is unit tests only: pure logic with no network that runs in
under three seconds. It covers parameter builders, secret schemas, config
resolution, state management, and output formatting, plus request shapes
checked against the `bedrock-agent` service model, and the security-relevant
controls in [THREAT-MODEL.md](THREAT-MODEL.md) — endpoint reporting, resource
ownership and tagging, the teardown ownership gate, file permissions, and log
redaction. Where a check needs an AWS client, tests use
small in-process fakes rather than reaching the network. Maintainers run live
validation against a real account before releases.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution guide.

---

## License

This project is licensed under the MIT-0 License. See [LICENSE](LICENSE).
