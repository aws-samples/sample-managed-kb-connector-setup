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

**Which document do I want?**

| Document | Answers |
|---|---|
| This README | How do I install it, configure a connector, and run the commands? |
| [CONFIG-REFERENCE.md](CONFIG-REFERENCE.md) | Which config keys does each connector take? |
| [IDENTITY-AND-PERMISSIONS.md](IDENTITY-AND-PERMISSIONS.md) | What does it create, where do credentials live, and what does the caller need? |
| [THREAT-MODEL.md](THREAT-MODEL.md) | What can go wrong, which threats are mitigated, and what risk is left? |
| [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) | What doesn't work yet, and what is exercised end to end? |
| [SECURITY.md](SECURITY.md) | How do I report a vulnerability? |

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
| `quick` | Amazon Quick, SharePoint and OneDrive. Creates the KMS signing key, certificate, Entra app, Quick data source and knowledge base; one console step authorizes the key | Complete, see [Amazon Quick target](#amazon-quick-target) |

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
read access — see [What the caller needs](IDENTITY-AND-PERMISSIONS.md#what-the-caller-needs)
for the exact
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

[CONFIG-REFERENCE.md](CONFIG-REFERENCE.md) lists every key each connector
takes. A key the tool does not read, or a value of the wrong type, prints a
warning naming the closest valid key, so a typo like `max_file_size` is
reported instead of silently ignored. A value the service would reject, such as
`max_file_size_mb` above its limit, stops setup before it creates anything.

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
`KbConnectorName=<connector>`, except data sources, which the API does not
tag. That's how a later run knows whether it created
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

### Request overrides

An `overrides` table deep-merges into the `CreateKnowledgeBase` and
`CreateDataSource` requests setup sends, so any field those APIs accept can be
set without a code change. Nested tables merge key by key; any other value,
including a list, replaces what setup built.

```toml
# Image, audio and video extraction, a deletion safeguard, and keeping indexed
# content when the data source is deleted.
[connectors.videos.overrides.create_data_source]
dataDeletionPolicy = "RETAIN"

[connectors.videos.overrides.create_data_source.dataSourceConfiguration.managedKnowledgeBaseConnectorConfiguration]
mediaExtractionConfiguration = { videoExtractionConfiguration = { videoExtractionStatus = "ENABLED" }, audioExtractionConfiguration = { audioExtractionStatus = "ENABLED" }, imageExtractionConfiguration = { imageExtractionStatus = "ENABLED" } }
deletionProtectionConfiguration = { deletionProtectionStatus = "ENABLED", deletionProtectionThreshold = 15 }

[connectors.videos.overrides.create_knowledge_base]
description = "Training videos"
```

`connector_params_overrides` is still read. It merges into `connectorParameters`
first, and `overrides.create_data_source` merges on top of it.

Setup checks overrides before it makes any Graph or AWS call:

- Fields setup sets itself (`name`, `roleArn`, `knowledgeBaseId`, `clientToken`)
  are refused, with the flag to use instead. Tags go through the same checks as
  the `[tags]` table, so the ownership tags cannot be set.
- Everything outside `connectorParameters` is validated against the installed
  botocore model, so a misspelled field or wrong type fails at the start of
  setup. A field newer than the installed botocore fails the same way; upgrade
  boto3 to use it. `connectorParameters` is a free-form document in the model,
  so its contents are checked only by the service.

Overrides apply when a resource is created. A knowledge base or data source that
setup reuses is not updated; to apply a changed data source override, run
`teardown --only ds` and then setup again.

For video, raise the connector's maximum file size as well, since the default
skips large files. With media extraction off the service accepts 1 to 500 MB.
Media extraction needs no IAM permissions beyond the role setup creates.

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
data source, and waits for them to become active. With `--kb`, it extends the
existing knowledge base's role for every connector type; a role passed with
`--kb-role-arn` is used as given.

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

For request fields the curated config doesn't surface, see
[Request overrides](#request-overrides).

```bash
kb-connector setup engineering-sp                 # both stages
kb-connector setup engineering-sp --sync          # plus first ingestion
kb-connector setup engineering-sp --rotate-cert    # issue a new certificate
kb-connector setup engineering-sp --kb EPS06WSNZU # attach to an existing KB

# Encrypt the secret + certificate with your own KMS key instead of the
# AWS-managed one (adds a key-policy gate; the KB role gets kms:Decrypt on it):
kb-connector setup engineering-sp --kms-key-arn arn:aws:kms:us-east-1:111122223333:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Take over a pre-existing role/secret whose ownership can't be verified:
kb-connector setup engineering-sp --adopt-existing-resources
```

Created resources are tagged `ManagedBy=kb-connector` and
`KbConnectorName=<name>`. Setup refuses to modify an existing role, secret, or
certificate bucket that those tags don't attribute to this connector — see
[Resource ownership and reuse](IDENTITY-AND-PERMISSIONS.md#resource-ownership-and-reuse).
If several people
run this tool in one account, set `resource_prefix` per connector so derived
names can't collide.

### `monitor`

```bash
kb-connector monitor engineering-sp               # start a sync + poll to done
kb-connector monitor engineering-sp --no-start    # poll the latest job
```

Prints a status line on every poll (elapsed time, status, scanned, indexed,
failed), then the final counts. It flags the common case where ACL is enabled
but the connector app can't read item-level permissions, which shows up as
documents scanned but skipped instead of indexed.

The job id is saved to state as soon as the job starts, so if the poll loop is
interrupted, `--no-start` resumes watching the same job. `setup --sync` and the
MCP monitor tool save it the same way.

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
later pass. Teardown exits non-zero when any delete fails or is skipped, and
when it refuses because of a running job.

Teardown deletes in the region recorded in state, falling back to the
connector's config region. With neither, it stops before prompting rather than
guessing.

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
`target = "quick"` on a SharePoint or OneDrive connector creates an Amazon Quick
knowledge base instead, following Quick's admin-managed pattern where the
credential is an AWS KMS key rather than a stored private key.

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

Setup creates, in order:

1. The Entra app with the documented permissions and admin consent.
2. The KMS asymmetric signing key (`RSA_2048`, `SIGN_VERIFY`, single-Region).
3. An X.509 certificate over that key's public half, signed by the same key and
   uploaded to the Entra app.
4. The Quick data source (`CreateDataSource`, type `SHAREPOINT` or `ONE_DRIVE`),
   which carries the tenant, the app's client id, the key ARN and the
   certificate thumbprint.
5. The Quick knowledge base (`CreateKnowledgeBase`) on that data source. Setup
   waits for it to be `ACTIVE`.

The private key is generated inside KMS and never exported, so unlike the Bedrock
path there is no PKCS#12 in S3, no secret in Secrets Manager, and no knowledge
base service role. Quick signs the Entra client assertion through `kms:Sign`. The
certificate's signature verifies against its own embedded public key, which the
OpenSSL `-force_pubkey` recipe in the AWS setup guide does not produce.

### The one console step

No Quick API authorizes a KMS key; the documented route is a step in the Quick
console. A Quick administrator (**Admin Pro**) does it once per key:

Manage account, Permissions, AWS resources, AWS Key Management Service, Select
keys, add the key ARN setup printed, Finish, then Save at the bottom of the page.

Setup prints this step with the key ARN and a link to the AWS docs page before it
creates the data source. When the account's Quick service role is
customer-managed (`DescribeResourcePermissions` returns `CUSTOMER_MANAGED`),
that role also needs `kms:Sign` on the key: setup prints the key policy
statement naming the role for a key administrator to add. Setup never writes a
key policy statement, a grant or an IAM policy.

Until the step is done, `CreateDataSource` fails with "Failed to generate JWT
assertion". Setup reports that Quick is not yet authorized to sign with the key,
prints `Setup is not finished`, creates no data source or knowledge base, and
exits 0. Run `kb-connector setup <connector>` again after the console step: it
reuses the key, certificate and Entra app and creates the data source and
knowledge base. On a terminal, setup instead asks you to press Enter after
saving the key in the console, then retries `CreateDataSource` up to 4 times,
15 seconds apart; `q` stops.

### What feeds the knowledge base

The knowledge base template has the shape the Quick console writes
(`SHAREPOINTV3` or `ONEDRIVEV3`), filled from keys the connector already has:

| Quick field | Config key |
|---|---|
| SharePoint domain (a bare host) | `sharepoint_domain` (scheme and path stripped), else `sharepoint_host`, else the host of the first `site_urls` entry |
| SharePoint sites, `crawlFiles`, `crawlPages` | `site_urls`, `crawl_files`, `crawl_pages` |
| SharePoint `filterConfiguration` | the SharePoint filter keys (`inclusion_item_paths`, `exclusion_file_name_patterns`, ...); `inclusionItemPaths` defaults to `site_urls`, as in the console |
| OneDrive `crawlPersonalDrives`, `crawlSharedWithMe` | `crawl_personal_drives`, `crawl_shared_with_me` |
| ACL (`isACLEnabled`, `crawlAcl`, `crawlIdentities`) | `acl` for SharePoint; always on for OneDrive |
| Data source and knowledge base names | `--ds-name`, `--kb-name` (defaults `<connector>-ds`, `kb-connector-<connector>`) |
| Tags | the ownership tags, unless `--no-tags` |

The data source id and knowledge base id are derived from the connector name
(`kb-connector-<connector>-ds`, `kb-connector-<connector>-kb`, with
`resource_prefix` applied), so a re-run finds them. The maximum file size is
500 MB, as in the console. `inclusion_user_emails` has no Quick counterpart, and
setup warns that it has no effect on OneDrive.

`quick_owner_arn` sets the Quick user or group that owns the data source and
knowledge base:

```toml
quick_owner_arn = "arn:aws:quicksight:us-east-1:123456789012:user/default/kb-admin"
```

Without it, the owner is the Quick user of the identity running setup (for an
assumed role, `<role>/<session>` in the `default` namespace). When that user
does not exist and no `quick_owner_arn` is set, setup stops before it creates the
data source.

### Re-running setup

Setup modifies nothing it finds. With `--kb ID`, it records that knowledge base
and its data source as external (unless state already records them as created
by this tool) and creates nothing; the data source must carry this app's client
id. Otherwise it looks for the data source, then the knowledge base:

1. The ids in state.
2. The derived ids. A resource there that carries this connector's ownership
   tags is reused; one that does not is refused, unless
   `--adopt-existing-resources`, which records it as external.
3. A data source with this app's client id, made outside this tool (for example
   in the console). Exactly one is recorded as external, with its single
   knowledge base, or setup creates a knowledge base on it when it has none.
   With several, setup prints their ids, records nothing and prints
   `Setup is not finished` (exit 0); pass `--kb` to `setup`, `validate` and
   `diagnose`.

Setup waits for a data source or knowledge base it finds to become usable. One
that failed (a data source in `CREATION_FAILED` or `UPDATE_FAILED`, a knowledge
base in `FAILED`) stops setup with exit 1 and the service's error message.

ACL is fixed when a knowledge base is created. A reused knowledge base whose ACL
differs from the config gets a warning, and `validate` fails on it.

### Validate, diagnose, monitor and teardown

`validate` has no test query, because Amazon Quick has no API to query a
knowledge base, so the authorized/denied/no-user retrieve checks do not run. It
checks instead:

| Check | What it confirms |
|---|---|
| `signing_key_usable` | The key exists, is enabled, `RSA_2048` `SIGN_VERIFY`, single-Region, in the connector's Region |
| `quick_key_authorized` | The role Quick signs with may call `kms:Sign` on the key, through its identity policy (IAM policy simulator), a key policy statement or a grant |
| `entra_app`, `certificate_installed`, `entra_consent` | The app exists, carries the certificate, and has admin consent for every permission setup grants (through Microsoft Graph; `--auth-method device_code` when `az login` is not available) |
| `quick_kb_active` | The knowledge base exists and is `ACTIVE` |
| `quick_kb_acl` | Its ACL setting matches the config |
| `quick_kb_documents` | It holds at least one document |
| `quick_kb_latest_sync` | The latest sync is `COMPLETED` or in progress. For `INCOMPLETE`, `FAILED`, `TIMEOUT` and `CANCELLED` the API gives no reason: the knowledge base's [sync report](https://docs.aws.amazon.com/quick/latest/userguide/sync-reports-observability.html) in the Quick console does |

`diagnose` runs the same checks plus certificate expiry and a CloudTrail scan
for denied `kms:Sign` calls on the key (`kms_sign_denied`). Denials followed by
a successful `kms:Sign` by the Quick role on the same key pass, because the key
was authorized after them. `diagnose` does not run the
secret, log (`--logs`) or account-wide CloudTrail checks, which apply to Bedrock.
Over MCP, both run without the Entra checks. `validate` reports the skipped
checks in its notes; `diagnose` skips them without a note.

Quick starts the first sync itself once the knowledge base exists and has no
sync API, so `monitor` refuses a Quick connector and `setup --sync` has no
effect.

`teardown` deletes the knowledge base, then the data source, then the Entra app,
when this tool created them. A data source or knowledge base recorded as
external is kept. A data source this tool created is also kept while an external
knowledge base uses it: delete that knowledge base in the Amazon Quick console,
then re-run `kb-connector teardown <connector>` to remove the data source and the
rest. Teardown checks that knowledge base with one read-only
`DescribeKnowledgeBase` call. If the check fails for any reason other than "not
found", it keeps the data source and the Entra app and prints the error code. A
kept data source cannot sync once teardown deletes the Entra app it
authenticates with. The signing key is never deleted automatically (see below);
`teardown` prints its ARN and the command to schedule its deletion.

### SharePoint and OneDrive differ

The tool requests the documented permission set for each, and they are not the
same. OneDrive needs `Group.Read.All`, which the Bedrock connector does not ask
for, and no SharePoint REST permission. Quick always enforces document-level
access control for OneDrive, so `acl = false` is reported and overridden. There
is no `Sites.Selected` equivalent for OneDrive, so its app holds tenant-wide
read across every user's drive; `sites_selected` warns and has no effect.
SharePoint supports `Sites.Selected` as it does for `bmkb`.

### Signing key options

By default each connector gets its own key, aliased
`kb-connector-<connector>-signing`. Point several connectors at one key with
`signing_key_arn` instead, which also skips creating one:

```toml
signing_key_arn = "arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

A key supplied that way is recorded as external, so `teardown` reports it and
leaves it alone. A key the tool created is never deleted automatically either:
KMS only supports scheduled deletion, 7 to 30 days, and one key can back several
Quick knowledge bases. `teardown` prints the ARN and the command to schedule it.

`cert_valid_days` sets the certificate lifetime, defaulting to 365. Reissuing
with `--rotate-cert` uses the same KMS key, so only the Entra upload and the
thumbprint change, not the key ARN. The Quick data source records the
certificate thumbprint when it is created, and setup does not update a data
source it finds, so after `--rotate-cert` the data source still uses the
thumbprint of a certificate the Entra app no longer has, and its syncs fail to
authenticate. Setup prints a warning when this happens.
To recover, recreate the knowledge base and the data source:

```bash
kb-connector teardown <connector> --only kb
kb-connector teardown <connector> --only ds
kb-connector setup <connector>      # new data source with the new thumbprint
```

Teardown deletes only what this tool created; delete a knowledge base or data
source recorded as external in the Quick console first. The same applies to a
new signing key (`signing_key_alias` set to a new alias), because the data
source also keeps the key ARN it was created with.

Full step detail lives in the AWS docs:
[SharePoint](https://docs.aws.amazon.com/quick/latest/userguide/sharepoint-kb-admin-config.html)
and
[OneDrive](https://docs.aws.amazon.com/quick/latest/userguide/onedrive-kb-admin-config.html).

---

## Security and identity model

This tool provisions identity and access resources. What it creates, which
credentials it handles, and what the caller needs are documented in
[IDENTITY-AND-PERMISSIONS.md](IDENTITY-AND-PERMISSIONS.md). Read it before
running against a real environment.

For the threats those controls address, see
[THREAT-MODEL.md](THREAT-MODEL.md). For vulnerability reporting, see
[SECURITY.md](SECURITY.md).

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
