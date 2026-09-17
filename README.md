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
kb-connector setup engineering-sp --kms-key-arn arn:aws:kms:us-east-1:111122223333:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

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
signing_key_arn = "arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
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
