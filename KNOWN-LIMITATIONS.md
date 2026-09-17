# Known Limitations

A short, honest list of what the tool doesn't do yet and where the rough edges
are, so you can find them here rather than the hard way.

This covers the tool's own limitations. Behavior that belongs to the Bedrock
managed connectors themselves is documented by the service, not here.

For security-relevant limitations specifically — which risks are mitigated in
code and which are accepted — see [THREAT-MODEL.md](THREAT-MODEL.md).

### Ingestion log analysis needs vended log delivery

`diagnose --logs` reads the knowledge base's per-document `APPLICATION_LOGS`
events to explain a scanned-vs-indexed gap, but it can only read them — setup
does not turn delivery on. Configure it in the Bedrock console or via
`PutDeliverySource`/`PutDeliveryDestination` first. Enabling it during setup is
planned.

The log group defaults to `/aws/bedrock/knowledgebases/<kb-id>`; if yours
delivers elsewhere, pass `--log-group`. When the group is absent the check
reports that rather than failing, since a missing group means "logging isn't set
up", not "the connector is broken".

### Ownership tagging needs two extra caller permissions

Resources the tool creates are tagged `ManagedBy=kb-connector` and
`KbConnectorName=<connector>`, which is what lets it prove ownership before
modifying something that already exists and lets `teardown` tell created
resources from adopted ones.

`iam:CreateRole` with `Tags` also requires `iam:TagRole`, and
`secretsmanager:CreateSecret` with `Tags` requires
`secretsmanager:TagResource`. If the caller lacks either, setup still succeeds —
it retries untagged and warns. The state file records that the resource was
created without a tag, so a later run still recognizes it as the tool's own and
reuses it rather than refusing. The same applies to `--no-tags`.

The limitation is that ownership for those resources then rests on the state
file instead of on the resource itself. Lose the state file and an untagged
resource becomes indistinguishable from a stranger's, at which point reusing it
needs `--adopt-existing-resources`. Granting the two tagging permissions keeps
the ownership record where it belongs, on the resource.

Tag-verified adoption also means a *first* run in an account that already has a
role or secret matching the derived name will stop rather than overwrite it. Use
`--kb-role-name` / `--secret-name`, set `resource_prefix` in config, or pass
`--adopt-existing-resources`.

### SharePoint ROPC auth is out of scope

The Bedrock SharePoint connector supports ROPC (resource-owner password
credentials — a delegated flow authenticating as an admin user, sent as
`authType: OAUTH2_APP`). This tool doesn't automate it, and `credential = "ropc"`
is not a working configuration.

Parts of the path exist: `ropc` maps to the right auth type, `build_secret_body`
emits the right secret shape, and the permission plan adds the delegated
`AllSites.Read` scope. What's missing is the wiring — setup never collects the
admin username and password, and the delegated scope is never actually granted
(the consent code assigns application permissions only). Selecting `ropc` gets as
far as creating the Entra app, then fails with a `ValueError` when the secret is
built. The app is recorded in state, so `teardown` removes it.

Use `credential = "cert"` for SharePoint. Cert is the only mode that supports ACL
crawling, so ROPC's best case is a non-ACL knowledge base that cert already
covers — and Microsoft discourages ROPC, with Conditional Access or MFA blocking
it outright in most tenants. That's why it isn't on the roadmap. If you
specifically need it, create the app registration, delegated grant, and Secrets
Manager secret by hand and create the data source outside this tool (`probe`
submits a raw `connectorParameters` body).

### What's exercised end-to-end

The setup, monitor, validate, diagnose, and teardown paths have been run
against a live tenant and AWS account for:

- **SharePoint** with cert auth and ACL on, including the ACL-aware retrieve
  trio (authorized user returns results, unauthorized user returns zero,
  no-userContext returns zero), a full crawl to `COMPLETE`, and stopping an
  in-flight ingestion job.
- **OneDrive** with cert auth and ACL on, same trio.

A knowledge base encrypted with a customer-managed key has been created and
reached `ACTIVE`. Note that `GetKnowledgeBase` does not echo the encryption
configuration back, so there is no API-level confirmation to read: what is
verifiable is that the service validates the key at create time and rejects an
ARN it cannot resolve. Encryption of the secret and the certificate object is
ordinary Secrets Manager and S3 SSE-KMS.

Web (NO_AUTH) and S3 have been smoke-tested through to data-source
AVAILABLE. Confluence and Google Drive have been validated for connector
parameter shape only — a real OAuth2 or service-account run hasn't happened
yet, so expect to find rough edges if you test those first.

### Connector parameter surface is curated, not complete

The TOML fields the tool exposes are the ones we've validated end-to-end.
The Bedrock managed connectors expose a much larger surface; the long tail
(operational tuning, advanced indexing, deletion semantics) is not yet
wired into config. Highlights:

| Bedrock console label | API field | Status |
|-----------------------|-----------|--------|
| Advanced content indexing (visual content in documents, images) | `dataSource.vectorIngestionConfiguration.parsingConfiguration` (BEDROCK_FOUNDATION_MODEL strategy) | not exposed |
| Max file size (default 500 MB) | per-connector field on `dataEntityConfiguration` or filter | exposed for S3 and Web; missing for SharePoint, OneDrive, Confluence, Google Drive |
| Document deletion safeguard | `dataSource.dataDeletionPolicy` (RETAIN vs DELETE) | not exposed; the service default is in effect |

Other gaps worth knowing about:

- **SharePoint** now exposes most of `filterConfiguration`
  (`inclusion_item_paths`, `exclusion_item_paths`,
  `inclusion_file_name_patterns`, `exclusion_file_name_patterns`,
  `inclusion_file_path`, `exclusion_file_path`, `modified_date_after`,
  `modified_date_before`) — read the note above on `inclusion_item_paths`
  before using it. Still missing: `maxFileSizeInMegaBytes` (the service
  injects a default), content-type filters, and the additional crawl
  toggles (`crawlAttachments`, `crawlComments`, `crawlEvents`,
  `crawlListItem`, `crawlList`).
- **OneDrive** is missing `inclusionPatterns` / `exclusionPatterns` and
  the `modifiedDateBefore` / `modifiedDateAfter` since-date filters.
- **Knowledge base** creation uses the service-default embedding model and
  chunking strategy. There's no way to pick a specific embedder or override
  chunk size, overlap, or chunking type yet.
- **Server-side encryption** (KMS key) on the data source is not exposed.
  `--kms-key-arn` covers the knowledge base, the connector secret, and the
  certificate bucket.

The current shape of the tool is "set up the connector with sensible
defaults and run". To run a tuned ingest with custom filtering, the path
today is one of:

- **Curated config field** for fields the builder surfaces (S3 prefix
  filters, Web crawl depth, SharePoint and OneDrive crawl toggles, etc.).
- **`connector_params_overrides` table** for anything the builder doesn't
  surface. The dict deep-merges onto the params the builder produced
  before the data source is created. Validated end-to-end with a
  SharePoint `filterConfiguration.modifiedDateBefore` override on a real
  knowledge base.

  ```toml
  [connectors.engineering-sp.connector_params_overrides.filterConfiguration]
  modifiedDateBefore = "2025-01-01T00:00:00Z"
  ```

The override path is intentionally unvalidated — anything the API accepts
becomes available without code changes, and the tool doesn't pretend to
verify fields it hasn't tested. The cost is that using it means knowing
the API JSON shape; the curated fields are still where to look first.

Curated fields for the most-requested knobs (visual content parsing, max
file size, `dataDeletionPolicy`) are planned. The override path is the
pressure-release valve in the meantime.

### Credential rotation isn't built

The certificate generated by setup is valid for one year, and so is the Entra
client secret. There's no `rotate` command yet, so when either is near expiry,
plan on tearing the connector down and re-running setup, or rotate manually
through the Azure portal and S3.

`setup --stage both --rotate-cert` will issue a fresh certificate, but it is not
a substitute for a rotation command, because it replaces the credential with a
gap. A certificate is one credential split across two systems: the directory
holds the public certificate, and Secrets Manager plus S3 hold the private key.
`--rotate-cert` writes the directory first and AWS second, so between those two
writes the directory trusts a certificate whose private key AWS does not yet
have, and an ingestion running at that moment fails to authenticate. Run it when
no crawl is in flight.

Closing that gap needs overlap: add the new certificate to the app *alongside*
the old one, write the new private key to AWS, then remove the superseded entry.
Both certificates are trusted in the middle, so there is no moment where the two
halves disagree. That is the intended shape of a future `rotate` command. It is
not what `--rotate-cert` does today, and it carries its own tradeoff — during the
overlap the old certificate is still accepted, so rotating away from a credential
you believe is compromised would not revoke it until the final step.

Without `--rotate-cert`, setup keeps the certificate already installed on the
app: it re-runs without touching a working credential, and without opening that
gap. Re-running is therefore safe.

`diagnose` flags expiring certs (warns at 30 days, fails on expiry) so
you'll see the issue before retrieve breaks. It also confirms the directory still
carries the certificate the connector authenticates with, which expiry alone
cannot tell you — the two halves can drift apart, and the AWS side looks healthy
either way. That check needs Graph access; without it the check reports as
unverified and the rest of the diagnosis still runs. There's no equivalent check
for the client secret's expiry. The security consequence of no rotation path is
that a credential you suspect is compromised stays valid until you rebuild the
connector.

### The split-admin handoff does not carry a Microsoft credential

`handoff` moves identifiers and non-secret configuration between the identity
admin and the AWS admin, and deliberately never carries a secret. For
SharePoint and OneDrive that means the split cannot be completed by handoff
alone, whichever credential mode you choose: Stage 1 creates the certificate
private key or the client secret and holds it only in memory, so Stage 2 in a
second process has nothing to write to Secrets Manager.

`setup --stage 1` is refused for these connectors for that reason. It would
leave the directory holding a certificate whose private key never reaches AWS,
and against an already-working connector it would replace a certificate that AWS
still depends on. Run `--stage both` in one process, where the credential passes
between the stages in memory and never touches disk.

Where the two roles genuinely have to be separate people, the workable path today
is that the AWS admin runs `--stage both` with directory permissions delegated
for the duration, or the identity admin runs it with AWS credentials scoped to
the connector's resources. Making the split work end to end would mean the tool
handing the private key to the operator to transfer — a deliberate credential
export, which is the thing the handoff format is designed to avoid.

`handoff` remains useful in both directions for what it does carry: tenant and
app ids to the AWS admin, and knowledge base and data source ids back, so each
side can configure and validate without the other's credentials.

### Group-based ACL is unvalidated

Document-level ACLs that resolve through group membership work in
principle, but the test we've run against this tool has been user-direct.
If your SharePoint or OneDrive content relies heavily on group-based
permissions, expect to find issues we haven't caught yet.

### Connector-app blast radius

Each setup run creates one Entra app per connector. The app holds
broad-tenant read permissions:

- **SharePoint** with ACL: `Sites.Read.All`, `User.Read.All`,
  `GroupMember.Read.All` on Graph; `Sites.FullControl.All` on the
  SharePoint REST resource (needed to read item-level permissions for the
  ACL crawl).
- **OneDrive** with ACL: adds `Files.Read.All` to the SharePoint set,
  meaning the connector app can read every user's drive. ACL filtering
  scopes content per-user at retrieve time, but the app token's blast
  radius at crawl time is tenant-wide.

Sites.Selected (least-privilege per-site) is supported for SharePoint to
reduce the SP blast radius, but not for OneDrive (the API doesn't offer
an equivalent scope).

Note how the Sites.Selected path works: granting per-site access itself requires
`Sites.FullControl.All`, so the tool creates a temporary "granter" app with that
permission and a 2-day client secret, uses it, then deletes it. Deletion runs in
a `finally` block, so a failed grant still cleans up — but a hard kill (SIGKILL,
power loss) mid-run can orphan it. After any interrupted `--sites-selected` run,
check your tenant for an app named `<app-name>-granter` and delete it. The tool
prints the object ID and an `az ad app delete` command if it can't remove the app
itself.

### Amazon Quick target stops at the service credentials

`target = "quick"` completes the credential half of the Amazon Quick
admin-managed SharePoint setup and then stops. It does not create the
Quick data source or knowledge base, because the API cannot express this
connection yet.

Verified against the published QuickSight model (`quicksight`
`2018-04-01`, from botocore `develop`): the full transitive closure of
`CreateDataSourceRequest` is 363 member paths, and none of them accept a
KMS signing key or a certificate thumbprint. `SharePointParameters`
carries exactly four fields (`SharePointDomain`, `TenantId`, `ClientId`,
`AuthType`), and `DataSourceCredentials` has six arms, none holding a key
ARN. The strings `thumbprint` and `signing key` do not appear anywhere in
the model. The only KMS members in the whole service belong to
`UpdateKeyRegistration` / `DescribeKeyRegistration` and are documented for
"encryption and decryption use", meaning the symmetric QDataKey rather than
the asymmetric `SIGN_VERIFY` key this flow needs.

So two steps remain manual, and setup prints both with the values filled
in:

1. **Granting Quick use of the signing key.** The documented route is the
   Quick console (Manage account → AWS resources → AWS Key Management
   Service). If your organization manages its own Quick IAM service role,
   the alternative is granting that role `kms:Sign` on the key; setup
   prints the policy statement.
2. **Creating the knowledge base**, in the Quick console, pasting the five
   printed values.

Two consequences worth planning around. **ACL management is immutable
after the knowledge base is created**. Changing it means creating a new
one, so decide before you click Create. And there is no knowledge-base
sync API to drive: the only ingestion operations are dataset-scoped
(`/data-sets/{DataSetId}/ingestions/{IngestionId}`). That costs nothing
here, because Quick triggers the first sync itself once the knowledge base
exists. It does mean `monitor` and `--sync` do not apply to this target,
and `--sync` warns and no-ops.

This area of the API is moving: `SharePointParameters` itself, along with
`CreateKnowledgeBase` and `UpdateKnowledgeBase`, landed between botocore
`1.43.32` and `develop`. If a credential field appears, the work is
confined to `targets/quick.py` and the Stage 2 branch in `cli/setup.py`.

`target = "quick"` supports `type = "sharepoint"` and `type = "onedrive"`,
both requiring `credential = "cert"`. The credential is a KMS-held key
pair and there is nowhere in the flow for a client secret, so unlike the
Bedrock OneDrive path no client secret is created.

The two sources need different Entra permissions, and the tool requests
the documented set for each rather than sharing one. OneDrive needs
`Group.Read.All`, which the Bedrock connector never asks for. Without it,
group-based access control resolves to nothing and documents shared with a
group are silently missed. It needs no SharePoint REST permission, so the
Bedrock path's `Sites.FullControl.All` (tenant-wide full control) is not
granted. And admin-managed OneDrive always enforces document-level access
control, so `acl = false` is reported and overridden rather than honored
into a permission set that cannot support the crawl Quick runs.

There is no `Sites.Selected` equivalent for OneDrive: its setup guide has
no per-site grant step, so the app necessarily holds tenant-wide
`Files.Read.All` across every user's drive. Setting `sites_selected` on a
OneDrive connector warns and has no effect.

OneNote (`Notes.Read.All`) cannot work in admin-managed setup for either
source: Microsoft retired app-only tokens for the OneNote APIs on
31 March 2025. Use Quick's user-managed setup for OneNote content.

### Setup doesn't reuse an existing knowledge base by name

If you re-run setup after a failed attempt that left an orphan KB
behind, or after running setup against the same connector without a
clean teardown in between, the second setup will 409 on
`CreateKnowledgeBase` because a KB with the target name already exists.
Setup also has no logic that looks the KB up by name and reuses it.

Caught when retrying a setup mid-test. Workarounds while this is open:

- Use `--kb` to attach to the existing KB explicitly, or
- Pick a different connector name (every default name is derived from
  the connector name, so it's the simplest way to dodge the collision), or
- Delete the orphan KB through the console or AWS CLI and re-run.

The fix is to look the KB up by name before creating, and either reuse
or fail with a clearer message.

### Setup state can overwrite tracking on a partial-failure retry

If setup fails mid-Stage-2 (after credentials are written but before
the KB or DS is recorded in state) and you re-run, the second attempt
overwrites the state's credential references with new values. The
first run's resources are still in AWS but the tool has lost track of
them, so teardown cannot find them.

Workaround: before re-running a failed setup, take note of any
resource IDs the tool printed before it failed, so you can fall back
to manual cleanup if needed. The cleaner fix is for setup to detect
that the recorded state already references credentials and reuse them
instead of provisioning new ones on retry.

### Teardown leaves the cert bucket; secrets are force-deleted

Teardown deletes the `.p12` object inside the cert bucket but doesn't
delete the bucket itself, since the bucket is shared across connectors
and across runs. If you decommission the tool entirely you'll need to
empty and delete the bucket manually.

Secrets are force-deleted (no recovery window) so re-runs of `setup`
under the same connector name don't trip on AWS's default 7-day deletion
schedule. Don't use teardown if you actually want the recovery window.

Two things teardown deliberately will not do. It skips resources the tool
*adopted* rather than created — an existing KB passed via `--kb`, that KB's own
IAM role, anything taken over with `--adopt-existing-resources` — listing them as
"kept" unless you pass `--include-adopted`. And on a role it removes only the
inline policies it authored (`kb-connector*`), refusing outright if managed
policies are attached, since that means the role is used for something beyond
this connector. If teardown leaves a role in place with a message about foreign
policies, that is why.

### Confluence and Google Drive are param-validated only

The connector parameter shapes are validated against the live API
(creating a data source with fake credentials reaches AVAILABLE), but no
end-to-end ingestion has been run against a real Atlassian instance or
Google Workspace. Builders should expect to find issues that show up
only with a real OAuth2 or service-account run.

OAUTH2 with ACL is rejected by the service for both connectors. Use
Basic auth for Confluence + ACL, and a service account for Google Drive
+ ACL.

### MCP server exposes one write, and no destructive tools

The MCP server registers `kb_connector_list`, `kb_connector_diagnose`,
`kb_connector_monitor`, `kb_connector_validate`, and
`kb_connector_handoff`. All are read-only against AWS except
`kb_connector_monitor` with `start=true`, which starts a real ingestion
job — that re-crawls the source and incurs embedding cost. It defaults
to off and the server's instructions call it out so the model treats it
as privileged, but there is no confirmation step: an agent that decides
to set it will set it.

`setup` and `teardown` aren't exposed. The right confirmation semantics
for a write-heavy or destructive tool in an agent context still need
design, and teardown in particular force-deletes secrets.

The stdio transport has no authentication of its own and inherits the
credentials of whatever shell launched it. The agent also controls
`profile`, `config_path`, and `state_path`, so it selects which AWS
credential and which local files are used. Treat the server as holding
whatever authority its launching shell holds.

### Web crawl target validation is a sanity check, not an SSRF boundary

`seed_urls` and `sitemap_urls` are checked at config time: non-`http(s)`
schemes, missing hosts, `localhost`, and any host that parses as a
loopback, link-local, private, reserved, or multicast address are
rejected. That catches the common operator mistake early rather than as
an opaque, wholly-failed ingestion.

It does not stop a determined config author. The check tests literal IP
forms only, so `http://2130706433/`, `http://0x7f000001/`,
`http://0177.0.0.1/` and `http://127.1/` are all treated as hostnames
and pass. DNS is deliberately not resolved, so any name resolving to a
private address also passes. Only the seed URLs are checked — with
`crawl_depth` or an `ALL_DOMAINS` sync scope the crawler follows links
away from them, and redirects aren't inspected. `inclusion_filters` and
`exclusion_filters` are passed through unvalidated, and
`probe --connector-params` bypasses the check entirely.

This is a deliberate line rather than a gap to close. The crawl runs in
AWS's service account against the public internet, not in your VPC or on
your workstation, so the check exists to make intent explicit and catch
mistakes — not to contain an attacker. See T-13 in
[THREAT-MODEL.md](THREAT-MODEL.md).

### Retries and idempotency come from the SDK

Retry behavior is whatever the AWS SDK does: transient socket errors, HTTP
5xx, and throttling are retried, and the attempt count follows the SDK's own
configuration, so `AWS_MAX_ATTEMPTS` or `retry_mode` in your profile applies
here like anywhere else.

`CreateKnowledgeBase`, `CreateDataSource` and `StartIngestionJob` all declare a
`clientToken` that the SDK fills automatically, and a request is serialized
once before the retry loop, so every attempt within one call carries the same
token and the service de-duplicates. A retried create therefore does not
produce a duplicate resource.

What the SDK does not distinguish is whether a failed write reached the
service: an ambiguous read timeout or 5xx on a create is retried even though it
might already have been processed. The idempotency token is what makes that
safe, and it is the reason this tool does not add a retry policy of its own.
The residual case is a create that fails in a way the SDK does not retry at
all, which surfaces as an error rather than a duplicate.
