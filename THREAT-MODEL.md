# Threat Model

This document describes what `kb-connector` is trusted to do, what could
go wrong, and which of those risks are mitigated in code versus accepted and
documented.

It exists because this project is easy to misread. It ships as an AWS sample, so
it looks like example code — but it is a privileged administrative tool. A single
`setup` run registers an application in a customer's Microsoft Entra tenant,
grants it tenant-wide read permissions with admin consent, generates and stores
private key material, and creates IAM roles in an AWS account. Anyone evaluating
it should understand that before running it, and anyone changing it should know
which behaviors are load-bearing for security.

Related documents: [SECURITY.md](SECURITY.md) for vulnerability reporting and a
summary of credential handling; [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) for
functional gaps; the README's
[security and identity model](README.md#security-and-identity-model) for
operator-facing guidance.

---

## 1. Scope

**In scope.** The `kb-connector` CLI, the `kb-connector-mcp` MCP server, and the
`kb_connector` library: their handling of credentials, the AWS and Microsoft
Graph resources they create and delete, the files they write, and the data they
surface in output.

**Out of scope.** The security of Amazon Bedrock Knowledge Bases, Microsoft
Graph, Atlassian, or Google Workspace themselves. The managed vector store
(AWS-operated; not configurable from this tool). The correctness of Bedrock's own
ACL enforcement at retrieval time. Physical and host security of the operator's
workstation. Supply-chain integrity of `boto3`, `cryptography`, `requests`, and
`mcp`.

**Assumptions.**

- **A1.** The operator's workstation is not already compromised. Nearly every
  threat below becomes moot against an attacker with code execution as the
  operator, since that attacker inherits both the AWS credential chain and the
  Graph token.
- **A2.** The operator is authorized to administer both the AWS account and the
  identity tenant they point the tool at, or is deliberately running one half of
  the split-admin workflow.
- **A3.** AWS IAM, KMS, and Secrets Manager enforce their documented semantics.
- **A4.** Microsoft Entra enforces admin consent and application permission
  boundaries as documented.
- **A5.** The Bedrock managed connector reads the credential secret only to
  crawl the source it was configured for.

---

## 2. Assets

| ID | Asset | Why it matters |
|---|---|---|
| **AS-1** | Connector credential secret (`privateKey`, `certificatePassword`, `clientSecret`, `apiToken`, `refreshToken`, service-account JSON) | Holds the connector's identity in the source system. For SharePoint/OneDrive that identity can read the whole tenant. Highest-value asset. |
| **AS-2** | RSA private key + PKCS#12 bundle | Authenticates as the Entra application. Exists in memory during setup, in the secret, and in the S3 object. |
| **AS-3** | Operator AWS credentials | The credential chain used to sign every AWS request. Never handled directly, but exposed via signature if requests go somewhere unexpected. |
| **AS-4** | Operator Microsoft Graph token | Borrowed from `az` or device-code. Carries the operator's *full* directory privileges, not a scoped subset. |
| **AS-5** | Entra application + its grants | The standing tenant-wide read capability the tool creates. Persists after setup. |
| **AS-6** | AWS resources created (IAM role, secret, KB, data source, S3 bucket/object) | Availability and integrity of the customer's ingestion pipeline. |
| **AS-7** | Pre-existing customer resources | An adopted KB, its IAM role, a same-named secret. Not the tool's to modify or destroy. |
| **AS-8** | Indexed document content | Reachable via `Retrieve`; surfaces in `validate`, `probe` output, and MCP responses. |
| **AS-9** | Environment metadata (tenant ID, app IDs, account IDs, ARNs, site URLs, user emails) | Not secret, but a precise map of the target for an attacker. Lives in config, state, and handoff files. |
| **AS-10** | Document paths and service reasons in ingestion logs | Filenames and folder paths are customer content; routinely pasted into support tickets. |

---

## 3. Trust boundaries and data flow

```mermaid
flowchart TB
    subgraph OP["Operator workstation — TB-1"]
        CLI["kb-connector CLI"]
        MCPS["kb-connector-mcp<br/>(stdio)"]
        CFG["kb-connector.toml<br/>state.json / handoff<br/>probe artifacts"]
        MEM["In-process secrets<br/>cs._p12_bytes etc."]
        AZ["az CLI session<br/>AS-4"]
        AWSC["AWS credential chain<br/>AS-3"]
    end

    subgraph AGENT["AI agent host — TB-2"]
        LLM["Model + transcript store"]
    end

    subgraph MSFT["Microsoft Entra / Graph — TB-3"]
        APP["Connector app + grants<br/>AS-5"]
        GRANTER["Temp Sites.Selected<br/>granter app"]
    end

    subgraph AWS["AWS account — TB-4"]
        SM["Secrets Manager<br/>AS-1"]
        S3["S3 cert bucket<br/>AS-2"]
        IAM["IAM role<br/>AS-6"]
        BEDROCK["Bedrock KB + data source"]
        LOGS["CloudWatch Logs<br/>AS-10"]
    end

    subgraph SRC["Source systems — TB-5"]
        SP["SharePoint / OneDrive /<br/>Confluence / Drive / Web"]
    end

    LLM -.->|"5 read tools<br/>+ monitor start=true"| MCPS
    MCPS --> CLI
    CLI --> CFG
    CLI --> MEM
    CLI -->|"Graph token"| AZ
    AZ -->|"create app, consent,<br/>upload cert, add secret"| APP
    AZ --> GRANTER
    CLI -->|"SigV4, AS-3"| AWSC
    AWSC --> SM
    AWSC --> S3
    AWSC --> IAM
    AWSC --> BEDROCK
    AWSC --> LOGS
    BEDROCK -->|"assumes role"| IAM
    IAM -->|"GetSecretValue"| SM
    IAM -->|"GetObject"| S3
    BEDROCK -->|"crawls using AS-1"| SP
    SP -->|"document content AS-8"| BEDROCK
    BEDROCK -->|"Retrieve results"| CLI
    LOGS -->|"document paths AS-10"| CLI
```

| ID | Boundary | Crossing |
|---|---|---|
| **TB-1** | Operator workstation | Local files are inputs the tool trusts for resource names and API payloads (T-14), and the AWS SDK's own configuration decides where signed requests go (T-01). Values that become the *target* of a destructive AWS call are shape-checked rather than trusted (T-24), as are values interpolated into IAM policy ARNs (T-26). |
| **TB-2** | AI agent → MCP server | stdio, no authn of its own. Agent controls `profile`, `config_path`, `state_path`. Document content flows back into model context. |
| **TB-3** | Tool → Microsoft Entra | Directory writes using the operator's full-privilege token. Creates standing capability that outlives the run. |
| **TB-4** | Tool → AWS | SigV4-signed requests, to whichever endpoint the SDK resolves (T-01). Creates IAM roles and reads/writes secrets. |
| **TB-5** | Bedrock → source system | AWS-side crawl using AS-1. The tool configures this but is not on the path. |

---

## 4. Threat actors

| ID | Actor | Capability |
|---|---|---|
| **TA-1** | Malicious/compromised local file | Can set config values: endpoint URLs, resource names, crawl targets, raw API payload overrides. Realistic via a shared repo, a copied example, or a poisoned CI checkout. |
| **TA-2** | Other principal in the same AWS account | Holds some IAM permissions but not the operator's. Interested in AS-1. |
| **TA-3** | Other local user on a shared host | Can read files the operator writes. |
| **TA-4** | AI agent driving the MCP server | Untrusted-by-default automation; may be steered by prompt injection from indexed content. |
| **TA-5** | Attacker who obtains AS-1 | Holds connector credentials without holding the operator's credentials. |
| **TA-6** | Careless operator | Runs the wrong command in the wrong account. Not malicious; the most likely cause of damage. |
| **TA-7** | Network attacker | Can observe or redirect traffic. |

---

## 5. Threats

Threat statements follow the [AWS Threat Composer](https://awslabs.github.io/threat-composer/)
grammar. Priority reflects likelihood × impact *for this tool's realistic
deployment*, not raw severity. **Status** is one of Mitigated (addressed in
code), Partially mitigated, or Accepted (documented, not fixed).

### T-01 — SDK endpoint configuration exfiltrates signed AWS credentials
**High · Spoofing/Information disclosure · TB-1→TB-4 · AS-3**

A **TA-1** able to set `AWS_ENDPOINT_URL`, a service-specific variant such as
`AWS_ENDPOINT_URL_BEDROCK_AGENT`, or `endpoint_url` in the operator's
`~/.aws/config` can redirect requests to a host they control, which yields a
valid SigV4 `Authorization` header plus the request body, negatively impacting
the confidentiality of the operator's AWS credentials and enabling replay
against the real endpoint inside the signing window.

**Status: Accepted.** Endpoint resolution is delegated to the AWS SDK, so this
tool has no endpoint settings of its own and applies no host allowlist. Three
reasons that is the right call rather than a gap:

Every client here has always behaved this way. Secrets Manager, IAM, S3, STS,
CloudTrail and CloudWatch Logs are ordinary boto3 clients and honour SDK
endpoint configuration. A previous allowlist covered only `bedrock-agent`,
whose request bodies carry secret *ARNs*, and left unguarded the Secrets
Manager path — whose signed `GetSecretValue` can be replayed for AS-1 itself.
The control protected the less sensitive path and misrepresented the rest.

For the `~/.aws/config` vector the capability is already inside the boundary: a
**TA-1** who can write that file can set `credential_process`, `role_arn` or
`source_profile` and take over the credential chain outright, which is strictly
more powerful than redirecting an endpoint.

Suppressing SDK configuration (`ignore_configured_endpoint_urls`) would break
FIPS endpoints, VPC endpoints and pre-production testing, and would make this
sample model behaviour no other AWS tool exhibits.

**Residual:** an inherited environment variable in CI redirects signed requests
for every service, and nothing in the tool detects it. `setup` prints the
resolved endpoint alongside the profile and caller ARN before its first write,
so the redirection is visible in the run's own output, but that is detection
rather than prevention. Operators who need prevention should constrain the
environment the tool runs in.

### T-02 — Teardown destroys resources the tool did not create
**High · Denial of service · TB-4 · AS-7**

A **TA-6** who attached a connector to an existing knowledge base with `--kb`
and later ran `teardown` can delete that knowledge base and strip the IAM role it
shares with its other data sources, negatively impacting the availability of
workloads that predate the connector.

**Status: Mitigated.** `ConnectorState.created_resources` records `tool` vs
`external` per resource kind, written at every provisioning site. An adopted KB
(`setup._provision_kb_and_ds`) and an adopted role
(`setup._extend_existing_kb_role`) are recorded `external`. Teardown skips those,
lists them as "kept", and deletes them only with `--include-adopted`.

`_delete_role` evaluates every reason to refuse *before* it removes anything —
managed policies attached, membership of an instance profile, or an inline policy
the tool did not author — so a refused role is left completely intact rather than
stripped of permissions and then abandoned. Recognition is by exact name against
`provisioning.TOOL_INLINE_POLICY_NAMES`, not a `kb-connector` prefix, so a
similarly-named policy belonging to another connector or to the operator is not
claimed. `--dry-run` has no reachable write ahead of it, and the y/N prompt gates
every deletion.

**Residual:** `is_tool_owned` returns `True` for a resource kind absent from
`created_resources`. That is deliberate — a state file where a create succeeded
and the state write did not would otherwise make teardown silently refuse to
delete anything the tool really did create. Adoption is always recorded
explicitly, so the direction that loses data is covered by an entry being
present. But it does mean the guard is only as good
as the state file: a truncated or hand-edited `created_resources` map re-enables
deletion of an adopted resource. `load_state` also treats an unparseable file as
empty, so a corrupted state file has the same effect.

### T-03 — Name collision silently hijacks or clobbers another workload's resource
**High · Tampering · TB-4 · AS-7**

A **TA-6** running the tool in an account that already contains a role named
`kb-connector-<name>-role` or a secret named `kb-connector/<name>-credentials`
can cause the trust policy of an unrelated role to be replaced, or an unrelated
secret's value to be overwritten, negatively impacting the integrity and
availability of the resource's real owner — a realistic case because derived
names are predictable and several people may use this tool in one account.

**Status: Mitigated.** Created resources are tagged
`ManagedBy=kb-connector` and `KbConnectorName=<connector>`.
`ensure_kb_role`, `put_secret`, and `ensure_cert_bucket` classify what they find
(`core/tagging.classify_ownership`) and refuse to modify anything not attributed
to this tool *and* this connector, with a message offering three ways forward.
`resource_prefix` lets teams share an account without renaming connectors. Tags
that cannot be read classify as `UNVERIFIABLE` and are also refused — absence of
evidence is not treated as evidence of ownership.

For SharePoint and OneDrive the same classification also runs as a read-only
preflight (`provisioning.preflight_ownership`) before Stage 1, so a run that will
be refused does not first register an Entra app, grant tenant-wide admin consent
and replace the app's certificate — none of which are rolled back. It reports
every conflicting resource at once rather than the first, and fails soft if it
cannot run, so it never blocks a setup that would have succeeded.
Operator-supplied `[tags]` are merged into the same tag set, but `ManagedBy` and
`KbConnectorName` are rejected rather than ignored, so a config file cannot forge
the ownership record this threat depends on.

Where tagging is unavailable — the caller lacks `iam:TagRole` or
`secretsmanager:TagResource` — the create succeeds untagged and state records the
resource as `tool-untagged`. A later run reclaims it on the strength of that
record (`provisioning._reclaim_untagged`) rather than refusing a resource the
tool created itself. This is scoped deliberately: only `UNMANAGED` is reclaimed,
never `OTHER_CONNECTOR` (a different connector's tag is real evidence) and never
`UNVERIFIABLE` (unreadable tags say nothing either way).

**Residual:** for those untagged resources the ownership anchor is the local
state file rather than the resource, which is the same trust T-02 already places
in it and narrower, since deletion is the more consequential operation. Losing
state makes an untagged resource indistinguishable from a stranger's.
`--no-tags` and `--adopt-existing-resources` both bypass the check by design;
adoption does not write the tag, so an adopted resource needs the flag on every
later run.

### T-04 — Failed Sites.Selected run abandons a tenant-wide full-control app
**High · Elevation of privilege · TB-3 · AS-5**

Any failure during per-site granting (an unresolvable site URL is sufficient)
leaves behind the temporary granter application — which holds SharePoint
`Sites.FullControl.All` and a client secret valid for two days — negatively
impacting the confidentiality and integrity of every SharePoint site in the
tenant for as long as it survives.

**Status: Mitigated.** Deletion moved into a `finally` block
(`setup._delete_granter_app`). If deletion itself fails, the tool prints the
object ID and an `az ad app delete` command rather than failing silently, and
does not mask the original exception. **Residual:** a hard kill (SIGKILL, power
loss) mid-grant still orphans the app. Worth an operator check after any
interrupted `--sites-selected` run.

### T-05 — Account-wide secret read yields tenant-wide source access
**High · Information disclosure · TB-4 · AS-1, AS-2**

A **TA-2** holding `secretsmanager:GetSecretValue` on the connector secret can
read the unencrypted private key and the PKCS#12 password together, then
authenticate to Microsoft Graph as the connector application, negatively
impacting the confidentiality of every SharePoint site or OneDrive drive the
connector app can read — an escalation from limited AWS access to tenant-wide
document access.

**Status: Partially mitigated.** The KB role's grant is a single
`secretsmanager:GetSecretValue` on one ARN. `--kms-key-arn` adds a
customer-managed key so the key policy is evaluated in addition to IAM, with
`kms:Decrypt` scoped by `kms:ViaService`. The AWS-managed key remains the default
because a CMK carries a cost and key-administration burden that many sample users
won't want. **Accepted:** the secret's field layout (`privateKey` and
`certificatePassword` in one secret) is fixed by the Bedrock connector contract,
so splitting key material across two secrets is not available. Documented
explicitly in the README.

### T-06 — Caller permission set is a privilege-escalation primitive
**High · Elevation of privilege · TB-4 · AS-3**

An operator or automation granted the permissions this tool needs holds
`iam:CreateRole` together with `iam:PutRolePolicy`, which is sufficient to grant
itself any permission in the account, negatively impacting the integrity of the
entire AWS account if those permissions are attached to a long-lived principal or
a role other workloads can assume.

**Status: Partially mitigated (documented).** The README now enumerates every
required action per subcommand and ships a scoped caller policy that restricts
IAM actions to `role/kb-connector-*` and constrains `iam:PassRole` with
`iam:PassedToService = bedrock.amazonaws.com`, which removes the general
escalation path. It also states plainly that the tool should run as a human
operator with an SSO session, not as a long-lived key or a shared service role.
**Accepted:** the tool cannot enforce how its caller is provisioned.

### T-07 — Connector app holds standing tenant-wide read after setup
**Medium · Information disclosure · TB-3 · AS-5, AS-8**

A **TA-5** who obtains the connector's credentials can read broadly across the
tenant, because ACL-enabled SharePoint requires SharePoint
`Sites.FullControl.All` and OneDrive requires `Files.Read.All` across all users,
negatively impacting confidentiality of documents far beyond the sites the
operator intended to index. Per-user ACL filtering applies at *retrieval* time
and does not narrow the app token's reach at *crawl* time.

**Status: Accepted (inherent, documented).** These are the permissions the
Bedrock managed connectors require; the tool cannot reduce them and still
deliver ACL-aware retrieval. `Sites.Selected` is supported for SharePoint to
scope to named sites (the least-privilege path), and `permissions.build_plan`
requests the narrowest set for each mode. OneDrive has no equivalent scope. The
blast radius is documented per connector in the README and
KNOWN-LIMITATIONS.md.

### T-08 — Operator's Graph token is broader than the tool's task
**Medium · Elevation of privilege · TB-3 · AS-4**

The tool borrows a Graph token from `az account get-access-token` or a
device-code flow using the Azure CLI's well-known first-party client ID, so every
directory write it performs rides on the operator's full privileges rather than a
consented, scoped subset, meaning a defect or a malicious config value acts with
Global Administrator authority if that is what the operator holds.

**Status: Accepted (documented).** Registering applications and granting admin
consent genuinely require these privileges; there is no narrower token that can
do the job. Mitigations are structural: the tool makes a bounded, auditable set
of Graph calls (`providers/microsoft/apps.py`), all directory writes appear in
the Entra audit log, and the split-admin workflow lets the identity admin run
Stage 1 without ever holding AWS credentials. Required directory roles are
documented.

### T-09 — MCP surface exposes document content and a write path to an agent
**Medium · Information disclosure/Tampering · TB-2 · AS-8, AS-9**

A **TA-4** can call `kb_connector_validate` to issue `Retrieve` queries whose
results — actual indexed document excerpts — enter the model's context and any
transcript store behind it, can call `kb_connector_monitor(start=true)` to
trigger a real crawl of the source system, and can steer `profile`,
`config_path`, and `state_path` to select which AWS credential and which local
files are used, negatively impacting confidentiality of AS-8 and giving an agent
a resource-consuming write action.

**Status: Partially mitigated.** `setup` and `teardown` are deliberately not
exposed. `monitor` is poll-only unless `start=true`, and the server's
`instructions` string names that parameter as the one write on the surface — it
does not describe the surface as read-only — so the model has the information it
needs to treat it as privileged and ask first. `kb_connector_diagnose` hardcodes
`redact_logs=True`, so both the document paths and the service-supplied reason
strings reaching an agent are redacted (T-15) and the CLI's `--no-redact` has no
MCP equivalent. **Accepted:**
retrieval results are the point of `validate`, so content necessarily reaches the
caller; the stdio transport has no authn of its own and inherits the spawning
process's credentials. Operators should treat the MCP server as holding whatever
authority the shell that launched it holds. Note the prompt-injection path:
indexed documents are attacker-influenced content that flows into an agent that
can call these tools.

### T-10 — Local artifacts expose environment metadata to other host users
**Medium · Information disclosure · TB-1 · AS-9, AS-10**

A **TA-3** on a shared workstation or build agent can read the files the tool
writes and obtain the Entra tenant ID, application IDs, AWS account IDs, role and
secret ARNs, and — from probe runs — full data-source configuration and retrieved
document excerpts, negatively impacting confidentiality of AS-9 and providing
precise targeting information for the account and tenant.

**Status: Mitigated.** Every file the tool writes goes through `core/fileio` and
lands at mode `0600` — the state file, handoff documents, probe artifacts, and
the generated `kb-connector.toml`, which carries the tenant ID, account detail,
site URLs and operator email addresses and so is exactly the material this threat
is about. Probe directories are `0700`. Writes go through `atomic_write_bytes`,
which creates its temp file with `mkstemp` inside the destination directory,
`fchmod`s the descriptor rather than the path, `fsync`s, and then renames — so
there is no window at looser permissions, no path to race, and no partial file
that `load_state` would silently treat as empty. `open_owner_only`, used by
callers that must stream, sets `O_NOFOLLOW` so an existing symlink at the target
path is refused rather than written through.

`handoff` prints a reminder that the file identifies the environment and should be
moved like a credential. `.gitignore` covers config, state, handoff, `.p12`,
`.pem`, and `.internal/`. No secret value reaches the state file, enforced
structurally by `asdict()` over declared fields.

### T-11 — Credential material leaks through a traceback
**Medium · Information disclosure · TB-1 · AS-2**

An unhandled exception raised while a `GeneratedCertificate` is in scope can
print the dataclass's default `repr`, disclosing the unencrypted PKCS#8 private
key and the PKCS#12 password into the terminal, CI logs, and crash reports,
negatively impacting confidentiality of AS-2.

**Status: Mitigated.** `private_key_b64_pkcs8`, `pkcs12_bytes`, and
`pkcs12_password` are declared `field(repr=False)`; verified that neither the key
nor the password appears in `repr()`. `DocumentEvent.details` (raw log events) is
likewise `repr=False`. **Residual:** provider error bodies are still interpolated
into messages via `GraphError`; those carry Entra API responses, which are not
credential-bearing but are unbounded.

### T-12 — Private key uploaded to an inadequately protected bucket
**Medium · Information disclosure · TB-4 · AS-2**

If public-access-block or default encryption cannot be applied to the certificate
bucket, the tool would upload a PKCS#12 file containing the connector's private
key into a bucket whose protections are unknown, negatively impacting
confidentiality of AS-2.

**Status: Mitigated.** `_harden_cert_bucket` raises rather than warning, so
public-access-block and default encryption are preconditions for the upload
rather than best-effort; `--allow-unhardened-cert-bucket` is the deliberate
override for environments enforcing the same controls elsewhere. Hardening is
confirmed before the key is uploaded, not alongside it. Separately,
`_bucket_status` distinguishes `403` from `404`, so a bucket owned by another
account is reported as unverifiable rather than misdiagnosed as absent — which
would otherwise send the caller into `CreateBucket` and surface as a confusing
`BucketAlreadyExists`. Bucket reuse is tag-verified (T-03).
**Accepted:** no versioning, access logging, or TLS-only bucket policy is set.

### T-13 — Crawl target configuration reaches non-public addresses
**Low · Information disclosure · TB-5 · AS-8**

A **TA-1** setting `seed_urls` or `sitemap_urls` can name link-local (including
the instance metadata endpoint), loopback, or private addresses, and whatever the
Bedrock managed crawler retrieves becomes chunked, embedded, and queryable via
`Retrieve`, negatively impacting confidentiality of whatever the crawler can
reach. Severity is low because the crawl executes in AWS's service account and
not in the caller's VPC, so the reachable surface is the public internet.

**Status: Partially mitigated.** `connectors/web.validate_crawl_urls` rejects
non-`http(s)` schemes, missing hosts, `localhost`, and any host that parses as a
link-local, loopback, private, reserved, or multicast address — consistent with
the client-side `sync_scope` validation, and failing at config time rather than as
an opaque ingestion failure.

**Residual, and the reason this is not a full mitigation:** the check is a
one-shot string test on literal IP forms, so equivalent spellings of the same
target pass. `http://2130706433/`, `http://0x7f000001/`, `http://0177.0.0.1/`,
`http://127.1/` and a trailing-dot form all fail `ipaddress.ip_address` and are
treated as hostnames. DNS is deliberately not resolved, so any name that resolves
to a private address (`localtest.me`, a `*.nip.io` label, internal corporate DNS)
also passes. Redirects are not followed here, and with `crawl_depth` or an
`ALL_DOMAINS` sync scope the crawler follows links away from the seeds, so only
the seeds are ever checked. `probe --connector-params` bypasses the check entirely
by design (T-14), as do `inclusion_filters` / `exclusion_filters`.

This is accepted rather than closed because the crawl runs in AWS's service
account and reaches the public internet, not the caller's VPC or workstation:
the check is there to catch an operator mistake early and to make the intent
explicit, not to serve as an SSRF boundary. Treating it as one would be the
mistake.

### T-14 — Raw payload override bypasses every client-side validator
**Low · Tampering · TB-1→TB-4 · AS-6**

A **TA-1** can use `connector_params_overrides` (deep-merged into
`connectorParameters`) or `probe --connector-params` to submit arbitrary fields
to `CreateDataSource`, bypassing all client-side validation and potentially
pointing `secretArn` or `certificateS3Path` at resources the connector was not
meant to use, negatively impacting the integrity of the data source
configuration.

**Status: Accepted (intentional).** This is a documented escape hatch and the
reason it exists is stated in KNOWN-LIMITATIONS.md: the connector parameter
surface is larger than the curated builders cover, and pretending to validate
untested fields would be worse than passing them through. The API authorizes
every referenced resource against the caller's own credentials, so this does not
cross an authorization boundary. `probe` is documented as a maintainer tool.

### T-15 — Ingestion log analysis discloses customer document paths
**Low · Information disclosure · TB-1 · AS-10**

`diagnose --logs` surfaces sample document locations from CloudWatch — SharePoint
and Drive URLs naming sites, folders, and filenames, sometimes with query-string
tokens — and this output is routinely pasted into support tickets and shared with
people who should not see the customer's file inventory, negatively impacting
confidentiality of AS-10.

**Status: Partially mitigated.** Two fields carry this content, and both are
redacted by default; `--no-redact` is local-only and the MCP tool cannot request
unredacted output (T-09).

`log_analysis.redact_document_location` replaces the filename with
`<redacted>.<ext>`, drops query strings, and elides deep paths while keeping the
host and one leading segment — enough to identify *which* pattern is failing
without naming files. Two details are load-bearing: the prefix is rebuilt from
`hostname`, never `netloc`, so userinfo in a `https://user:pass@host/...`
location is not copied into output headed for a support ticket; and only the
first path segment is kept, because the second holds the SharePoint site name in
one layout and the owning user's email-derived identity
(`/personal/john_doe_contoso_com/`) in another.

`log_analysis.redact_reason` covers the service-supplied `reason` string, which
frequently embeds the same document URL or a bare filename
("AccessDenied reading https://.../salaries-2026.xlsx"). This matters because
`reason` also flows into `actionable_issues`, so redacting only the sample
locations would leave the filename in the output by another route. It rewrites
embedded `http(s)` URLs through `redact_document_location` and masks tokens
ending in a known document extension; the extension set is explicit so version
strings, hostnames and ARNs are left readable.

**Residual:** an identifier with no extension and no URL form — a bare document
ID, or a title carried in `reason` as plain prose — is not recognizable in free
text and is not redacted. Sanitizing service-authored prose is best-effort by
nature, so `--no-redact` output and any log excerpt should still be reviewed
before it leaves the operator's hands.

### T-16 — Existing-KB role extension widens a policy the tool did not author
**Low · Tampering · TB-4 · AS-7**

When attaching to an existing knowledge base, appending resource ARNs to a
statement matched only by *action* could modify an unrelated statement in a
policy the tool did not write, negatively impacting the integrity of that
policy's intended scope.

**Status: Mitigated.** `_find_statement` matches on `Sid` only, with no
action-based fallback. When no recognizable statement exists, the tool
attaches a separate policy named `kb-connector-supplemental-access` rather than
editing someone else's statement, so the addition is auditable and individually
removable. Extension still only ever *adds* resource ARNs — never removes them,
never widens actions, and it skips `Deny` statements and statements already
containing `"*"`.

### T-17 — OData filter injection redirects app lookup
**Low · Tampering · TB-3 · AS-5**

An application display name containing a single quote can alter the
`$filter` expression used to locate an existing app registration, at minimum
breaking the query and at worst causing the tool to match a different
application — the object it then uploads a certificate to and grants tenant-wide
permissions on.

**Status: Mitigated.** `apps.escape_odata_literal` doubles single quotes per the
OData spec, and `find_application_by_name` re-verifies the exact `displayName`
client-side rather than trusting the server-side filter, so the reuse decision
does not depend on filter interpretation.

### T-18 — Irrecoverable secret deletion
**Low · Denial of service · TB-4 · AS-1**

`teardown` deletes secrets with `ForceDeleteWithoutRecovery=True`, so a
**TA-6** who tears down the wrong connector cannot recover the secret via the
normal 7-day window, negatively impacting availability of AS-1.

**Status: Accepted (documented).** The recovery window would block re-running
`setup` under the same connector name, which is the common path during setup and
testing. Mitigated procedurally: `--dry-run`, a y/N prompt, `--only` scoping, and
a refusal to tear down while an ingestion job is running. Called out in both the
README and KNOWN-LIMITATIONS.md so the tradeoff is visible before use.

Because there is no undo, the *target* is also checked: `_delete_secret` requires
a well-formed Secrets Manager ARN (`identifiers.validate_secret_arn`) before it
calls `DeleteSecret`, so a malformed or crafted state entry cannot redirect the
deletion at another service's resource (T-24). The refusal to tear down while a
job is running depends on a `ListIngestionJobs` call; if that call fails the
teardown proceeds, but prints a warning saying the check did not run, since
failing closed on a transient API error would be its own foot-gun.

### T-19 — Trust policy permits any knowledge base in the account
**Low · Elevation of privilege · TB-4 · AS-6**

The created role's trust policy conditions on `aws:SourceArn` with
`ArnLike ...knowledge-base/*`, so any knowledge base in the same account and
Region can assume it and thereby read the connector's secret, negatively
impacting confidentiality of AS-1 relative to a per-KB scoping.

**Status: Accepted (matches platform behavior).** This mirrors the role the
Bedrock console creates. The KB ID is not known before `CreateKnowledgeBase`
returns, so a per-KB ARN would require a second `UpdateAssumeRolePolicy` after
creation. `aws:SourceAccount` and `aws:SourceArn` are both set, which is the
confused-deputy protection that matters here — the exposure is confined to
principals who can already create a knowledge base in the account. Documented in
the README.

### T-20 — Credential material resident in process memory
**Low · Information disclosure · TB-1 · AS-1, AS-2**

Private keys, passwords, and client secrets are held on dynamic attributes of
`ConnectorState` (`cs._p12_bytes` and similar) for the duration of a `setup`
run, so a core dump or a memory-inspecting process on the same host could
recover them, negatively impacting confidentiality of AS-1 and AS-2.

**Status: Accepted.** This is a deliberate design choice with a security benefit:
keeping secrets off the declared dataclass fields is what structurally prevents
`save_state` from ever serializing them, at the cost of a same-process
constraint between Stage 1 and Stage 2 (the tool raises an actionable
`StateError` explaining this rather than failing obscurely). Python offers no
reliable zeroization for `str` and `bytes`. Falls under assumption **A1**.

### T-21 — Partial-failure retry orphans tracked resources
**Low · Denial of service · TB-4 · AS-6**

If `setup` fails mid-Stage-2 after writing credentials but before recording the
KB or data source, re-running overwrites the state's credential references with
new values, so the previous run's resources remain in AWS with nothing tracking
them and `teardown` can no longer find them, negatively impacting the
availability of cleanup and leaving cost and unused credentials behind.

**Status: Accepted (documented, tracked).** State is persisted in a `finally`
block so whatever was created before a failure is still recorded, and setup
prints the tracked resources plus the teardown command on failure. The
overwrite-on-retry case is documented in KNOWN-LIMITATIONS.md; the fix is for
setup to detect existing credential references and reuse them. Ownership tags now
make orphans identifiable after the fact (`ManagedBy=kb-connector`).

### T-22 — No credential rotation path
**Low · Various · TB-3 · AS-1, AS-2**

Certificates are issued for 365 days and Entra client secrets for 365 days with
no rotation command, so an operator's only route to fresh key material is a full
teardown and re-setup, which increases the window during which a compromised
credential stays valid.

**Status: Accepted (documented).** `diagnose` performs a cert-expiry check that
warns at 30 days and fails after expiry, so the condition is detectable before
retrieval breaks. Rotation is a known gap in KNOWN-LIMITATIONS.md.

### T-23 — Non-AWS partitions produce non-matching conditions
**Informational · TB-4**

Trust and resource policies hardcode the `arn:aws:` partition, so in GovCloud
(`aws-us-gov`) or China (`aws-cn`) the condition ARNs will not match. This fails
closed — access is denied rather than wrongly granted — so it is a functional
limitation rather than a security weakness.

**Status: Accepted.** Recorded here so that adding partition support later is
understood as a functional change rather than a security fix.

### T-24 — Tampered state or handoff file retargets a destructive AWS call
**Medium · Tampering/Denial of service · TB-1→TB-4 · AS-6, AS-7**

A **TA-1** who can write the state file, or hand the operator a handoff document,
can set `secret_arn`, `kb_role_arn`, `cert_s3_bucket` or `cert_s3_key` to name a
resource the connector never created, and `teardown` will then act on it with the
operator's credentials — deleting a secret with no recovery window, deleting an
IAM role, or deleting an S3 object — negatively impacting the availability of
resources belonging to another workload.

This is a distinct threat from T-02: the ownership map guards *whether* a tracked
resource may be deleted, but it does not check that the identifier next to it
names the resource the tool actually provisioned. A handoff document is the more
realistic vector of the two, since it is expected to arrive from another person in
another team, usually over email or chat.

**Status: Mitigated.** Every identifier taken from a local file and used as the
target of an AWS call is shape-checked first, in `core/identifiers.py`:

- `_delete_secret` requires a Secrets Manager ARN naming a secret, so an ARN for
  another service cannot reach `DeleteSecret`.
- `_delete_role` requires a well-formed IAM role ARN and validates the extracted
  name against IAM's charset and length limit. Trimming from a `:role/` marker
  would pass a bare string straight through, letting a state entry of
  `OrganizationAccountAccessRole` aim `DeleteRole` at that role.
- `_delete_cert` requires a syntactically valid bucket name and a relative key
  with no `..` segment.

Handoff documents go through `handoff.parse_handoff` before any value reaches
state. It pins `version` against a supported set — a field the builders write, so
not reading it would let a format change be misparsed — compares `direction` with
`==` rather than `in`, so a string merely *containing* a known direction cannot
select that branch, and validates every identifier field it imports. Unknown
top-level keys are preserved and ignored so a newer writer stays readable.

**Residual:** these are shape checks, not authorization. They establish that a
value could have come from a provisioning run, not that this operator owns the
resource; a well-formed ARN for a secret the operator can delete but did not
create still passes, and is caught only by the ownership map (T-02) and the y/N
prompt. Under **A1** an attacker with code execution needs none of this.

### T-25 — Declared dependency floors admit versions with known CVEs
**Low · Various · TB-1 · AS-2, AS-3**

A `>=` floor states what a resolver is *allowed* to install, so a fresh install
driven by a constraints file, a lockfile, or an older distro base image can land
exactly on the floor rather than on a current release. A floor set to the oldest
version whose API the tool happens to use can therefore admit a release with a
known vulnerability in a code path the tool exercises — for `cryptography`, the
`pkcs12.serialize_key_and_certificates` call that builds the PKCS#12 bundle.

**Status: Mitigated.** Floors are set to the first release clear of known
advisories rather than the oldest compatible one: `cryptography>=50.0.0`,
`requests>=2.33.0`, `pytest>=9.0.3`, and `mcp>=1.28.1` (five HIGH-severity
transport advisories). `pyproject.toml` records which advisory forces each
number, and CI runs `pip-audit` against both the resolved tree and the declared
floors, so a new advisory against a floor becomes visible rather than dormant.

`boto3>=1.43.32` is the exception: that floor is a capability requirement, not
an advisory one. It is the first release whose service model contains the
managed-connector data-source envelope, knowledge-base encryption, and the
top-level `userContext` on Retrieve, so an older botocore fails parameter
validation rather than admitting a vulnerability.

Of the `cryptography` advisories below the current floor, only the statically
linked OpenSSL ones sit on a path this tool uses. The floor is raised anyway:
a sample should not tell its users that a vulnerable release is acceptable.

**Accepted:** supply-chain integrity of these packages themselves remains out of
scope (§1), and the audit job is advisory so a new advisory against a pinned floor
does not block an unrelated change.

### T-26 — Unvalidated connector name widens an IAM policy
**Low · Elevation of privilege · TB-1→TB-4 · AS-1, AS-2**

The connector name, `resource_prefix`, and `cert_s3_key_prefix` are interpolated
into derived resource names, and those names are interpolated into the `Resource`
ARNs of the inline policy attached to the knowledge base role. `*` and `?` are
IAM policy wildcards, so a **TA-1** naming a connector `x*` produces an object ARN
of `arn:aws:s3:::<bucket>/kb-connector/x*.p12` and grants the role read access to
every object matching that pattern rather than the single certificate it needs,
negatively impacting confidentiality of any other connector's key material in the
shared certificate bucket.

**Status: Mitigated.** `identifiers.validate_name_component` and
`validate_s3_key_prefix` constrain these values to a charset that is
simultaneously safe for an IAM role name, a Secrets Manager name and an S3 key,
and reject `*` and `?` explicitly. Validation runs in `config.resolve_connector`,
the single point every command resolves configuration through, so the run fails
before the first AWS call.

Characters IAM rejects outright are refused for a second, non-security reason:
Secrets Manager and S3 accept names that IAM will not, so without a local check
the secret and the certificate get created and only the role fails, leaving a
half-provisioned run to clean up by hand.

---

## 6. Prioritized summary

| ID | Threat | Priority | Status |
|---|---|---|---|
| T-01 | SDK endpoint config exfiltrates signed credentials | High | Accepted |
| T-02 | Teardown destroys adopted resources | High | Mitigated |
| T-03 | Name collision clobbers another workload | High | Mitigated |
| T-04 | Orphaned Sites.Selected granter app | High | Mitigated |
| T-05 | Account-wide secret read → tenant access | High | Partial + accepted |
| T-06 | Caller permissions enable escalation | High | Partial (documented) |
| T-07 | Standing tenant-wide connector app | Medium | Accepted (inherent) |
| T-08 | Operator Graph token over-privileged | Medium | Accepted (inherent) |
| T-09 | MCP exposes content + one write path | Medium | Partial |
| T-10 | Local artifacts readable by other users | Medium | Mitigated |
| T-11 | Key material in traceback | Medium | Mitigated |
| T-12 | Key uploaded to unhardened bucket | Medium | Mitigated |
| T-24 | Tampered state/handoff retargets a delete | Medium | Mitigated |
| T-13 | Crawl target reaches non-public addresses | Low | Partial |
| T-14 | Raw payload override bypasses validation | Low | Accepted (intentional) |
| T-15 | Log analysis discloses document paths | Low | Partial |
| T-16 | Role extension widens foreign policy | Low | Mitigated |
| T-17 | OData filter injection | Low | Mitigated |
| T-18 | Irrecoverable secret deletion | Low | Accepted |
| T-19 | Trust policy allows any KB in account | Low | Accepted |
| T-20 | Secrets in process memory | Low | Accepted |
| T-21 | Partial-failure retry orphans resources | Low | Accepted (tracked) |
| T-22 | No rotation path | Low | Accepted (tracked) |
| T-25 | Dependency floors admit known CVEs | Low | Mitigated |
| T-26 | Unvalidated name widens an IAM policy | Low | Mitigated |
| T-23 | Non-AWS partitions | Info | Accepted |

## 7. Operator checklist

Before running this tool against a real environment:

- [ ] Confirm the AWS account and Region are the intended ones
      (`setup` prints the resolved profile and caller ARN before its first write).
- [ ] Use a scoped caller policy
      ([README](README.md#what-the-caller-needs)), not `AdministratorAccess`, and
      an SSO session rather than a long-lived key.
- [ ] Decide whether the connector needs ACL. It significantly widens the Entra
      permissions required (T-07).
- [ ] For SharePoint, prefer `sites_selected = true` to scope to named sites.
- [ ] Decide on `--kms-key-arn`. Without it, anyone in the account with
      `GetSecretValue` can read the connector's source credentials (T-05).
- [ ] If several people use this tool in the account, set `resource_prefix`.
- [ ] Do not commit `kb-connector.toml` or `kb-connector.state.json`; both are
      gitignored by default.
- [ ] After any interrupted `--sites-selected` run, confirm no
      `*-granter` application remains in the tenant (T-04).
- [ ] Treat `handoff` files as credentials in transit; delete them after use.
- [ ] Review `teardown --dry-run` output before deleting, and check the "kept"
      list to confirm adoption was recorded as you expect.

## 8. Maintaining this document

Security-relevant behaviors that this model depends on:

- `core/tagging.py` — the ownership model behind T-02 and T-03, including
  `validate_extra_tags`, which keeps operator tags from overwriting it.
- `provisioning.preflight_ownership` — the check that moves a T-03 refusal ahead
  of the irreversible Entra work in Stage 1.
- `provisioning.TOOL_INLINE_POLICY_NAMES` — the exact-name set that bounds what
  `teardown._delete_role` will remove (T-02). A new `put_role_policy` call site
  must add its name here.
- `teardown._delete_role` — the refuse-before-remove ordering behind T-02.
- `core/fileio.py` — the `0600` and atomicity guarantees behind T-10, including
  `O_NOFOLLOW` in `open_owner_only`.
- `core/identifiers.py` — the shape checks behind T-24 and T-26. Anything that
  becomes the target of a destructive call, or is interpolated into a policy ARN,
  belongs here.
- `handoff.parse_handoff` — the version, direction and field validation behind
  T-24.
- `config.resolve_connector` → `_validate_derived_name_inputs` — the single
  choke point behind T-26.
- `diagnostics.describe_endpoints` — the pre-write endpoint report behind T-01.
  It compares each resolved endpoint against botocore's own region-derived
  default, so it catches a service-specific override as well as a global one.
- `core/state.ConnectorState.is_tool_owned` — the teardown gate behind T-02, and
  the reason its default-`True` behavior is a documented residual there.
- `setup._delete_granter_app` — the `finally` cleanup behind T-04.
- `connectors/web.validate_crawl_urls` — the target validation behind T-13.
- `log_analysis.redact_document_location` and `redact_reason` — the redaction
  behind T-15. Both are needed: `reason` flows into `actionable_issues`.
- `field(repr=False)` in `providers/microsoft/certs.py` — behind T-11.
- `mcp_server.server` `instructions` — the disclosure behind T-09. It must keep
  naming `monitor(start=true)` as a write.
- Dependency floors in `pyproject.toml` — behind T-25. Raise to the first release
  clear of advisories, not the oldest compatible one.

Two CI jobs keep this document from drifting away from the code: `security`
(bandit plus gitleaks over the working tree and full history) is blocking, and
`audit` (pip-audit over the resolved tree and the declared floors) is advisory. A
security config that nothing executes is not a control — bandit silently ignores
its skips unless the config is passed explicitly, and a malformed gitleaks
allowlist makes gitleaks exit without scanning anything.

Changing any of the above, or adding a new MCP tool, a new resource type, a new
credential path, a new destructive call, or a new file the tool writes, should
come with a corresponding update here.
